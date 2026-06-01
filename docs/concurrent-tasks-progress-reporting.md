# 技术方案：并发多任务 + 进度汇报（"既能干又像人的同事"）

> 目标：让 MicroClaw 像一个**能同时推进多个项目、并会主动汇报进展**的靠谱同事——
> 用户一句话派下多件事，bot 并行开多条线，运行中途定期同步进展，完成后给结论。
> 本文是落地方案，对照现有代码，分阶段可直接开发。

---

## 0. 这件事和"更像人"的关系

上一份 `docs/humanlike-chat-analysis.md` 指出 bot 最大的短板是**反应式、被动**。
本方案正好补上"能干 + 主动"的一面：

- **能干**：真正并发执行多个长任务（不是假装多线程，是后台真的同时跑）。
- **像人**：像同事一样**主动 standup**——"竞品分析做完 3/5 家了，有个发现先同步你一下"，
  而不是闷头干完一次性甩结果。
- 这与拟人化方案里的 **A. 主动性（Inner Thoughts）** 是同一套机制：进度推送也要被
  "表达欲/价值"门控，避免刷屏（研究反复强调：每次主动消息都要 deliver real value，
  not spam）。

---

## 1. 现状盘点：基础设施已完成约 70%

**好消息：并发执行 + 完成汇报已经是生产级的，不需要从零造。**

| 能力 | 现有实现 | 位置 |
|---|---|---|
| 后台并发子代理 | `sessions_spawn` 工具 → `tokio::spawn` 后台跑，立即返回 `run_id` | `src/tools/subagents.rs:615`（定义）, `:873`（spawn） |
| 并发配额/限流 | 全局信号量 + 每 chat 活跃数 + 深度 + 每父级子数 | `src/config.rs:760+` (`SubagentConfig`) |
| 运行状态存储 | `subagent_runs` 表：accepted→queued→running→completed/failed/cancelled/timed_out/budget_exceeded，含 tokens、result_text、artifact_json | `crates/microclaw-storage/src/db.rs:782` |
| **事件日志（进度底座）** | `subagent_events(run_id, event_type, detail, created_at)`，已记录生命周期事件 | `db.rs:857`；写入 `append_subagent_event` `db.rs:4949`；当前从 `subagents.rs:238 log_subagent_event` 调用 |
| 完成汇报（可靠投递） | `subagent_announces` 表 + 后台 relay 循环（轮询、指数退避重试） | `db.rs:835`；relay `src/runtime.rs:528`；`flush_pending_announces_once` `subagents.rs:551` |
| 取消 | 内存 AtomicBool + DB `cancel_requested`，循环内轮询 | `subagents.rs:187-265` |
| 焦点/跟进 | `subagents_focus/unfocus/focused/send` 绑定一个 run 做后续 | `subagents.rs:1347+` |
| 编排（fan-out） | `subagents_orchestrate`（深度2，多 worker 模板） | `subagents.rs` |
| 定时/周期任务 | `scheduled_tasks`（cron + once）、原子 `claim_due_tasks`、DLQ、时区 | `src/scheduler.rs:19`；表 `db.rs:1103` |
| 统一消息投递 | 跨频道单一入口 | `deliver_and_store_bot_message` `crates/microclaw-channels/src/channel.rs:220` |
| 每 chat 串行回合 | `ChatTurnQueue`（防同 chat 并发，跨 chat 独立） | `src/chat_turn_queue.rs` |

**现有工具清单**（已核对真名）：
`sessions_spawn`, `subagents_list`, `subagents_info`, `subagents_kill`, `subagents_focus`,
`subagents_unfocus`, `subagents_focused`, `subagents_send`, `subagents_orchestrate`,
`subagents_log`, `subagents_retry_announces`；
`schedule_task`, `list_scheduled_tasks`, `pause/resume/cancel_scheduled_task`,
`list/replay_scheduled_task_dlq`, `get_task_history`。

---

## 2. 差距分析：缺的是哪 30%

| 用户期望 | 现状 | 差距 |
|---|---|---|
| 同时开多个任务 | ✅ `sessions_spawn` 已支持并发 | 无（已具备） |
| 完成后汇报 | ✅ announce relay 已支持 | 无（已具备） |
| **运行中途定期汇报进展** | ❌ 只在**完成时**announce 一次；中途事件只写日志、不推送 | **核心缺口①**：缺中途进度推送 + 节流 |
| **任务有人话名字** | ❌ 只有 `subrun-<uuid>`，用户无法说"研究那个任务到哪了" | **核心缺口②**：缺 human label |
| **"你现在都在忙啥"一览** | ❌ 有 `subagents_list` 但偏原始、无 label、无进度摘要 | **核心缺口③**：缺站会式 digest |
| 子代理能"主动说一句进展" | ❌ 子代理工具集里没有"汇报进度"工具 | 缺 `report_progress` 工具 |
| 主动 standup（不被问也同步） | ❌ 无 | 与拟人化方案 A 共用 motivation 门控 |

> 一句话：**底盘都在，缺的是"中途进度"这条数据流，以及把任务包装成人话（命名 + 站会）。**

---

## 3. 目标体验（用户视角场景）

**场景 A — 一句话派多活：**
```
用户：帮我同时做三件事：①调研三个竞品的定价 ②把上周的日志做个错误归类 ③起草周报
Bot ：好，我同时开三条线 👇
      ① 竞品定价调研  ② 日志错误归类  ③ 周报起草
      有进展我随时同步，你也可以问我"现在都在忙啥"。
```

**场景 B — 中途主动同步（节流后）：**
```
Bot ：📊 [竞品定价调研] 进度 3/5 —— A 家 $29/mo、B 家 $49/mo、C 家有隐藏年付折扣，
      剩 D、E 两家还在查。
```

**场景 C — 完成汇报：**
```
Bot ：✅ [日志错误归类] 完成。1,204 条错误归为 6 类，Top1 是超时(38%)，详情见下…
```

**场景 D — 随时查岗：**
```
用户：现在都在忙啥？
Bot ：手头三件事：
      ✅ 日志错误归类（完成）
      🔄 竞品定价调研（3/5，约还要 2 分钟）
      🔄 周报起草（草稿 60%）
```

---

## 4. 架构设计

### 4.1 数据模型变更（全部走 `table_has_column` 安全迁移，沿用现有 `db.rs:888` 的模式）

**`subagent_runs` 增列：**
```sql
ALTER TABLE subagent_runs ADD COLUMN label TEXT;                  -- 人话名字，如 "竞品定价调研"
ALTER TABLE subagent_runs ADD COLUMN progress_text TEXT;          -- 最新一条进度摘要
ALTER TABLE subagent_runs ADD COLUMN progress_pct INTEGER;        -- 可选 0..100
ALTER TABLE subagent_runs ADD COLUMN last_progress_at TEXT;       -- 最近一次进度时间
ALTER TABLE subagent_runs ADD COLUMN last_announced_progress_at TEXT;  -- 最近一次"已推送"时间（节流用）
CREATE INDEX IF NOT EXISTS idx_subagent_runs_chat_label
    ON subagent_runs(chat_id, label) WHERE label IS NOT NULL;
```

**复用 `subagent_events` 作为进度事件流**：新增 `event_type = 'progress'`，`detail` 存进度文本。
无需新表——这张表天生就是 per-run append-only 时间线。

**复用 `subagent_announces` 投递通道**：增列 `kind TEXT DEFAULT 'completion'`
（取值 `completion` | `progress` | `standup`），让一条 relay 同时承载完成/进度/站会三类推送，
共享重试/退避/幂等（`run_id UNIQUE` 需放宽为允许 progress 多条，见 4.3）。

### 4.2 子代理内的进度上报（核心缺口①）

两条互补的来源：

**(a) 显式：新增 `report_progress` 工具（仅子代理可用）**
- 像 `send_message` 一样按上下文授权：只有在子代理运行内（有 `run_id` 的 auth context）才暴露。
- 行为：
  1. `append_subagent_event(run_id, "progress", text)`
  2. 更新 `subagent_runs.progress_text / progress_pct / last_progress_at`
  3. enqueue 一条 `kind='progress'` 的 announce（投递交给 relay，**带节流**）
- 子代理在 system prompt 里被告知："完成一个里程碑就调用 `report_progress` 简短同步一句。"
- 落点：新增 `src/tools/report_progress.rs`，在 `src/tools/mod.rs` 注册；
  仅在子代理工具集组装处加入（参考现有"9 个受限工具"的装配点）。

**(b) 隐式：里程碑心跳（零额外 LLM 成本）**
- 在子代理 agent 循环里，每完成 N 次工具迭代或耗时超过 T，自动写一条结构化 progress 事件
  （如 "iter 6: ran web_search ×3, read 4 files"）。纯结构化、不额外调用 LLM。
- 落点：子代理循环处（`subagents.rs` 的 native 运行循环，`MAX_SUB_AGENT_ITERATIONS` 附近）。
- 心跳事件默认**只入 `subagent_events`、不推送**（避免刷屏）；只有 `report_progress` 或
  达到"显著进展"阈值才推送。

### 4.3 进度投递 relay（节流 + 合并）

复用现有 relay 基础设施，扩展为多 kind：

- **节流**：同一 run 两次 progress 推送间隔 ≥ `progress_min_interval_secs`（默认 60s）；
  且仅当 `progress_text` 相对上次有实质变化（简单 diff / 长度阈值）。
- **合并**：relay 一个 tick 内，同一 run 多条 progress 只发最新一条（按 `last_announced_progress_at` 去重）。
- **幂等**：completion 仍用 `run_id` 唯一；progress 改为 `(run_id, created_at)` 唯一或自增 id。
- 投递仍走 `deliver_and_store_bot_message`，语气模板见 4.6。
- 落点：扩展 `flush_pending_announces_once`（`subagents.rs:551`）按 kind 分支；
  relay 循环 `runtime.rs:528` 不变。

> 注意与 `ChatTurnQueue` 的关系：进度推送是"bot 主动发消息"，不抢占用户回合的锁，
> 直接经 `deliver_and_store_bot_message` 投递即可（completion announce 现在就是这么做的）。

### 4.4 命名任务（核心缺口②）

- `sessions_spawn` input schema 增加可选 `label`（人话名字）。
- 落地到 `subagent_runs.label`；冲突策略：同 chat 同 label 若已有活跃任务，
  返回提示或自动追加序号。
- `subagents_list / info / kill / focus / send` 全部支持用 `label` 代替 `run_id` 定位
  （内部 `resolve_run(chat_id, label_or_run_id)`）。
- 主代理在派活时自动给每个子任务起一个简短 label（prompt 引导）。

### 4.5 站会式汇总（核心缺口③）

- 新增 `tasks_status` 工具（或增强 `subagents_list`）：返回该 chat 全部**近期**任务的
  `label / status / progress_text / progress_pct / 估时`，并渲染成场景 D 那样的人话清单。
- 主代理在用户问"在忙啥/进度如何"时调用它。
- 落点：`src/tools/subagents.rs` 增强 list，或新文件 `src/tools/tasks_status.rs`。

### 4.6 拟人化整合（语气 + 主动 standup）

- **语气**：进度/完成/站会文案不用机械模板，走 SOUL 风格——简短、同事口吻、emoji 适度
  （`📊 进度` / `✅ 完成` / `⚠️ 卡住`）。文案由"包装层"决定，可选让主代理用一次轻量
  LLM 把结构化进度转成人话（受 token 预算控制，默认结构化模板，省钱）。
- **主动 standup（可选，与拟人化方案 A 共用）**：一个低频 scheduler 循环，当某 chat 有
  ≥1 活跃任务且距上次同步 ≥ `standup_interval` 时，用 motivation 门控决定是否主动发一条
  合并 standup（"还在跑：…，预计…"）。被门控避免刷屏。
  - 落点：`src/scheduler.rs` 新增 `run_task_standup()`，与现有 reflector/scheduler 循环并列。

---

## 5. 配置项（新增，放进 `SubagentConfig` 与新 `progress` 子配置）

```yaml
subagents:
  # —— 已有 ——
  max_concurrent: 4
  max_active_per_chat: 3
  run_timeout_secs: 600
  announce_to_chat: true
  announce_relay_interval_secs: 5
  # —— 新增：进度汇报 ——
  progress:
    enabled: true
    min_interval_secs: 60          # 同一任务两次进度推送的最小间隔（节流）
    heartbeat_every_iters: 5       # 每 N 次子代理迭代写一条结构化心跳（不一定推送）
    announce_heartbeat: false      # 心跳是否也推送（默认否，避免刷屏）
    humanize_with_llm: false       # 是否用一次轻量 LLM 把进度转人话（默认否，省 token）
  standup:
    enabled: false                 # 主动站会（不被问也同步）
    interval_secs: 1800            # 最小站会间隔
    motivation_threshold: 0.6      # 与拟人化方案 A 共用的门控阈值
```

---

## 6. 分阶段实施计划

> 原则：每一阶段都**独立可上线、可回滚**，先拿 UX 收益大、风险小的。

### Phase 1 — 命名任务 + 站会一览（低风险，高 UX）✅ 已完成
- DB：`subagent_runs` 加 `label`（schema v26 迁移，`db.rs`）。
- 工具：`sessions_spawn` 加 `label` 参数；`subagents_list` / `subagents_info` 输出带 `label` +
  最新进度，主代理据此回答"现在都在忙啥"。
- Prompt：主代理提示词引导"多任务时给每个起 label，用 `subagents_list` 查岗"。
- 测试：`test_subagent_run_label_and_progress` 断言 label 在 create/get/list 间往返。
- **交付物**：用户能"同时开多个有名字的任务"并"一句话查全部状态"。

### Phase 2 — 运行中途进度推送（核心）✅ 已完成
- DB：`subagent_runs` 加 `progress_text` / `last_progress_at`（schema v26）；复用 `subagent_events`
  记录 `event_type='progress'` 时间线；新增 `record_subagent_progress()`。
- 工具：新增 `report_progress`（仅子代理可用，`src/tools/report_progress.rs`）——记录进度 +
  `deliver_and_store_bot_message` 推送 `📊 [label]: ...`。
- 节流：`subagents.progress_min_interval_secs`（默认 45s）；距上次推送不足间隔则只记录不推送。
- Prompt：子代理 system prompt 加"里程碑时调用 `report_progress` 简短同步"。
- 测试：`test_subagent_run_label_and_progress` 覆盖进度记录 + 时间线事件 + 节流所需的"上次时间"返回。
- **交付物**：场景 B 落地——任务运行中会主动同步进展（节流防刷屏）。

### Phase 3 — 主动 standup + fan-in 汇总
- Scheduler：`run_task_standup()`，motivation 门控（复用拟人化方案 A）。
- 编排：一组同 parent 的子任务全部完成时，自动产出一条聚合结论（fan-in）。
- 测试：多任务并行，门控下每 chat 不超过 1 条/interval 的 standup；全部完成给汇总。
- **交付物**：场景 D 主动版 + 多任务收束汇报。

### Phase 4 — 打磨
- `progress_pct`/ETA 估算、卡住(`stalled`)检测与提醒、`humanize_with_llm` 可选人话化、
  任务依赖触发链（A 完成自动起 B，复用 scheduler 的 `trigger_run_id` 思路）。

---

## 7. 风险与取舍

| 风险 | 缓解 |
|---|---|
| **刷屏**（进度太频繁像 spam） | `min_interval_secs` 节流 + 同 tick 合并 + 心跳默认不推送 + standup motivation 门控 |
| **token 成本**（每条进度都 LLM？） | 默认结构化模板，不额外调 LLM；`humanize_with_llm` 显式开启才花钱 |
| **迁移安全** | 全部用现有 `table_has_column` 增量迁移模式（`db.rs:888`），旧库平滑升级 |
| **并发与 per-chat 串行** | 进度/完成推送走 `deliver_and_store_bot_message`，不抢用户回合锁（与现有 completion announce 一致） |
| **幂等/重复投递** | completion 维持 `run_id UNIQUE`；progress 用自增 id + `last_announced_progress_at` 去重 |
| **进度噪音 vs 信息量** | 心跳只入日志、`report_progress` 才推送；推送前做实质变化 diff |

---

## 8. 验收标准

1. 用户一句话派 3 件事 → 后台真并发 3 个 run，bot 回执列出 3 个带名字的任务。
2. 运行中至少收到 1 条节流后的进度同步（场景 B），且不刷屏。
3. 每个任务完成各自汇报（场景 C），失败进 DLQ/有错误说明。
4. "现在都在忙啥" → 一条人话站会清单（场景 D）。
5. 旧数据库升级后无报错（迁移幂等）。
6. 关闭 `progress.enabled` 时行为回退到现状（只完成汇报），零回归。

---

## 9. 涉及文件清单（开发索引）

| 模块 | 文件 | 改动 |
|---|---|---|
| DB schema/迁移/方法 | `crates/microclaw-storage/src/db.rs` | 增列、index、`record_progress`、`resolve_run_by_label`、`list_active_tasks` |
| 子代理工具 | `src/tools/subagents.rs` | `sessions_spawn` 加 label；list→digest；relay 支持 kind；心跳 |
| 新工具 | `src/tools/report_progress.rs`（新）, 可选 `src/tools/tasks_status.rs`（新） | 子代理进度上报 / 站会一览 |
| 工具注册 | `src/tools/mod.rs` | 注册新工具（注意子代理受限工具集装配点） |
| Relay/后台 | `src/runtime.rs:528`, `subagents.rs:551` | relay 多 kind |
| 站会循环 | `src/scheduler.rs` | `run_task_standup()`（Phase 3） |
| 配置 | `src/config.rs`, `microclaw.config.example.yaml` | `subagents.progress` / `subagents.standup` |
| Prompt | `src/agent_engine.rs` | 派活起 label、子代理里程碑 report_progress 的指引 |

---

## 参考

- 现状基础设施详见本仓 `src/tools/subagents.rs`、`src/scheduler.rs`、
  `crates/microclaw-storage/src/db.rs`、`crates/microclaw-channels/src/channel.rs`。
- 拟人化/主动性配套见 `docs/humanlike-chat-analysis.md`（方案 A 与本方案的 standup 门控共用）。
- Proactive Conversational Agents with Inner Thoughts (CHI 2025) — <https://arxiv.org/abs/2501.00383>
