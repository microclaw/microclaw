# 已实现功能总览（branch: humanlike-chat-analysis）

把这个分支落地的代码改动汇总在一处，便于审阅。配套设计文档见
`humanlike-chat-analysis.md`、`concurrent-tasks-progress-reporting.md`、
`being-more-human.md`、`builtin-skills-roster.md`。

> 状态图例：✅ 已实现　·　⏳ 未做（可选）

---

## 1. 更像人地聊天

| 项 | 状态 | 实现 / 位置 |
|---|---|---|
| 简短优先、结论先行 | ✅ | `SOUL.md`（Chat style 段）+ `src/agent_engine.rs` 系统提示词 "Conversational style" 块 |
| 一次回多条短消息（multi-bubble） | ✅ | prompt 引导用已有 `send_message` 发前置气泡，最后一条作最终回复 |
| 情绪/语气动态（人格稳定、情绪流动） | ✅ | `src/mood.rs`（零成本启发式，中英双语，保守触发）→ 调用点注入 `<conversation_mood>` |
| 沟通风格跨会话学习 | ✅ | reflector 显式抽取沟通偏好为 PROFILE 记忆（`src/scheduler.rs` REFLECTOR_SYSTEM_PROMPT） |

## 2. 能干：专科 Sub-Agent 团队

| 项 | 状态 | 实现 / 位置 |
|---|---|---|
| 可扩展专家档案（7 个） | ✅ | `src/tools/specialists.rs`（generalist / mathematician / illustrator / researcher / coder / writer / analyst）。加专家 = 加一条记录 |
| `sessions_spawn` 路由到专家 | ✅ | `specialist` 枚举参数 → persona 注入子代理系统提示词 |
| 画师/分析师可用视觉工具 | ✅ | 子代理工具集加入 `generate_image` + `describe_image`（`src/tools/mod.rs`） |

## 3. 并发多任务 + 进度汇报

| 项 | 状态 | 实现 / 位置 |
|---|---|---|
| 后台并发多任务 | ✅（原有） | `sessions_spawn` + 信号量 + 每 chat 配额 |
| 命名任务（human label） | ✅ | schema v26 `subagent_runs.label`；`sessions_spawn` 的 `label` 参数 |
| 按 label 操作任务 | ✅ | `db.resolve_subagent_run_id`；`subagents_info` / `subagents_kill` 接受 run_id 或 label |
| 运行中途进度推送 | ✅ | `report_progress` 工具（仅子代理）+ `db.record_subagent_progress`；`📊 [label] (n%): …`，节流 `subagents.progress_min_interval_secs`(45s) |
| 完成汇报 | ✅（原有） | announce relay |
| “现在都在忙啥” | ✅ | `subagents_list` / `subagents_info` 带 label + 最新进度 |
| 主动 standup（长任务定期同步） | ✅ | `scheduler::spawn_task_standup`；`db.list_active_subagent_runs`；默认关 `subagents.standup.enabled`，节流 `interval_secs`(1800) |
| 卡住(stalled)检测 | ✅ | standup 中超 2× interval 且无近期进展的任务标 `⚠️ no recent progress` |
| fan-in 聚合（同 parent 全完成出总结） | ⏳ | 可选，未做 |

## 4. 出厂即用的内置 Skills（共 42 个）

| 批次 | 状态 | 内容 |
|---|---|---|
| 原有 | ✅ | pdf/docx/pptx/xlsx、apple-*、weather、github、propagation-trace、skill-creator、find-skills（12） |
| Batch 1 | ✅ | calculator、planning、code-review、regex |
| Batch 2 | ✅ | unit-converter、datetime、csv-tools、json-tools |
| Batch 3 | ✅ | debugging、shell-scripting、api-design、testing、git |
| Batch 4 | ✅ | research、wikipedia、define、brainstorming、decision-matrix、meeting-notes、goal-setting |
| Batch 5 | ✅ | mermaid、color-tools、writing-editor、summarize、email-drafting、translate |
| Batch 6 | ✅ | sql、qrcode、data-analysis、algorithmic-art |

- 机制：`skills/built-in/<name>/SKILL.md`，编译期 `include_dir!` 嵌入、运行时按兼容性自动安装。
- 安装测试断言全部嵌入（`crates/microclaw-app/src/builtin_skills.rs`）。

## 5. 已存在（无需新建）

| 项 | 说明 |
|---|---|
| 记忆衰减/遗忘（plan E） | ✅ 已有：`memory_service.rs` confidence×recency-decay（PROFILE 免疫）、`scheduler.rs` 调用 `archive_stale_memories`/`archive_excess_memories`、config `recency_half_life_days` |
| reflection（Generative-Agents 式） | ✅ 已有：reflector 循环 |

## 6. 可选未做（Phase 4+）

- fan-in 聚合汇报；群聊社交动态（plan D）；motivation 门控的“长沉默关怀”主动触达；ETA 估算。

---

## 新增配置项一览

```yaml
subagents:
  progress_min_interval_secs: 45     # 进度推送节流
  standup:
    enabled: false                   # 主动站会（默认关，因是主动发消息）
    interval_secs: 1800
```

## 测试

- 新增/覆盖：`mood`（4）、`specialists`（3）、subagent label+progress+resolve（storage）、
  standup 格式化与 stalled（scheduler）、builtin skills 安装。
- 已知失败：2 个 `hooks` 子进程测试在本沙箱环境失败，**在改动前的 baseline 同样失败**（环境性，与本分支无关）。
