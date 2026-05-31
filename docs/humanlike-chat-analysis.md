# MicroClaw 拟人化分析与改进方案

> 目标：分析 MicroClaw 当前的"智能/拟人化"实现，对照 2025–2026 年最新研究，
> 找出让聊天"更像人"的改进方向。本文档为分析与方案，不含代码改动。

## 一句话结论

MicroClaw 的**记忆/认知层已经相当先进**（reflector、分层记忆、知识图谱，基本对齐
2025 年学术界 Mem0 / Generative Agents 的水平）；真正让它"不像人"的短板集中在
**交互的时序与社交维度**——它永远是「被叫到 → 立刻 → 一口气说完」的反应式机器人。
最高性价比的改进是：**主动性（Inner Thoughts）、情绪/语气动态、打字节奏、群聊插话礼仪**。

问题不在"脑子"，在"社交时序"。

---

## 一、现状评估：它已经做对了什么

把 MicroClaw 对照最新研究，会发现它的长期记忆架构已经是论文级别的：

| 学术机制 | MicroClaw 的对应实现 | 位置 |
|---|---|---|
| Generative Agents 的 **reflection**（周期性把情节记忆合成高层洞察） | `run_reflector` 增量反射循环，提取 memories/triples/user_model | `src/scheduler.rs:347-981` |
| **Mem0 两阶段**（extraction → update，按 saliency 提炼事实） | reflector 抽取 + Jaccard/embedding 去重 + `supersedes_id` 更新 | `src/memory_service.rs`, `src/scheduler.rs` |
| 分层记忆（identity / semantic / episodic） | L0 Profile / L1 Essential / L2 Relevant 三层 + token 预算分配 | `src/agent_engine.rs:2053-2232` |
| 时序知识图谱（valid_from / valid_to） | `knowledge_graph{subject,predicate,object,valid_from,valid_to,confidence}` | storage 层 |
| 连贯用户模型 | `USER.md` 单一叙述，跨 session 维持 | `crates/microclaw-storage/src/memory.rs` |
| 持久身份/人格 | `SOUL.md` 注入 `<soul>` 块，支持按频道/聊天覆盖 | `src/agent_engine.rs:2053-2090` |

交互层也已有不错的拟人细节：

- **选择性回复**：群里只回 @mention（Telegram `src/channels/telegram.rs:595-620`，
  Discord `:451-477`，Slack `:1186-1195`），不会对没提到自己的话做出反应。
- **Typing 指示器**：Telegram 每 4s 心跳重发 `ChatAction::Typing`（`:890-1110`）、
  Discord 保持 typing 直到完成（`:658-697`）、WeChat 有 typing ticket 机制。
- **消息分段**：长回复按换行边界分段（Telegram 4096 / Discord 2000 / Slack·Feishu 4000），
  保持代码块完整。
- **Mid-turn injection**：思考时收到新消息会并入当前轮（`enable_mid_turn_injection`），
  还带 emoji ack，不会忽略并发消息。

> 结论：这不是一个"幼稚的 bot"。它的脑子很好，缺的是社交时序。

---

## 二、最新技术调研（2025–2026）

### 1. Inner Thoughts —— 主动对话的关键范式
> Salesforce / 东京大学 / UCLA / Northeastern，CHI 2025

与本任务最相关。它不去"预测下一个该谁说话"，而是让 AI **在对话进行的同时并行地持续生成
一串"内心想法"**，每个 thought 带 `saliency`（新近度）和 `intrinsic motivation`（表达欲）
评分；只有当某个想法的表达欲超过阈值，才在"合适时机"插话。五步流水线：

```
trigger → retrieval → thought formation → evaluation → participation
```

用户在 **82%** 的情况下更偏好它，认为轮替更自然。这正好补上 MicroClaw 最大的空白：主动性。

- 论文：<https://arxiv.org/abs/2501.00383>
- 解读：<https://www.marktechpost.com/2025/01/05/researchers-from-salesforce-the-university-of-tokyo-ucla-and-northeastern-university-propose-the-inner-thoughts-framework-a-novel-approach-to-proactive-ai-in-multi-party-conversations/>

### 2. Mem0 —— 生产级记忆层（2025）
两阶段：extraction（用「对话摘要 + 最近 N 条」提炼候选事实）+ **异步** update（对每条候选做
ADD / UPDATE / DELETE / NOOP）。要点是异步更新不阻塞实时对话、只存最 salient 的事实。
MicroClaw 的 reflector 已经很接近，但**缺少人类式的"遗忘/衰减"**。

- 论文：<https://arxiv.org/abs/2504.19413>
- 解读：<https://apidog.com/blog/mem0-memory-llm-agents/>

### 3. Generative Agents 的 reflection 不可省
实验显示去掉 reflection 后，agent 在 48 模拟小时内退化成"重复、无上下文"的回复。
MicroClaw 已有等价机制，要保住。

- 综述与论文列表：<https://github.com/Shichun-Liu/Agent-Memory-Paper-List>

### 4. 情感智能 & 人格一致性
多篇 companion AI 研究（APA 2026 等）反复指出：真正"像人"的 bot 会**记得你说过的话、
回应你的情绪、读出语气并相应调整、有一致的性格与幽默**。persona consistency + 情绪检测
是用户满意度的核心。MicroClaw 的 SOUL.md 是**静态**的，没有动态情绪状态。

- APA 2026：<https://www.apa.org/monitor/2026/01-02/trends-digital-ai-relationships-emotional-connection>
- 人格构建：<https://www.chatbot.com/blog/personality/>
- 让 bot 更像人：<https://livechatai.com/blog/how-to-make-chatbot-sound-more-human>

---

## 三、改进方案（按性价比排序，落到 MicroClaw 的代码）

### 高优先级

**A. Inner Thoughts 式主动性（最大增量）**
当前 bot 只在被 @ 或 cron 触发时说话。引入一个轻量"内心想法"循环：
- 复用已有的 `scheduler` tick 与 reflector 基础设施，新增一个低频"念头评估"：对最近沉默的
  活跃聊天，用一次廉价 LLM 调用产出 `{should_speak: bool, motivation: 0-1, draft}`。
- 只有 `motivation > 阈值` 且满足节流（如 ≥30min 无人说话 / 触及用户已声明的兴趣或未完成
  承诺）才主动发一句。
- 落点：`src/scheduler.rs` 新增 `run_inner_thoughts()`，复用 `process_with_agent` 的
  `override_prompt`；阈值/节流走 config。
- 配套：从 reflector 抽取"未完成承诺 / ongoing goals / 习惯"作为主动触发源
  （例："上次你说下周给反馈"）。

**B. 情绪 / 语气动态状态**
- 在 `sessions` 表加一个 `mood_state`（或存进 memory），每轮做轻量情感判断
  （用户沮丧 / 兴奋 / 着急），在 `build_system_prompt` 注入 `<conversation_mood>` 标签，
  指导 LLM 调语气。
- 落点：`src/agent_engine.rs` 的 `build_system_prompt`，与现有 L0/L1/L2 注入同一处。
- 原则：**SOUL.md 管"性格不变"，mood 管"此刻的语气"**——人就是这样：人格稳定、情绪流动。

**C. 打字节奏 / 把回复拆成"人类大小的轮次"**
现在最终回复是一口气发出。让它更像人：
- 启用 Telegram 已有的 `streaming`（`microclaw.config.example.yaml` 里
  `streaming.enabled: false` → 可选开），并给 Discord/Slack 补增量编辑。
- 更轻量的做法：让 LLM 用已有的 `send_message` 工具把长答案**拆成 2–3 条短消息**，
  配可配置的随机延迟（300ms–2s）+ typing 心跳，模拟真人"边想边发"。
- 落点：`src/tools/send_message.rs` 已支持中途发送，只需在 SOUL/prompt 里鼓励 + 加节奏配置。

### 中优先级

**D. 群聊社交动态**
当前群里只是"加载上次回复后的消息"。可以：
- 用 reflector 额外抽取群 meta（成员、活跃度、话题、内部梗）存为群级记忆；
- 在 prompt 注入"群角色"（助手 / 成员 / 主持），让 bot 学会**何时插话、何时沉默**
  （Inner Thoughts 的 motivation 阈值天然适用于群）。

**E. 人类式记忆遗忘 / 衰减**
给 memory 的 `confidence` 随时间 / `last_seen_at` 衰减，低于阈值归档。这让"记得重要的、
淡忘琐碎的"更像人，也防止记忆无限膨胀。落点：reflector 里加 decay pass。

**F. 输入风格自适应**
reflector 增加"交互风格"PROFILE（`prefers_short_answers` / `formal_tone` / 语言偏好），
注入 prompt。

### 长期积累

**G. 反馈学习与纠正**
- 隐式反馈：用户追问 = 上轮不满意 → 写入 `sessions.quality_score`。
- 显式纠正命令：`/forget`、`/correct`。
- 长期目标与习惯追踪表，配合 A 的主动推送。

---

## 四、优先级速览

| 改进 | 拟人化感知提升 | 实现成本 | 复用现有设施 |
|---|---|---|---|
| A 主动性 (Inner Thoughts) | ★★★★★ | 中 | scheduler + reflector |
| B 情绪/语气动态 | ★★★★☆ | 低 | build_system_prompt |
| C 打字节奏/拆短消息 | ★★★★☆ | 低–中 | send_message + streaming |
| D 群聊社交动态 | ★★★☆☆ | 中 | reflector + prompt |
| E 记忆遗忘/衰减 | ★★☆☆☆ | 低 | reflector |
| F 输入风格自适应 | ★★★☆☆ | 低 | reflector + prompt |
| G 反馈学习/纠正 | ★★★☆☆ | 高 | sessions 表 |

**建议起步**：先做 A（主动性）+ B（情绪语气）——对"像人"的感知提升最大，且都能复用现有
reflector / scheduler / prompt 基础设施，改动相对收敛。

---

## 参考来源

- Proactive Conversational Agents with Inner Thoughts (CHI 2025) — <https://arxiv.org/abs/2501.00383>
- Inner Thoughts 解读 (MarkTechPost) — <https://www.marktechpost.com/2025/01/05/researchers-from-salesforce-the-university-of-tokyo-ucla-and-northeastern-university-propose-the-inner-thoughts-framework-a-novel-approach-to-proactive-ai-in-multi-party-conversations/>
- Mem0: Production-Ready AI Agents with Scalable Long-Term Memory — <https://arxiv.org/abs/2504.19413>
- Mem0 工程解读 (apidog) — <https://apidog.com/blog/mem0-memory-llm-agents/>
- Agent Memory 论文综述列表 — <https://github.com/Shichun-Liu/Agent-Memory-Paper-List>
- AI companions & emotional connection (APA, 2026) — <https://www.apa.org/monitor/2026/01-02/trends-digital-ai-relationships-emotional-connection>
- How to Build an AI Chatbot's Persona (2026) — <https://www.chatbot.com/blog/personality/>
- How to Make Your Chatbot Sound More Human — <https://livechatai.com/blog/how-to-make-chatbot-sound-more-human>
