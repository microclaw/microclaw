# 深度分析：下一步方向 — 2026-07

Status: **strategy** · Date: 2026-07-12 · 语言：中文（面向维护者的战略评审）
Companions: [`stability-usability-roadmap-2026-q3.md`](./stability-usability-roadmap-2026-q3.md) ·
[`competitive-intel-update-2026-07.md`](./competitive-intel-update-2026-07.md) ·
[`capability-deepening-2026-h2.md`](./capability-deepening-2026-h2.md)

本文回答一个问题：**在既有 Q3 稳定性路线图和 v0.4.0 安全支柱之外，还有什么是"别人没做、
预见未来、且不牺牲稳定可靠"的方向？** 结论先行：

> 三个杀手锏（污点追踪、家庭多用户模式、本地/云混合路由+成本治理），四个小额未来赌注
> （MCP Tasks、MCP server 化、受监督浏览器×污点、Trust Report 升格），以及对现有 Q3
> 稳定性计划的全面背书 + 两处测试盲区补充。

---

## 1. 现状判断（2026-07-12，基于代码核实）

- v0.3.0-rc.1，约 12.6 万行 Rust，8 个 workspace crate，16 个渠道适配器，约 60 个内置
  工具，47 个内置 skills，MCP 客户端、插件系统、A2A/ACP、哈希链审计、调度 DLQ、投递
  outbox、中断回收、CI eval gate 均已落地。
- 可靠性肌肉（supervision/outbox/turn-recovery/circuit-breaker fallback）在同体量开源
  项目里罕见；安全治理面（tool_policy、token budget、输出护栏、沙箱路由）领先于两个
  参照项目。
- 与自身叙事的差距：**"gets better the longer it runs" 还缺 skill curator**；guardrail
  仍是 warn-only；沙箱 Docker-only 且默认关；真·断点续跑（mid-turn resume）未完成。
  这些都已在既有 roadmap 中排期，本文不重复。

## 2. 竞争格局的三个关键事实（2026-07 外部调研）

1. **安全已成为品类的头号叙事，且是负面叙事。** OpenClaw（~38 万 star）今年连续曝出
   提示注入→本地文件读取、注入规则**持久化进记忆/配置成为后门**、约 4.3 万暴露实例
   93.4% 可利用；NSA 都为 MCP/agent 发布了安全指引。Simon Willison 的 "lethal trifecta"
   （私有数据 + 不可信内容 + 对外通信）成为行业通用批评框架。**没有任何项目在运行时
   层面真正打破这个三角** —— nanoclaw 只隔离了文件系统与凭证，不隔离信息流。
2. **成本失控是第二大用户痛点。** 单会话日烧 21.5M token 的案例、"默认配置浪费 60–80%
   预算"、Hermes 的 "week-3 bill problem"——全品类没有内置的预算治理器，修复方案全是
   博客里的手工调参。MicroClaw 已有 token budget + insights，只差把它变成产品面。
3. **多用户/家庭场景是真空地带。** 所有主流开源 bot 都是单主人模型；群聊内 per-user
   身份、私有 vs 共享记忆、未成年人策略、按成员配额——基本无人做（证据面偏薄，需
   小切片验证需求）。另：Rust 阵营出现了最接近的对手 **OpenFANG**（~1.7 万 star，
   "40 适配器/16 安全层"），营销声量大于实证——不要跟它拼数字，拼可验证的深度。

MCP 已是 table stakes（1 万+ 公开 server）；2026-07 规范 RC 新增 **Tasks / Extensions /
MCP Apps / auth 硬化**——这是一个可以早期占位的信号。

## 3. 三个"别人没做"的杀手锏（按优先级）

### 3.1 污点追踪信息流控制（taint-aware tool policy）— 最高优先级

**这是全品类最大的未解事故面，且 MicroClaw 的既有件几乎拼齐了。**

- 机制：每个进入上下文的内容块打**来源标签**（owner 消息 / 群成员消息 / web_fetch /
  browser / MCP 工具输出 / 召回记忆），标签随 `Vec<Message>` 持久化。当上下文存在
  tainted（不可信来源）内容时，对高危动作——对外 send_message、write_file、写记忆、
  网络 egress、High-risk 工具——按策略**降级、要求确认或阻断**；每次信息流决策写入
  哈希链审计。
- 为什么是我们：`ToolRisk` 分级、`tool_policy`、audit chain、injection scan、session
  的全量消息持久化都已存在，缺的只是把"来源"变成一等公民字段；Rust 类型系统天然适合
  把 taint 做成编译期可见的结构而非 prompt 约定。竞品（50 万行 TypeScript / Python
  云优先）追这个需要伤筋动骨。
- 落地三段：Phase 1 给消息块加 origin 元数据（纯记录，schema 迁移）；Phase 2
  tool_policy 增加 taint 维度，**warn-only**（沿用 output guardrail 的先观察后执行
  剧本）；Phase 3 可配置 block + 每条阻断的 `explain`。每段配 eval fixture
  （"被注入的网页试图让 bot 把 .env 发到群里"必须被拦）。
- 与 v0.4.0 egress control、per-chat least-privilege 同属"信息流治理"支柱，建议合并
  为一条叙事对外发布：**"第一个在运行时打破 lethal trifecta 的开源 agent"**。

### 3.2 家庭 / 小团队多用户模式 — 差异化蓝海，先 RFC 后切片

- 内容：群聊内 per-user 身份与权限（谁能触发 High-risk 工具）、**记忆作用域**（私有 /
  共享 / bot 自有；A 的私事不在 B 面前说）、per-user token 预算、未成年人安全策略、
  "谁教了 bot 什么"的可审计归因。
- 为什么是我们：群聊 catch-up、per-chat SOUL、per-chat user-model 记忆文件、RFC-0001
  auth 模型全部已有，距离比任何竞品都近；这不是 enterprise SaaS（不违反 non-goals），
  是自托管者的真实家庭场景。
- 风险：需求证据偏薄（多为厂商内容 + 一篇 arXiv）。**先出 RFC-0006 + 最小切片**
  （记忆作用域 + per-user budget 两项），在社区验证后再扩。

### 3.3 本地/云混合路由 + 成本治理面板 — 直击竞品最大槽点

- 内容：在已有 `AuxModels` 上加 **local-first 预设**——reflector、mood、标题、心跳、
  睡眠期整理走 Ollama 本地小模型，主 agent 轮次走云端，容量不足时优雅降级；把已有
  token budget + insights 升格为 web 面板上的**实时花费仪表盘 + 硬性 kill-switch**；
  每个 release 发布 **tokens-per-task 基准数字**（Q3 文档已列为 foresight bet，建议
  升格为正式条目）。
- 为什么是我们：单二进制 + $5 VPS + 本地模型 = 完整的"数据不出门、账单可预测"故事；
  Python/TS 云优先架构跟进成本高。这同时是防御（Hermes/OpenClaw 用户的迁移理由）
  和定位强化。

## 4. 预见未来的小额赌注（各 ≤2 周投入，可随时止损）

1. **MCP Tasks 早期占位**：2026-07 spec RC 引入长任务原语。把 completion contracts
   映射到 MCP Task 生命周期——做**第一个"契约校验的 MCP 任务执行器"**，把已有的
   trust 差异化输出到协议层。
2. **MCP server 模式**：目前只是 MCP 客户端。把自身工具/记忆/调度以 MCP server 暴露
   （套用已规划的 A2A/MCP trust tiers），让 MicroClaw 成为其它 agent 的记忆与调度
   后端——"个人 agent 基础设施"卡位。
3. **受监督浏览器 × 污点模型**：browser 工具加 per-site 权限 + taint 标注，是外部
   调研明确指出的"genuinely novel"组合；等 3.1 Phase 2 落地后顺势做。
4. **Trust Report 周报升格**：insights + contracts + audit chain 数据全在，渲染一份
   "本周它做了什么、哪些被证据校验、花了多少钱、护栏拦了什么"的用户报告。品类正在
   把"信任"变成产品界面，目前无人为终端用户渲染它。

## 5. 稳定可靠：背书 + 两处补充

Q3 路线图（stable 分支救援、发布节奏、24h soak、restart counters、LTS-1）方向完全
正确，**是本文一切建议的先决条件**——先做完 Horizon 1 再动杀手锏。代码盘点补充两个
路线图未覆盖的测试盲区：

1. **Web 前端零测试**：`web/package.json` 无任何测试框架，而 Governance/Tasks 面板已
   承载治理功能。建议最低限度：Vitest 组件测试 + 一条 Playwright 冒烟链路（登录 →
   发消息 → 改 tool_policy → 看审计），纳入 CI。
2. **集成测试与代码规模失衡**：`tests/` 仅 4 文件 951 行 vs 12.6 万行代码（单测很厚，
   1400+，但跨模块链路薄）。建议按 cookbook 的五个配方各建一条端到端 harness 测试
   （mock provider），恰好与 24h soak 的脚本化流量复用。

## 6. 不做什么（重申 + 一条新增）

不做渠道数量竞赛、enterprise SaaS、RL/训练飞轮、vector-DB 核心依赖、桌面 app 竞赛
（均见既有 non-goals）。新增：**不跟 OpenFANG 拼营销数字**（"N 个适配器、M 层安全"）；
MicroClaw 的对位话术是可验证的工程证据——soak 图表、eval gate、tokens-per-task 基准、
OWASP 自评。

## 7. 90 天排序建议

| # | 事项 | 依赖 | 定位 |
|---|---|---|---|
| 1 | Q3 Horizon 1 收尾（stable 救援、soak、零红测试） | — | 先决条件 |
| 2 | 污点追踪 Phase 1–2（warn-only）＋ egress control 同支柱推进 | #1 | 杀手锏 |
| 3 | 成本治理面板 + local-first 路由预设 + tokens-per-task 基准 | #1 | 杀手锏 |
| 4 | MCP Tasks 占位 + trust tiers 命名 | — | 未来赌注 |
| 5 | 家庭模式 RFC-0006 + 最小切片（记忆作用域、per-user budget） | #1 | 蓝海验证 |
| 6 | Trust Report 周报 + web E2E 冒烟 | #2/#3 | 信任产品面 |

三个杀手锏共享同一条对外叙事，也是对"要做别人没做的、要预见未来、要稳定可靠"三个
要求的直接回答：**"唯一一个你能审计它每一次信息流动、预测它每一分账单、并让全家人
安全共用的个人 agent——因为它从第一天就是为了在你自己的机器上跑十年而写的。"**
