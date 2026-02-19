# MicroClaw vs NanoClaw Deep Comparison and Development Plan (2026-02-19)

## 1. 对比结论（TL;DR）

- `microclaw` 已在“平台能力、可观测、治理能力、可扩展性”上明显超出 `nanoclaw`。
- `nanoclaw` 当前最强优势是“默认安全边界更硬（容器隔离是主边界）+ 极简可理解性 + 技能系统的确定性升级流程”。
- 如果目标是“对齐并超越”，短中期主线应是：
  1) 把 `microclaw` 的执行安全从“可选 sandbox”升级为“默认隔离优先”；
  2) 借鉴 `nanoclaw` 的 deterministic skills lifecycle，补齐可回放升级链路；
  3) 在保持多渠道/多模型/Web 运维优势的前提下压缩默认复杂度与认知负担。

---

## 2. 事实基线（代码证据）

### 2.1 NanoClaw 的关键特点

- 极简定位与单进程叙事：`tmp/nanoclaw_upstream/README.md:21`, `tmp/nanoclaw_upstream/README.md:35`, `tmp/nanoclaw_upstream/README.md:141`
- 安全主边界是容器隔离：`tmp/nanoclaw_upstream/docs/SECURITY.md:14`
- 挂载最小化（主群组/非主群组差异、只读全局目录、独立会话与 IPC）：`tmp/nanoclaw_upstream/src/container-runner.ts:68`, `tmp/nanoclaw_upstream/src/container-runner.ts:82`, `tmp/nanoclaw_upstream/src/container-runner.ts:102`, `tmp/nanoclaw_upstream/src/container-runner.ts:150`
- IPC 权限模型明确：`tmp/nanoclaw_upstream/docs/SECURITY.md:50`
- 技能系统强调 deterministic primitives 与升级工作流：`tmp/nanoclaw_upstream/README.md:90`, `tmp/nanoclaw_upstream/skills-engine/update.ts:45`, `tmp/nanoclaw_upstream/skills-engine/lock.ts:30`

### 2.2 MicroClaw 的关键特点

- 多渠道架构（Telegram/Discord/Slack/Feishu/Web）与统一运行时：`src/runtime.rs:55`, `src/runtime.rs:62`, `src/runtime.rs:72`, `src/runtime.rs:83`, `src/runtime.rs:95`, `src/runtime.rs:110`
- Agent loop 能力更完整（显式记忆快路径、会话恢复、压缩、hook、工具循环）：`src/agent_engine.rs:154`, `src/agent_engine.rs:289`, `src/agent_engine.rs:403`, `src/agent_engine.rs:428`
- Web 安全与治理能力（登录、会话、API key、scope、审计）：`src/web/auth.rs:55`, `src/web/auth.rs:149`, `src/web/auth.rs:177`
- hooks + MCP 联邦：`src/hooks.rs:17`, `src/hooks.rs:233`, `src/mcp.rs:52`
- sandbox 存在，但默认是 `Off`，且可降级到主机执行：`crates/microclaw-tools/src/sandbox.rs:12`, `crates/microclaw-tools/src/sandbox.rs:39`, `crates/microclaw-tools/src/sandbox.rs:283`
- 高风险工具有 approval gate，但是“应用层确认”而非 OS 级隔离：`crates/microclaw-tools/src/runtime.rs:74`, `crates/microclaw-tools/src/runtime.rs:220`, `crates/microclaw-tools/src/runtime.rs:236`

### 2.3 规模与复杂度采样

- 代码体量采样：`microclaw`（`src+crates+tests`）约 35,501 行；`nanoclaw`（`src+container+skills-engine`）约 13,866 行。
- 依赖采样：`nanoclaw` 运行依赖 9 个（`tmp/nanoclaw_upstream/package.json`）；`microclaw` 为多 crate 工作区（7 crates）。
- 结论：`microclaw` 功能密度更高，但默认可理解性成本高于 `nanoclaw`。

---

## 3. 对齐项（需要补齐 NanoClaw 的地方）

### A. 默认安全姿态（P0）

目标：从“可选 sandbox”转为“默认隔离执行 + 明确失败策略”。

- 将 `sandbox.mode` 默认从 `Off` 调整为“安全默认值”，并在无 runtime 时给出显式降级策略（可配置为 fail-closed）。
- 为 `bash` / 文件写入类工具增加统一执行策略标签（host-only / sandbox-only / dual）。
- 为每个 chat/session 映射独立容器上下文（已有 `session_key` 基础，可扩展容器命名和生命周期策略）。

验收：
- 新安装默认不在 host 直接执行高风险命令。
- 安全基线测试覆盖“runtime 缺失、网络隔离、mount 越权、跨 chat 访问”。

### B. 挂载与凭证暴露模型（P0）

目标：复制 nanoclaw 的“最小挂载 + 外部 allowlist + 秘钥最小暴露”。

- 引入外部 mount allowlist（项目外路径、不可被 agent 修改）。
- 增加敏感路径阻断模式（`.ssh`、`.env` 等）与 symlink 解析校验。
- 凭证改造为“按 tool capability 下发短时 token”而非全量 env 暴露（分阶段）。

验收：
- 增加安全文档与威胁模型页。
- 安全回归用例覆盖 traversal / symlink / secret exfiltration。

### C. Skills 的确定性升级链路（P1）

目标：在现有 ClawHub 基础上补齐“可回放、可回滚、冲突可审计”的生命周期。

- 在 lockfile 之上补齐 `preview/stage/commit/rollback` 流程。
- 记录技能对文件影响哈希与冲突风险，支持升级前 drift 检测。
- 失败场景支持自动备份恢复。

验收：
- 给定任意 core 版本迁移，支持 dry-run diff 与一键 rollback。

### D. 复杂度削峰（P1）

目标：保留能力上限的同时，降低默认认知成本。

- 新增 `microclaw init --profile personal-minimal`（单渠道 + 安全默认 + 最小工具集）。
- 提供“功能分层启动”说明：Core / Pro / Platform。
- README 首屏收敛为 5 分钟路径，深度能力下沉到 docs。

验收：
- 新用户 10 分钟内可完成首条消息与首个计划任务。

---

## 4. 超越项（MicroClaw 可建立护城河的方向）

### 4.1 可治理的多租户/多渠道能力（P0-P1）

`microclaw` 已具备基础，建议强化成“企业可用级”：

- 渠道级策略中心：按 channel/chat/tool 配置风险门、速率、审批策略。
- Web 管理面板加入“策略变更审计 + 回放”。
- 审批链扩展为人审（Web）与策略审（hook）双通路。

### 4.2 MemoryOps 体系化（P1）

已有结构化 memory + reflector，建议升级为产品能力：

- 增加 memory provenance（来自哪次对话/工具结果）可追踪图。
- 提供 memory 回放与“错误记忆回滚”。
- 将 memory 质量门（precision/recall）做成可观测 SLO。

### 4.3 MCP 可靠性与隔离（P1-P2）

- 对 MCP server 增加熔断/舱壁隔离/按 server 限流。
- 增加工具级超时预算与重试预算可视化。
- 为高风险 MCP server 引入 sandbox 执行或 sidecar 隔离。

### 4.4 生产可观测与运维体验（P1）

`microclaw` 已有 metrics + OTLP，建议扩展：

- 增加 trace 级 request timeline（ingress→LLM→tool→egress）。
- 增加错误预算仪表板（tool failure rate、approval drop rate）。
- 给 scheduler 增加 dead-letter queue 与自动补偿策略。

---

## 5. 分阶段开发计划（12 周）

## Phase 0（第 1-2 周）安全基线与设计冻结

- 输出 `security-baseline.md`：当前执行路径、资产分级、威胁面。
- 定义 sandbox 默认策略矩阵（desktop/server/CI 三种环境）。
- 完成回归测试清单（安全、跨 chat、工具权限、回滚）。

交付物：
- 架构决策记录（ADR）x2
- 基线测试计划 x1

## Phase 1（第 3-5 周）默认隔离执行落地（P0）

- 调整 sandbox 默认策略与失败策略。
- 工具执行策略引擎（host/sandbox 强约束）上线。
- mount allowlist + 敏感路径阻断 + symlink 校验。

交付物：
- 配置迁移脚本
- 安全回归测试套件
- 文档：`docs/security/execution-model.md`

成功指标：
- 高风险工具 host 直执行比例 < 5%
- 越权访问拦截率 100%（测试集）

## Phase 2（第 6-8 周）Skills 生命周期升级（P1）

- `clawhub` 新增 preview/stage/commit/rollback 命令。
- 文件影响哈希、冲突检测、备份恢复链路。
- 升级流程 CI 验证（模拟 drift + 冲突）。

交付物：
- `clawhub.lock.json` 扩展 schema
- 升级工作流文档与演示脚本

成功指标：
- 升级失败后可自动回滚成功率 > 95%

## Phase 3（第 9-10 周）复杂度削峰与默认体验（P1）

- `personal-minimal` 配置档。
- README 与 setup 交互重构（5 分钟上手路径）。
- Web 中增加“当前安全姿态”可视化。

交付物：
- onboarding 路径改版
- 默认配置 profile x3

成功指标：
- 新用户首条成功交互中位时间 < 8 分钟

## Phase 4（第 11-12 周）超越能力发布（P1-P2）

- MCP 可靠性治理（熔断、限流、预算）。
- MemoryOps 可追溯与回滚。
- 观测面板补齐 request timeline 与错误预算。

交付物：
- 运营手册更新
- Beta 发布说明

成功指标：
- Tool 失败恢复时间（MTTR）下降 30%
- Memory 错误修复时长下降 50%

---

## 6. 优先级清单（可直接进入 issue）

1. `P0` 默认 sandbox 策略切换与迁移。
2. `P0` mount allowlist + 敏感路径阻断。
3. `P0` 安全回归测试矩阵（含跨 chat 越权测试）。
4. `P1` ClawHub deterministic 升级工作流。
5. `P1` minimal profile 与 README 上手路径重构。
6. `P1` MCP 可靠性治理（熔断/限流/预算）。
7. `P2` MemoryOps 回溯与回滚。

---

## 7. 风险与依赖

- 默认安全策略升级会影响本地开发体验，需要 profile 分层避免“安全改动阻塞日常开发”。
- 技能升级工作流涉及 lockfile schema 演进，必须保证向后兼容。
- 多渠道 + Web + hooks 的联动测试成本高，建议先建立契约测试再做端到端扩容。

---

## 8. 推荐执行方式

- 双周迭代，每周一次安全/架构评审。
- 每个 Phase 至少 1 个“可演示场景”而非只交代码。
- 所有 P0 变更必须附带回归用例与回滚脚本。
