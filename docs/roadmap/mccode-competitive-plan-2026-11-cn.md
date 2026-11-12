# mccode 对比 Claude Code、Codex CLI、OpenCode（2026-11）及下一阶段计划

状态：**进行中**（0.30 的 N1–N4 已实现，见第 10 节；0.31 待做）
更新：**2026-11-11**
基线：**mccode 0.29.1**
前几份计划：[`mccode-next-plan-cn.md`](./mccode-next-plan-cn.md)（0.21–0.23，上下文引擎）、
[`mccode-ux-config-plan-2026-11-cn.md`](./mccode-ux-config-plan-2026-11-cn.md)（0.25，交互与配置）、
[`mccode-desktop-plan-2026-11-cn.md`](./mccode-desktop-plan-2026-11-cn.md)（桌面版，提议中）

本文以 **mccode 0.29.1** 为主体：先列出它现在有什么（第 1 节），再逐项和 2026-11-10 发布的三个竞品比较
（第 2 节：Claude Code 2.1.322、OpenAI Codex CLI 0.167.1、OpenCode 2.2.7），标出 mccode 在每一项上是领先、持平还是落后，
最后给出 mccode 的追平项和版本安排。

> 竞品资料来自各自的 GitHub release / CHANGELOG、npm 发布记录和官方文档，调研日期 2026-11-11。
> 三家都是一周多版，配置名和默认值会变，只作设计参考。标“未核实”的条目没能在一手资料里确认。
> mccode 的状态来自 `CHANGELOG.md`（0.20.0–0.29.1）和代码。

---

## 0. 结论

1. **mccode 在安全和“改对代码”上领先。** 默认开的 OS 沙箱、改完自动验证并回灌失败、LSP 诊断、原生 ACP、
   文件级回退、每轮回执，三家没有一家全有。OpenCode 2.x 还删掉了 LSP，Codex 没有 undo。
2. **mccode 落后在“工作方式”，不在单个工具。** 三家都已经是“一个常驻服务，多个前端”，都有插件格式，
   都有自定义子代理，两家有 AI 代审批。mccode 在这些方面要么没有，要么只有半套。
3. **先补便宜的缺口。** 后台化正在跑的命令、对话一起回退、子代理模型、AI 审批扩展到所有高风险工具，
   这四项改动小、用户每天都会碰到，放进 0.30。
4. **再补体系。** 私有项目记忆、插件包格式放进 0.31；桌面版按原计划恢复，作为常驻多端的答案，不另做云。
5. **不跟的：** Code Mode、几百个代理的编排、语音。继续观察。

---

## 1. mccode 0.29.1 现状

| 方面 | 已有 | 来自版本 |
|---|---|---|
| 形态 | 全屏 / 内联 TUI；`-p` / `--json`；`mccode acp`（Zed，ACP v1，在 Registry）；`mccode mcp-server`；`-p --remote`（经 Server 配对） | 0.20、0.25、0.27 |
| 模型 | Anthropic、OpenAI 兼容、`openai-codex`（ChatGPT 登录）、DeepSeek 等；模型预设；`model.roles`（plan / review / summary） | 0.20、0.25、0.29.1 |
| 权限 | `plan` / `ask` / `auto`；运行中审批（一次 / 总是 / 命令前缀 / 拒绝）；破坏性命令始终问；`allow` / `ask` / `deny` 规则（bash、read、edit、net、mcp、agent、tool）；分层设置（用户 / 项目 / 本地 / managed）；`--review-commands` 用模型复核 shell 命令 | 0.20、0.25 |
| 安全 | Seatbelt / bubblewrap / Landlock 回退，默认开；`--no-network`；凭据目录隐藏；路径保护；项目信任绑定文件哈希 | 0.20 |
| 验证 | 自动探测检查命令，改动后运行、失败回灌、限定修复轮数；LSP 诊断作为 `lsp` 检查 | 0.20、0.23 |
| 上下文 | 按 token 预算；先裁剪旧工具输出，再结构化增量摘要；摘要失败留机械摘要；`/context`、`/compact <重点>`；模型自管工具（`context_note` / `rewind_context`）；`explore` 只读子代理；`/handoff`；Anthropic context editing | 0.21–0.23 |
| 回退 | 每轮影子 git 检查点；`/undo`、`/rewind [N]`（只回退文件）；按块审阅和撤回改动 | 0.20、0.25 |
| 会话 | 续接、`/fork`、`/export`、`--worktree` 任务、`/goal`（TUI、Zed、`-p`）、`/btw`、`--max-session-tokens` | 0.20–0.29 |
| 记忆 | 受信任项目读 AGENTS.md / CLAUDE.md / AGENT.md；模型维护 `.microclaw/memory.md`（在仓库里） | 0.20、0.23 |
| 扩展 | 自定义斜杠命令；Claude Code 兼容的 hooks；engine skills；MCP 客户端；项目 agents（只给 `explore` 用）；`mccode import` 导入 Claude Code / Codex / OpenCode 的设置、命令、agents、hooks 和 MCP | 0.23、0.25 |
| 体验 | 主题（truecolor / 256 / 16 色）、Markdown 与语法高亮、diff 渲染；排队与引导分开；命令面板、Ctrl+R 历史搜索、外部编辑器、图片粘贴、Ctrl+T 全文、侧栏；每轮回执；系统通知；手机聊天渠道审批（经 Server） | 0.25 |
| 审查 | `/review`（只读）；`mccode review --pr N --post` | 0.23 |
| 评测 | `mccode eval` | 0.20 |

**已知缺口**（前三条和规则覆盖范围是 0.25 记下的，至今仍在）：

- Ctrl+B 不能把运行中的命令放到后台（现在是开关侧栏）。
- Esc Esc 只回退文件，不回退对话。
- `model.roles.subagent` 能写进设置，但设置模板注明 “not used yet”，引擎没读它。
- `read(...)` 规则不覆盖 shell 命令；`net(...)` 规则只覆盖 `web_fetch`。
- 没有桌面版、没有 VS Code 扩展、Windows 没有沙箱。

---

## 2. mccode 与三家逐项对比

“mccode 位置”一列：**领先**＝三家里至多一家做到同等程度；**持平**；**落后**＝三家里至少两家有而 mccode 没有或只有半套。

| 能力 | **mccode 0.29.1** | Claude Code 2.1.322 | Codex CLI 0.167.1 | OpenCode 2.2.7 | mccode 位置 |
|---|---|---|---|---|---|
| OS 沙箱 | Seatbelt / bwrap / Landlock，**默认开**；Windows 无 | 有，**默认关** | 有，默认开，含 Windows | **无** | 领先（Windows 落后） |
| 改完自动验证 | **内置**：检查、失败回灌、修复轮 | 靠 hooks 自己搭 | 无 | 无 | 领先 |
| LSP 诊断 | **有** | 未核实 | 无 | 2.x **已删** | 领先 |
| 每轮回执 | 文件、检查、沙箱与网络、token、费用 | `/cost`、状态栏缓存命中 | `/usage`、费用估算 | 未核实 | 领先 |
| Zed / ACP | **原生**，在 Registry | 靠 Zed 写的适配器 | 靠 Zed 写的适配器 | 原生 | 领先 |
| 作为 MCP server | `mccode mcp-server` | 未核实 | 已移除 | 未核实 | 领先 |
| 导入别家配置 | Claude Code / Codex / OpenCode | 无 | Claude / Cursor | 无 | 领先 |
| 手机审批 | Telegram / Discord / Slack 卡片（经 Server） | Remote Control、手机 App | 无（未核实） | 配对 Web | 持平 |
| 上下文压缩 | token 预算、先裁剪再摘要、`/context`、模型自管 | 自动、`/compact <重点>`、`/context`、**空闲压缩** | 自动、远程压缩、Pre/PostCompact hooks | 自动，`buffer` 可按百分比 | 持平（缺空闲压缩） |
| 权限规则 | allow / ask / deny + managed | allow / ask / deny + managed | requirements.toml | 有序规则 + 硬拒绝 policies | 持平 |
| Hooks | Claude Code 协议；`after_edit` / `after_turn` | 多种事件，命令或 HTTP | 约 15 种事件，命令或 MCP 工具 | 插件内 | 持平 |
| `/goal` | TUI、Zed、`-p` | 有 | 有 | 有 | 持平 |
| 无头模式 | `-p --json`、`--remote` | `-p` + json / stream-json / schema | `exec --json` / `--output-schema` | `run --format json` | 持平（缺结构化输出 schema） |
| PR 审查 | `review --pr N --post` | GitHub App、Action | `@codex review` | Action 已停 | 持平 |
| 撤销 / 回退 | `/undo` `/rewind`，**只回退文件** | `/rewind`：代码 + 对话 | **无** | snapshots | 落后于 Claude Code |
| 网络控制 | `--no-network`；`net(...)` 只管 `web_fetch` | 白名单代理，按命令设域名 | 沙箱模式决定 | 无 | 落后于 Claude Code |
| AI 代审批 | `--review-commands`，只复核 shell 命令 | auto 模式分类器 | Guardian | 无 | **落后** |
| 记忆 | AGENTS.md / CLAUDE.md + 模型维护的 `.microclaw/memory.md`（**在仓库里**） | 多级 CLAUDE.md + 私有自动记忆 | AGENTS.md + 后台生成的私有记忆 | 只有 AGENTS.md | **落后**（缺私有记忆） |
| 自定义子代理 | 只有 `explore` 读项目 agents；子代理模型未接通 | 模型、effort、工具 | TOML，`worker` / `explorer` | `.opencode/agents/` | **落后** |
| 后台化运行中的命令 | **无** | 有 | `/ps` | Ctrl+B | **落后** |
| 插件 | **无打包格式**；零件齐全 | 插件、市场、Mods | 插件、市场 | 可热加载 JS 插件 | **落后** |
| 常驻服务 / 多端 | Server 配对；桌面版提议中 | 桌面、Web、手机、Remote Control | daemon + ChatGPT 桌面 | 共享服务 + 桌面、Web、手机 | **落后** |
| VS Code | 无（并行轨道） | 扩展 | 扩展 | 未核实 | **落后** |
| 多代理编排 | 无 | workflows、agent teams（实验） | ultra effort、`codex agents` | 后台子代理 | 落后（暂不追） |
| Code Mode | 无 | 无 | 实验，默认关 | 默认开 | 观察 |
| 语音 | 无 | 未核实 | 有 | 无 | 观察 |

---

## 3. 竞品近期变化（背景）

### 3.1 版本与节奏

| | 最新版本 | 节奏 | 许可 / 语言 |
|---|---|---|---|
| **mccode** | **0.29.1（11-11）** | 一周一到两版 | Rust |
| Claude Code | 2.1.322（11-10；`stable` 标签为 2.1.311） | 几乎每天一版，8 月以来约 85 版 | 闭源；TypeScript |
| Codex CLI | 0.167.1（11-10）；0.169 alpha 每天出 | 每周一到两个小版本 | Apache-2.0；约 95% Rust |
| OpenCode | 2.2.7（11-10）；1.x 仍维护到 1.19.5 | 一周数版；2.0 于 10 月发布 | MIT；TypeScript + Bun |

### 3.2 近三个月的主要变化

**Claude Code**

- 默认模型 Opus 5.5（1M 上下文）；auto 模式（分类器代替人工审批）成为终端和 VS Code 的默认模式。
- Dynamic workflows：模型写 JS 脚本编排几十到上百个子代理，可保存、恢复、确定性重放。
- Mods：插件可以画界面、拦截工具调用、改写子代理的启动参数；`claude plugin eval` 给插件打分。
- 空闲压缩：超过 200K token 的会话闲置约 54 分钟、在 1 小时 prompt cache 过期前先压缩。
- 子代理可单独设 effort 和 `autoCompactWindow`；self-hosted runner；跨会话、跨机器的 `SendMessage`。
- 没有 CLAUDE.md 时读 AGENTS.md；新增 `blockWritesOutsideWorkingDirectories`、`denyInsteadOfPrompting`。

**Codex CLI**

- 默认模型 GPT-6.1 Sol；推理强度到 `ultra`，`ultra` 会把任务拆给并行子代理。
- 常驻后台 daemon 自动启动；`codex agents` 指挥台；`codex queue` 往运行中的会话塞消息；代理能创建任务、给其他任务发消息。
- Guardian：AI 代审批沙箱越权请求（`--approve-for-me`，被拒后 `/approve` 重试）。
- memories v2：后台从闲置会话总结本地记忆、脱敏；能从其他 agent 导入记忆，`/import` 导入 Claude Code / Cursor 的配置和对话。
- 全屏 TUI、worktree 默认开；主题、Vim、语音、Mermaid、`/config` 面板、`/presets`、`/goal`。
- 移除了 `codex mcp-server`；没有 `/undo`。

**OpenCode 2.x**

- TUI、桌面、Web、手机共用一个后台服务；桌面终端由服务端 PTY 支撑，重启后保留。
- Code Mode 对所有 MCP 默认开：模型在小型 JS 解释器里组合工具调用。
- `/goal`（reviewer 确认完成）、`/schedule` 定时提示、实验性交互 artifact、`run --worktree`。
- 80 多项内部功能改成可热加载插件，TUI 插件稳定；“Claude Agent” provider 借用 Claude Code 登录。
- **同时删掉了**：LSP 诊断、会话分享、GitHub Action、CLAUDE.md 回退（只读 AGENTS.md）。
- 默认权限几乎全放行，**没有 OS 沙箱**（SECURITY.md 明说不沙箱化 agent）。

---

## 4. 计划

编号 `N`。每项写清做什么、参照谁、落在哪里、怎么验收。

### P0：改动小、天天碰到（目标 0.30）

#### N1. 把正在跑的命令或子代理放到后台

- **参照**：Claude Code、OpenCode 2.x 的 Ctrl+B；Codex 的 `/ps`。
- **做法**：
  - `bash` 工具已有 `run_in_background` 和 `ProcessRegistry`（`tools/background_process.rs`）。
    新增“把前台命令转入后台”：前台执行时进程也登记进 registry，按键后工具立即返回“已转入后台，进程 id …”，
    之后模型用 `bash_output` 读取。
  - 子代理同理：转入后台后父代理继续，子代理结束时以消息形式回到对话。
  - 键位：Ctrl+B 改为“转入后台”，侧栏改到 Ctrl+]（`keymap.rs` 可配置，升级说明写明）。
    不用 Ctrl+\：它在不少终端和 tmux 配置里是 SIGQUIT 或前缀键。
  - 新增 `/jobs`：列出后台进程和子代理，可查看输出、结束。Zed 里对应一个斜杠命令。
- **验收**：`sleep 300` 转入后台后对话继续；`/jobs` 能看到并结束它；退出时进程被清理（现有 drop 行为不变）。

#### N2. 回退时连对话一起回退

- **参照**：Claude Code `/rewind`（代码、对话或两者）；0.25 的已知缺口。
- **做法**：
  - `CodeSession::rewind`（`driver.rs`）目前只调 `restore_checkpoint`。检查点记录当时的会话消息条数，
    回退时截断 `sessions` 里的消息，并写一条“已回退到第 N 轮”的系统备注，避免模型以为改动还在。
  - 对话框给三个选项：只回退文件 / 只回退对话 / 两者（默认两者）。Esc Esc 进入同一个对话框。
  - SDK 增加对应参数，ACP `/rewind [N]` 一起跟上。
- **验收**：回退两轮后问模型“刚才改了哪些文件”，它不再提被回退的改动；只回退对话时文件保持不变。

#### N3. 子代理用自己的模型，项目 agents 可被子代理调用

- **参照**：三家都支持自定义子代理，可设模型、工具；Claude Code 还能设 effort。
- **做法**：
  - 接通 `model.roles.subagent`：`launch.rs` 把它传给引擎，`sub_agent` 工具用它建 provider。删除模板里的 “not used yet”。
  - 项目 agents（`.microclaw/agents/*.md`，现在只给 `explore` 用）也能被 `sub_agent` 按名字调用：
    frontmatter 支持 `model`、`tools`（只能收窄，不能放宽工具策略）、`description`。
  - `read_only_subagent_channels` 的限制保持不变；`plan` 模式下子代理仍只读。
- **验收**：设置 `model.roles.subagent` 后，回执里子代理的用量记在该模型名下；一个只给 `read`、`grep` 的项目 agent 调不到 `bash`。

#### N4. AI 代审批覆盖所有高风险工具

- **参照**：Claude Code auto 模式分类器；Codex Guardian。
- **做法**：
  - 现在 `--review-commands` 只在 `launch.rs` 里给引擎装一个 `command_reviewer`，只复核 shell 命令。
    扩展为审批复核器：写工作区外的文件、联网、MCP 工具、`deny` 以外的所有 `ask` 都先过复核模型
    （默认用 `model.roles.review`）。
  - 结果只有两种：放行，或转人工。复核器**不能**直接拒绝后结束，避免模型自己说服自己；破坏性命令仍始终问人。
  - 每次复核写进回执：谁批的、理由一句话。设置项 `approvals.reviewer: off | commands | all`，`--review-commands` 保留为 `commands` 的别名。
- **验收**：`approvals.reviewer: all` 下，一轮包含联网和工作区外写入的任务，要么被自动放行并在回执里有记录，
  要么弹人工审批；`rm -rf` 类命令始终问人。

### P1：补体系（目标 0.31）

#### N5. 私有项目记忆

- **参照**：Claude Code 自动记忆（按仓库、私有）；Codex memories v2（后台总结、脱敏、可导入）。
- **做法**：
  - 保留 `.microclaw/memory.md`（团队共享、进 git）。新增私有记忆 `~/.mccode/projects/<项目哈希>/memory.md`，
    提示词说明两者分工：仓库事实写共享文件，个人偏好和本机情况写私有文件。
  - `/memory` 打开两个文件；压缩后两份记忆都重新注入。
  - `mccode import` 增加导入 Claude Code 自动记忆和 Codex memories。
  - 不做后台总结。先看模型主动写的效果，再决定要不要像 Codex 那样从闲置会话里总结。
- **验收**：在一个项目里告诉模型“我习惯用 nextest”，新会话里它直接用；共享文件不出现这句话。

#### N6. 插件包格式

- **参照**：三家都有插件；Codex 给插件 hook 设置 `CLAUDE_PLUGIN_ROOT`，说明 Claude Code 的插件格式已经成了事实标准。
- **做法**：
  - 一个插件是一个目录：命令、agents、hooks、skills、MCP 服务、主题。读取 Claude Code 的
    `.claude-plugin/plugin.json` 布局，不另造格式；不支持的部分（例如 Mods）安装时列出并跳过。
  - `mccode plugin add <git 地址 | 路径>`、`list`、`remove`、`update`。只从 git 或本地安装，不做市场服务。
  - 插件内容遵守项目信任：未信任的项目不加载项目级插件。插件 hook 走现有的 Claude Code hook 协议。
- **验收**：安装一个公开的 Claude Code 插件，其中的命令和 hooks 在 TUI 里生效；卸载后不留痕迹。

#### N7. 空闲压缩

- **参照**：Claude Code 2.1.299：大会话闲置、prompt cache 快过期前先压缩。
- **做法**：引擎记录上一次请求时间和缓存 TTL。TUI 会话闲置超过 TTL 的 90%、且上下文超过预算的一半时，
  后台做一次压缩，下次提问时直接用新的前缀。默认只对 Anthropic 打开（其他 provider 的缓存行为不同）。
- **验收**：模拟时钟的单元测试；一次真实 Anthropic 会话的回执里，闲置后第一问的缓存写入量下降。

### P1：常驻多端

#### N8. 恢复桌面版计划，不另做 daemon

- **背景**：三家都已是“一个服务，多个前端”。我们已有两块：Server 配对（`--remote`、聊天渠道审批）和
  `microclaw-code-core` 的 `Control` / `Update` 驱动层。桌面版计划原定 0.28 出预览（M1），被 Matrix 移除和 `/goal` 两个版本挤后。
- **做法**：按 [`mccode-desktop-plan-2026-11-cn.md`](./mccode-desktop-plan-2026-11-cn.md) 恢复 M1，
  作为并行轨道，不占 0.30 / 0.31 的主线。会话锁保证 TUI、Zed、桌面不会同时驱动一个会话。
- 不做本地 daemon，也不做云任务：跨设备的需求由 Server 配对承担。

### P2：观察，不排期

| 项 | 谁有 | 暂不做的原因 |
|---|---|---|
| Code Mode（JS 组合工具调用） | OpenCode 默认开，Codex 实验 | 收益依赖模型；要引入 JS 运行时。等 Codex 转正后再评估 |
| 大规模多代理编排 | Claude Code workflows，Codex ultra | 成本高、场景少；先做好 N3 |
| 语音 | Codex | 终端场景需求弱 |
| VS Code 扩展、Windows 沙箱、Windows ARM | Claude、Codex | 已在 [`next-plan-2026-11-cn.md`](./next-plan-2026-11-cn.md) 的并行轨道里 |

---

## 5. 继续加码的差异化

这些是三家没做或做了又删的。保持并写进对外文档：

- **默认开的 OS 沙箱**，命令自带网络开关；Claude Code 默认关，OpenCode 没有。
- **改完自动验证**：检查、失败回灌、修复轮，加上 LSP 诊断；OpenCode 2.x 删了 LSP。
- **文件级回退**：Codex 没有 undo。N2 之后对话也能回退。
- **原生 ACP**：Claude Code 和 Codex 在 Zed 里都靠 Zed 写的适配器。
- **每轮回执**和**手机聊天渠道审批**（Telegram / Discord / Slack）。
- **从三家导入配置**：Codex 只导 Claude / Cursor，另外两家不导入。

可以考虑参加 [FrontierHarness](https://frontierharness.org/live/) 的自测，用数字证明这条线。需要先写一个 Harbor 适配器，另行计划。

---

## 6. 版本计划

| 版本 | 内容 | 验收 |
|---|---|---|
| **0.30** | N1–N4 | 单元测试和 TUI 快照测试；Zed 里 `/jobs`、`/rewind` 走查；用真实模型（DeepSeek、Anthropic）各跑一遍 N1–N4 的验收步骤 |
| **0.31** | N5–N7 | 同上；安装一个公开 Claude Code 插件的端到端测试 |
| 并行 | N8（桌面版 M1）、VS Code、Windows 沙箱、Windows ARM | 按各自计划 |

---

## 7. 实施注意

- N1 改 Ctrl+B 是默认键位变化，升级说明写明，并告诉用户如何在 `keymap` 里改回。
- N2 截断会话消息前先归档（和压缩前归档一样），回退可以再撤销。
- N3、N4 涉及工具策略：子代理和复核器只能收窄权限，不能放宽；`deny` 规则和破坏性命令检查在复核之前执行。
- N4 的复核结果进回执和审计日志；复核模型调用失败一律转人工。
- N6 安装插件就是执行别人的 hooks：安装时列出插件包含的 hooks 和 MCP 命令，用户确认后才启用。
- 新配置项都有默认值，默认行为不变：`approvals.reviewer` 默认 `off`（`--review-commands` 时为 `commands`），空闲压缩默认只对 Anthropic 打开。

---

## 8. 待确认

1. Ctrl+B 改为“转入后台”、侧栏移到 Ctrl+]，可以吗？
2. N4 复核器只放行或转人工、不能单独拒绝，可以吗？
3. N6 直接沿用 Claude Code 插件布局，不另造格式，可以吗？
4. 桌面版 M1 作为 0.30 / 0.31 期间的并行轨道恢复，可以吗？

---

## 9. 来源

- Claude Code：<https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md>、
  <https://registry.npmjs.org/@anthropic-ai/claude-code>（发布日期）、<https://code.claude.com/docs/en/>
  （context-window、memory、sandboxing、permission-modes、settings、headless、model-config、agent-teams、workflows）
- OpenAI Codex：<https://github.com/openai/codex/releases>、<https://learn.chatgpt.com/docs>
  （config-file/config-reference、customization/memories、agent-configuration/subagents、sandboxing、hooks、code-review、models、pricing）、
  <https://zed.dev/acp/agent/codex-cli>
- OpenCode：<https://github.com/anomalyco/opencode/releases>、<https://anoma.ly/notes/opencode-2-0/>、
  <https://opencode.ai/v2/docs/>（config、permissions、migrate-v1）、<https://zed.dev/acp/agent/opencode-v2>
- mccode：`CHANGELOG.md`（0.20.0–0.29.1）、`crates/microclaw-code-core/src/{prompt,settings,launch,driver}.rs`、
  `apps/microclaw-code/src/tui/keymap.rs`、`crates/microclaw-engine/src/tools/{explore,background_process}.rs`

---

## 10. 0.30 交付情况

第 8 节的前两个问题按建议执行：Ctrl+B 改为“转入后台”、侧栏移到 Ctrl+]；复核器只能放行或转人工。

| 项 | 交付 | 和计划的差别 |
|---|---|---|
| N1 | Ctrl+B 把正在跑的前台命令转入后台，工具立即返回进程 id；`/jobs`（TUI 与 Zed）列出后台命令和子代理，`/jobs <id>` 看输出，`/jobs kill <id>` 结束，运行中也能用。工作区里的前台命令改走 `ProcessRegistry`（stdout、stderr 合并输出，取消运行仍会结束命令）。SDK：`background_running_commands`、`background_jobs`、`background_job_output`、`kill_background_job` | 子代理不需要“转入后台”：`sessions_spawn` 本来就是后台运行，`/jobs` 能列出和结束它；`explore` 是同步、只读、短任务，保持不变 |
| N2 | `/rewind` 默认同时回退文件和对话；时间线里 Enter 两者、`f` 只回退文件、`c` 只回退对话、`e` 只编辑提示词；`/rewind <id> files\|chat\|both`、Zed `/rewind N [files\|chat]`。只回退一边（以及 `/undo`）后，下一条提示会告诉模型文件和对话可能不一致。对话截断前先归档；该轮之后发生过压缩时，对话保持不变并说明原因。SDK：`session_mark`、`rewind_session` | 检查点不记录消息条数，改为每轮开始时记一个“会话标记”（条数 + 前缀指纹），指纹不符就拒绝截断，避免压缩后截错位置 |
| N3 | 接通 `model.roles.subagent`（引擎 `aux_models.subagent`、SDK `subagent_model`），`sessions_spawn` 和 `explore` 都用它；`sessions_spawn` 新增 `agent` 参数，按项目 agent 的提示词、`model` 运行；新增 front matter `tools:`，只能收窄工具集，`explore` 同样遵守 | 计划里写的 `sub_agent` 工具实际是 `sessions_spawn` |
| N4 | `permissions.reviewer: off \| advise \| approve`；`approve` 在 ask 模式下自动放行复核模型判为 SAFE 的高风险调用（命令、工作区外写入、联网、MCP），其余转人工；破坏性命令、`ask` 规则、hooks、复核失败都转人工；回执列出复核放行的调用和理由；复核用 `model.roles.review`；`--review-commands` 等于 `advise` | 设置值从计划里的 `commands \| all` 改名为 `advise \| approve`，因为差别不在“复核哪些工具”（引擎一直复核所有高风险调用），而在“复核器能不能放行” |

