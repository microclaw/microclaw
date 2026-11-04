# MicroClaw Code：三产物架构与编码 Agent 提案

状态：**已批准，首版实现中** · 日期：**2026-11-03**

## 一、产品线

MicroClaw 收敛为三个产物，共享同一个 Agent Engine：

| 产物 | 形态 | 给谁用 | 典型场景 |
|---|---|---|---|
| **MicroClaw**（Server，`microclaw`） | 守护进程 + Web 控制台 | 运维、团队 | 常驻、聊天渠道、定时任务、远程自动化 |
| **MicroClaw Code**（`mccode`） | 全屏 TUI + `-p` 脚本模式 | 开发者 | 在本地仓库里写代码，改完自动验证 |
| **MicroClaw SDK**（`microclaw-sdk`） | Rust 库 | 集成方 | 把引擎嵌进自己的应用 |

**MicroClaw Work（GPUI 桌面端）停止维护并从仓库删除**，不做兼容迁移：
- 删除 `apps/microclaw-work`、`apps/microclaw-work-headless`、`crates/microclaw-work-app`、`crates/microclaw-work-runtime`；
- 删除对应的打包文件、构建/冒烟/发布脚本、CI 任务和发布产物；
- 发布脚本会从 Homebrew tap 里删除 `microclaw-work` cask。

Server 的设备配对接口保留，不再提 Work，留给 Code 以后做"交给 Server 远程执行"。

## 二、为什么这样分

- 按界面形态和场景划分，三者定位互不重叠：常驻服务、本地开发工具、嵌入库。
- 去掉 GPUI 后依赖少了约 300 个包，macOS 签名和公证、DMG、Windows 安装包、便携包这些发布链路全部消失。
- 上次架构审视里与 Desktop 相关的问题随之消失：两个入口能力不对等、两份会话记录并发写、按 `"work"/"desktop"` 渠道名做的特殊处理。

## 三、MicroClaw Code 的结构

```text
apps/microclaw-code        mccode：命令行、全屏 TUI、-p / JSON 输出、setup
        │  只消费 Update、只发送 Control
crates/microclaw-code-core 与界面无关的核心
        ├─ home      Code 自己的目录与模型配置（~/.microclaw/code）
        ├─ project   仓库识别、.microclaw/project.yaml、检查命令识别
        ├─ trust     项目信任（绑定项目文件内容的哈希）
        ├─ verify    运行检查、生成修复提示
        ├─ git       工作区指纹（判断本轮是否改了文件，包括 bash 改的）
        ├─ sessions  会话索引（只存元数据，对话内容在引擎数据库）
        └─ driver    一轮对话：运行 Agent → 审批 → 验证 → 修复循环
        │
crates/microclaw-sdk       唯一入口（CI 检查：Code 不能直接依赖 microclaw-engine）
        │
crates/microclaw-engine
```

关键约束：
1. **只通过 SDK 访问引擎。** `check_runtime_boundaries.sh` 禁止 `microclaw-code` 和 `microclaw-code-core` 直接依赖 `microclaw-engine`。SDK 缺什么就补进 SDK，这次补了 `model_providers()` 和 `validate_config_file()`。
2. **逻辑和界面分离。** 回合驱动器（driver）通过 `Control` / `Update` 消息和前端通信；TUI 和 `-p` 输出是两个前端，共用同一套逻辑和测试。
3. **独立的数据目录。** Code 的引擎数据库、记忆、快照、会话索引、信任记录都在 `~/.microclaw/code`，从不写入 Server 的 `~/.microclaw`。模型凭据可以借用 Server 的配置文件，但数据目录始终是 Code 自己的。
4. **只保留一份会话记录。** 对话内容只存在引擎数据库里；`sessions.json` 只记录项目、标题、时间和轮数。

## 四、首版能力

### mccode
- **全屏 TUI**：
  - 流式回复；工具调用带状态和耗时，bash 命令显示输出尾部；
  - 彩色 Diff、计划清单、检查结果；
  - 对话框：审批、项目信任、执行计划；
  - 多行输入、历史记录、Tab 补全 `/命令` 和 `@文件`；
  - Shift+Tab 切换模式；Esc 中止；Agent 运行中输入文字即插话（steer）。
- **权限模式**：
  - `plan`：只读工具，出计划，确认后切到 ask 执行；
  - `ask`（默认）：编辑直接生效，bash 每次审批；
  - `auto`：命令自动执行，破坏性命令和项目配置的 `always_ask` 仍要审批。
- **工作区工具集**：非 plan 模式使用 `ToolPolicy::WorkspaceWrite`，只提供写代码需要的工具。
- **验证闭环**：本轮改动过工作区（文件工具或 bash 都算）就运行项目检查；失败交回 Agent 修复，有轮数上限，并明确禁止削弱测试。
- **项目信任**：
  - `.microclaw/project.yaml` 只有在信任后才生效，而且信任绑定文件内容的哈希；
  - 文件内容变了（比如 pull 进了别人的改动）会重新询问；
  - 仓库里的 `microclaw.config.yaml` 永不加载。
- **`-p` 模式**：退出码 0（完成）/ 1（失败、取消或检查仍失败）/ 2（等待审批）；`--session <id> -p 1|3` 续跑；`--json` 输出 JSONL 事件。
- **子命令**：`setup`（交互式或带参数）、`doctor`、`check`、`init`、`info`、`sessions`、`trust`；Server 的 `microclaw code …` 转发到 `mccode`。

### 引擎改进（Server 同样受益）
| 改动 | 说明 |
|---|---|
| glob / grep 遵守 `.gitignore` | `tools/workspace_walk.rs` |
| `edit_file` 多处编辑 | `edits[]` 全部成功才写入；`replace_all` |
| 防覆盖检查 | `FileStateTable`：文件在 Agent 读过之后被外部修改，拒绝覆盖 |
| bash 后台进程 | `run_in_background` + `bash_output` / `bash_kill` |
| 状态归属到注册表 | 防覆盖表和后台进程表属于各自的工具注册表，不再是全进程静态变量；注册表释放时会结束仍在运行的后台进程（对应审视里的 C7） |
| 直连工作区的 bash 目录 | 在项目根目录执行，不再进 `tmp/` |
| `ToolPolicy::WorkspaceWrite` | 原来未使用的协议变体获得明确语义 |
| ACP 事件 | 工具调用、Diff、计划；只有最终回复时（如审批提示）也会显示 |

## 五、验收

- **单元测试**：core 19 个、app 13 个、SDK 新增 1 个，加上引擎新工具和工作区工具集的测试。
- **`-p` 端到端**：用本地模拟的 OpenAI 兼容服务、真实 `mccode` 二进制验证了：
  - `setup` 写配置；
  - 未信任项目不自动验证；信任后"改错 → 检查失败 → 交回修复 → 通过"；
  - 仅用 bash 改文件也会触发检查；
  - auto 模式下 `git push` 仍要审批；
  - 审批挂起后 `-p 3` 拒绝续跑，命令确实没有执行；
  - JSON 输出；
  - 数据只写入 Code 自己的目录。
- **TUI 端到端**：用 pty 加终端模拟器（pyte）验证屏幕内容：信任对话框 → `/plan` → 执行计划对话框 → 执行并通过检查 → bash 审批对话框 → 批准 → Shift+Tab 切模式 → `/exit`。

## 六、第二批（已实现）

| 项目 | 说明 |
|---|---|
| 审批在引擎内挂起 | 调用方在 `RunRequest.metadata` 里设 `interactive_approvals: true`（SDK 常量 `INTERACTIVE_APPROVALS`），引擎为这次运行登记审批代理（`approval_broker`，按渠道和会话区分，随运行结束注销）。需要审批时，引擎发出带 `approval_id` 的 `ApprovalRequired`，在原地等待 `RuntimeControl::ResolveApproval`：批准则重试工具，"始终允许"则记录授权后重试，拒绝则把"用户拒绝"作为工具结果交给模型，同一次运行继续。没有登记代理的渠道（Telegram 等）和 `-p` 非交互模式仍走原来的文字审批。每次决定写入审计日志（`in_run_decision`）。headless 执行器的能力声明改为 `approvals: true` |
| 按命令前缀放行 | Shell 审批多一个选项"在本项目始终允许 `cargo test`"（按键 `p`）。规则存在 `~/.microclaw/code/allow-rules.json`，按项目区分。只匹配单条简单命令：带 `;`、`&&`、管道、重定向、`$(…)`、换行的命令一律不匹配；解释器、`sudo`、`rm`、`curl` 等不能按前缀放行；破坏性命令清单（`always_ask`）优先，这类命令也不提供该选项。管理方式：`/allow`、`mccode allow list/add/remove` |
| 续接会话回显历史 | SDK 新增 `MicroClaw::session_messages(session, limit)`；`mccode -c` / `--session` 在 TUI 里显示最近 60 条消息，验证回合压缩成一行 |

验证：
- 引擎测试用真实 Agent 循环覆盖批准（同一次运行看到命令输出）、拒绝（模型收到拒绝结果）、未开启时仍走文字审批；审批代理有单元测试。
- TUI 端到端（pty + pyte）：`ls -a` 弹出审批，按 `p` 保存规则，接着 `ls -l` 按规则自动批准，`git push` 弹出审批且不提供项目规则，按 `3` 拒绝，模型在同一次运行里继续并给出答复（模拟服务共收到 4 次请求，中间没有新的用户消息）；退出后 `mccode -c` 显示历史。
- `-p` 回归：审批挂起返回 2，`--session <id> -p 3` 拒绝，命令没有执行。

## 七、第三批（已实现）

| 项目 | 说明 |
|---|---|
| `apply_patch` 工具 | 引擎新工具，使用 `*** Begin Patch` 格式，一次调用里新增、删除、移动、修改多个文件。所有操作（路径检查、防覆盖检查、定位每个修改块）先全部校验通过才写入，否则一个文件都不改。修改块先按原文匹配，再忽略行尾空白，再忽略首尾空白；`@@ <文本>` 可以先跳到某一行之后再找。属于工作区工具（中风险），每个改动的文件都发出 `FileDiff` 事件 |
| `/undo`、`/rewind` | 每轮开始时用引擎的影子 git 仓库给工作区打快照（不碰用户自己的 `.git`）。`/undo` 恢复到最近一次改过文件的那一轮之前；恢复前先给当前状态打快照，所以 `/rewind <id>` 还能回去 |
| `/review`、`mccode review` | 取 `git diff HEAD` 加未跟踪文件（最多 60 KB）交给只读工具集审查，按严重程度列出问题，必须带 `文件:行号` 和修复建议；可加关注点 |
| `/model`、`/cost`、`/compact`、`/fork` | 按会话切换模型（只在本次运行内有效，分叉时带过去）；本会话的请求数和输入/输出 token，按模型列出；立即压缩旧消息；把对话复制到新会话继续，原会话保留 |
| AGENTS.md | 信任的项目把 `AGENTS.md`（没有就用 `CLAUDE.md`、`AGENT.md`，最多 16 KB）放进系统提示；未信任的项目只告诉 Agent 这个文件存在，不当作指令 |
| SDK | `checkpoint` / `checkpoints` / `restore_checkpoint`、`session_usage`、`session_model` / `set_session_model`、`compact_session`、`fork_session` |

验证：
- 引擎测试：`apply_patch` 6 个（多文件增删改移、某个块不匹配时什么都不改、空白容错和按顺序定位、防覆盖、格式错误、文件末尾）；会话分叉、切换模型、压缩；快照恢复（恢复后还能恢复回来）。
- TUI 端到端（pty + pyte + 模拟服务）：`apply_patch` 改两个文件并显示两份 Diff；信任后系统提示里有 AGENTS.md；`/review` 只给只读工具；`/undo` 删掉新增文件、还原修改；`/cost`；`/model mock-two` 之后请求确实用了 mock-two；`/fork` 之后继续对话；`/compact`。
- `mccode review typos`：请求里带有改动的 Diff 和关注点，不提供任何写入工具；工作区干净时提示没有可审查的内容。

## 八、后续（按优先级）

1. **地基**：
   - 统一的工具策略判断，去掉按渠道名的硬编码；
   - Agent 主循环收敛为单一入口。
2. **安全**：
   - 系统级沙箱（Landlock/seccomp、bwrap、Seatbelt）；
   - auto 模式下对命令做模型复核。
3. **体验**：
   - 可交互的持久终端；
   - 子目录里的 AGENTS.md 按路径就近加载。
4. **接入**：`mccode acp`（含 `session/request_permission`，可直接接引擎内审批）；`mccode mcp-server`；交给已配对的 Server 远程执行。
5. **评测与发布**：
   - Minimal 预设跑 Terminal-Bench；用本仓库历史里修 bug 的提交做回放测试集；
   - release 包含 `mccode`，提供 Homebrew 和自更新。
