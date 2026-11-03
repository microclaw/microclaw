# MicroClaw Desktop：本地产品合并提案（Work + 终端 CLI `mcdesk`）

状态：**已批准，首版在 `feat/microclaw-code` 实现** · 日期：**2026-11-03**

本文在 [`microclaw-work-proposal-cn.md`](./microclaw-work-proposal-cn.md) 的基础上，把本地产品统一为
**MicroClaw Desktop**：同一个产品，两个入口——图形桌面端（现在的 MicroClaw Work）和终端 CLI `mcdesk`。

## 一、产品线

| 产物 | 给谁用 | 形态 |
|---|---|---|
| **MicroClaw SDK**（`microclaw-sdk`） | 集成方 | Rust 库 |
| **MicroClaw Server**（`microclaw`） | 常驻服务、渠道、计划任务、团队 | 守护进程 + Web 控制台 |
| **MicroClaw Desktop** | 在自己电脑上和 Agent 一起干活 | 桌面 app（GPUI）+ 终端 CLI `mcdesk` |

Server 和 Desktop 对称：一个跑在服务器上、常驻无人值守；一个跑在你自己的电脑上、前台交互。
`microclaw desktop …` 转发到 `mcdesk`。

```text
MicroClaw Desktop
├─ 桌面 app（apps/microclaw-work，GPUI）
└─ mcdesk（apps/microclaw-desktop-cli，终端 + -p/--json）
      共用：microclaw-work-app      会话快照状态机 + 会话库
            microclaw-work-runtime  项目识别、信任、验证、数据目录、模型配置
                     ↓
               microclaw-sdk → microclaw-engine
```

## 二、为什么合并

- 两个入口本来共用直连工作区、Checkpoint、审批语义和同一个 Agent Engine。
- `microclaw-work-app` 已有完整的会话状态机（计划、进度、审批、验证、完成、中断恢复）和会话库；
  终端版直接驱动它，不再另写一套。
- 竞品都是一个品牌多个入口：Codex 有 CLI / IDE / 桌面 / 云，CLI 能把会话转给桌面端；
  DeepSeek Harness 用 web / desktop / acp 等 profile 区分入口。
- 对外少一个产品，维护和说明都更简单。

**不合并的部分**：二进制保持两个。GPUI 很重，`mcdesk` 要能在 SSH、服务器、CI 中使用，不能依赖图形库。
CI 继续检查两者都只通过 `microclaw-sdk` 进入 Agent 执行、不依赖 Server 根包。

## 三、首版（本 PR）

### 1. `mcdesk`（`apps/microclaw-desktop-cli`）

- **入口**：`mcdesk`（交互式）、`mcdesk -p "任务"`（单次运行，`--json` 输出 JSONL 事件）、`microclaw desktop …`。
- **共享会话**：会话写入桌面端的会话库（`<Desktop 数据目录>/work-sessions`），运行时会话名就是快照的
  `session_id`，调用方渠道与桌面端相同（`work`）。终端里的会话会出现在桌面端列表里；
  `/desktop`、`mcdesk desktop` 把当前会话设为活动会话并打开桌面 app。
  `mcdesk sessions` 列出本项目的会话，`-c` 续接最近一个，`--session <id>` 续接指定会话。
- **权限模式**：
  - `plan`：只读工具（`ToolPolicy::ReadOnly`），给出计划；交互模式下确认后切到 `ask` 执行。
  - `ask`（默认）：文件编辑直接生效（有 Diff 和 Checkpoint），bash 每次审批。
  - `auto`：bash 自动放行，但破坏性命令（`rm -rf`、`git push`、`git reset --hard`、`sudo`、`curl | sh`、`publish` 等，
    以及项目配置的 `always_ask`）仍要审批。
- **审批**：审批挂起时会话快照处于"等待审批"，桌面端打开能看到审批卡片；`-p` 模式退出码 2，
  用 `mcdesk --session <id> -p 1` 续跑（不会把"1"记成用户消息）。
- **工作区工具集**：非 plan 模式使用 `ToolPolicy::WorkspaceWrite`，去掉发消息、定时任务、A2A、媒体生成、
  技能/记忆管理等对外工具（64 → 40 个）。
- **验证闭环**：识别 Rust / Node / Python / Go / Make 的检查命令，Agent 改了文件后自动运行 `auto` 检查，
  失败输出交回 Agent 修复（默认最多 2 轮），明确禁止删除或削弱测试。
- **模型配置**：`--config` → `MICROCLAW_WORK_CONFIG` → `MICROCLAW_CONFIG` → 桌面端设置里保存的配置 →
  `~/.microclaw/microclaw.config.yaml`。仓库里的 `microclaw.config.yaml` **不会**被加载。

### 2. 项目信任（安全边界）

`.microclaw/project.yaml` 在仓库里，可以设置 `mode`、`checks`、`instructions`、`always_ask`。
别人的仓库可以借此打开 auto 模式、让检查命令自动执行、往 system prompt 注入内容，所以：

- 第一次在交互模式打开项目时询问是否信任；决定记录在 Desktop 数据目录（`trusted-projects.json`），不写进仓库。
- **未信任**：忽略项目文件；识别出的检查命令只用于展示和手动 `check`，**不会自动运行**（检查会执行仓库自己的构建脚本）。
- `-p` 模式需要显式 `--trust`；`mcdesk trust [--revoke]`、交互里的 `/trust` 修改决定。

### 3. 共用层（`microclaw-work-runtime` / `microclaw-work-app`）

- 新增 `project`（项目识别、模式、项目配置）、`trust`、`verify`（运行检查、生成修复提示）模块。
- `work_data_root()` 移到 `microclaw-work-runtime`，桌面端和 CLI 用同一个数据目录。
- 修复会话状态机丢第一个事件的问题：SDK 运行时的事件序号从 0 开始，状态机原来只接受从 1 开始，
  每轮第一个事件（通常是 Checkpoint）被丢弃；现在新一轮接受 0 或 1，同一轮内的跳号仍会拒绝。

### 4. 引擎改进（所有产物受益）

| 改动 | 说明 |
|---|---|
| glob / grep 遵守 `.gitignore` | `tools/workspace_walk.rs`；`include_ignored` 可关闭；glob 无结果时回退字面匹配 |
| edit_file 多处编辑 | `edits[]` 全部成功才写入；`replace_all` |
| 防覆盖检查 | `tools/file_state.rs`：文件在上次读/写后被外部修改，edit/write 拒绝（`stale_read`） |
| bash 后台进程 | `run_in_background` + `bash_output` / `bash_kill`；按会话隔离，沙箱开启时拒绝 |
| 直连工作区的 bash 目录 | `Direct` 隔离下 bash 在项目根目录执行（原来是 `项目/tmp`） |
| `ToolPolicy::WorkspaceWrite` | 原来未使用的协议变体获得明确语义：工作区工具集 |
| ACP 事件 | `microclaw acp` 发送工具调用、挂在调用上的 Diff、计划更新；只有最终回复（如审批提示）时也显示 |

## 四、验收

- 单元测试：项目识别/配置/信任、检查与超时、渲染、破坏性命令匹配、CLI 参数、退出码、按项目过滤会话、
  零起始序号、引擎新工具、工作区工具集、ACP 事件映射。
- 端到端（本地模拟的 OpenAI 兼容服务）：未信任项目不自动验证；信任后"编辑 → 检查失败 → 交回修复 → 通过"；
  会话快照记录完整对话并成为活动会话；ask 模式审批挂起（快照为等待审批、退出码 2）→ `-p 1` 续跑；
  auto 模式下 `git push` 仍要审批；交互模式信任提示 → `/plan` → 确认 → 执行 → 验证 → `/sessions`。

## 五、后续

1. **打包改名**（单独 PR）：桌面 app 对外改名为 MicroClaw Desktop——app 名、cask（`microclaw-work` 保留别名）、
   bundle 标识、签名与公证流程；`MICROCLAW_WORK_*` 环境变量和数据目录保持兼容。内部 crate 名暂不改。
2. **桌面端接入共用能力**：模式切换、项目信任、自动验证在 GPUI 界面中可用。
3. **安全**：系统级沙箱（Landlock/seccomp、bwrap、Seatbelt）、按命令前缀的放行规则、auto 模式的模型复核。
4. **体验**：全屏 TUI（ratatui）、`/fork`、`/undo`、`/compact`、`/cost`、`apply_patch`、可交互的持久终端、
   启动时合并 AGENTS.md（受信任约束）、`/review`。
5. **接入**：`mcdesk acp`（含 `session/request_permission`）、`mcdesk mcp-server`、`/goal`。
6. **评测与发布**：Minimal 预设 + Terminal-Bench；release 包含 `mcdesk`、Homebrew、自更新。
