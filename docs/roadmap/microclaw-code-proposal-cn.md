# MicroClaw Code：第四个产物提案

状态：**已批准，首版在 `feat/microclaw-code` 实现** · 日期：**2026-11-03**

本文在 [`microclaw-work-proposal-cn.md`](./microclaw-work-proposal-cn.md) 的双产品方向之上，
增加第四个产物 **MicroClaw Code**：一个在本地仓库里运行的终端优先编码 Agent。

## 一、产品线

| 产物 | 给谁用 | 形态 | 关键差异 |
|---|---|---|---|
| **MicroClaw SDK**（`microclaw-sdk`） | 集成方 | Rust 库 | 把同一个 Agent Engine 嵌进别人的应用 |
| **MicroClaw Server**（`microclaw`） | 运维或团队，长期运行 | 守护进程 + Web 控制台 | 多渠道、计划任务、多用户、投递 |
| **MicroClaw Code**（`microclaw-code` / `microclaw code`） | 开发者，一个人一个仓库 | 终端 + ACP 接编辑器 | 在项目目录里交互式写代码，改完自动验证 |
| **MicroClaw Work**（桌面端） | 人在电脑前协作，不限于写代码 | GPUI 原生应用 | 可视化计划、审批、Diff 审阅 |

依赖关系：SDK ← Server / Code / Work。三个应用共用同一个 Agent Engine（工具、权限、
记忆、SQLite、Checkpoint），各自只负责界面和运行方式。

## 二、为什么是独立产物

- **用户和场景不同**：Server 面向无人值守和渠道投递；Code 面向坐在终端前、对一个仓库做修改的开发者。
- **SDK 的第一个纯外部用户**：Code 只通过 `microclaw-sdk` 的公开接口（`MicroClaw::builder`、
  `Agent`、`RunHandle`、`RuntimeEvent`）构建，SDK 哪里不好用会立刻暴露。
- **独立二进制**：不打包 Web UI 和渠道 SDK，启动更快；`microclaw code …` 像 `git` 子命令一样转发到 `microclaw-code`。

## 三、和 Work 的边界

两者都是本地运行、都把所选目录当成直连工作区（`WorkingDirIsolation::Direct`）。

- Code 面向开发者，入口是终端和 IDE（ACP）；Work 面向更广的知识工作，重点是可视化审阅。
- 两者共用引擎里的工作区语义：bash 在项目根目录执行、Checkpoint、`work`/`code` 渠道的高风险审批、
  子 Agent 只读限制。
- 后续阶段让同一项目的会话在两边互相打开（见第七节）。

## 四、首版能力（本 PR）

### 1. `microclaw-code` 应用（`apps/microclaw-code`）

- **入口**：`microclaw-code`（交互式）、`microclaw-code -p "任务"`（单次运行，`--json` 输出 JSONL 事件）、
  `microclaw code …`（主程序转发）。
- **工作区**：向上找到 `.git` 所在目录作为项目根；会话按项目区分，`-c` 续接上次会话，`--session` 指定名称。
- **权限模式**：
  - `plan`：只读工具（`ToolPolicy::ReadOnly`），给出计划；交互模式下确认后切到 `ask` 执行。
  - `ask`（默认）：文件编辑直接生效（有 Diff 和 Checkpoint 兜底），bash 每次审批（可选"本会话始终允许"）。
  - `auto`：bash 自动放行，但破坏性命令（`rm -rf`、`git push`、`git reset --hard`、`sudo`、`curl | sh`、`publish` 等，
    以及项目配置的 `always_ask`）仍然要审批。
- **编码工具集**：非 plan 模式使用 `ToolPolicy::WorkspaceWrite`，只提供读写工作区、运行命令、计划和 MCP 工具，
  去掉发消息、定时任务、A2A、媒体生成、技能/记忆管理等对外工具（64 → 40 个）。
- **验证闭环**：识别 Rust / Node / Python / Go / Make 项目的检查命令；Agent 改了文件后自动运行 `auto` 检查，
  失败输出交回 Agent 修复，最多 `max_fix_rounds` 轮（默认 2），并明确禁止删除或削弱测试。
- **项目配置** `.microclaw/code.yaml`：`mode`、`checks`、`verify`、`max_fix_rounds`、`instructions`、`always_ask`；
  `microclaw-code init` 生成模板。仓库里的 `microclaw.config.yaml` **不会**被自动加载，避免克隆来的项目篡改模型端点或工具策略。
- **交互**：流式输出、工具调用和彩色 Diff、运行中输入文字即插话（steer）、Ctrl-C 取消当前运行；
  `/mode`、`/plan`、`/check`、`/verify`、`/diff`、`/new`、`/status`、`/init`。
- **子命令**：`check [name…]`（运行检查）、`init`、`info`。

### 2. 引擎改进（所有产物受益）

| 改动 | 说明 |
|---|---|
| glob / grep 遵守 `.gitignore` | 新增 `tools/workspace_walk.rs`（`ignore` crate），也支持 `.ignore`；`include_ignored` 可关闭，glob 在无结果时回退到字面匹配 |
| edit_file 多处编辑 | `edits[]` 按顺序应用、全部成功才写入；`replace_all` 替换全部精确匹配 |
| 防覆盖检查 | `tools/file_state.rs` 记录读/写时的内容哈希，文件被外部改过后拒绝 edit/write（`stale_read`），提示先重新读 |
| bash 后台进程 | `run_in_background` + 新工具 `bash_output`（增量读取、过滤）/ `bash_kill`；按会话隔离，沙箱开启时拒绝 |
| 直连工作区的 bash 目录 | `Direct` 隔离下 bash 在项目根目录执行（原来是 `项目/tmp`），Work 同样受益 |
| `code` 渠道审批 | 高风险工具审批和子 Agent 只读限制覆盖 `code` 渠道 |
| `ToolPolicy::WorkspaceWrite` | 原来未使用的协议变体获得明确语义：工作区工具集 |
| ACP 事件 | `microclaw acp` 发送工具调用（类型/状态/位置）、挂在对应调用上的 Diff、计划更新；只有最终回复（如审批提示）时也会显示 |

## 五、验收

- 单元测试覆盖项目识别、配置、检查、渲染、会话、破坏性命令匹配、引擎新工具和 ACP 事件映射。
- 端到端（本地模拟的 OpenAI 兼容服务，按脚本返回工具调用）验证：
  读文件 → 编辑 → 自动检查失败 → 失败交回 Agent → 修复 → 检查通过；
  ask 模式审批挂起（退出码 2）→ `-p 1` 批准续跑；auto 模式自动放行；auto 模式下 `git push` 仍要审批；
  交互模式 plan → 确认 → 执行 → 验证；plan 模式只暴露只读工具；工作区工具集拦截 `send_message`。

## 六、不做

- 不做完整 IDE 或自己的编辑器（交给 ACP 客户端和 Work）。
- 不新写 Agent 循环。
- 没有评测数据前不做 LSP、仓库符号索引。
- 不让 Agent 修改自己的工具代码。

## 七、后续阶段

1. **ACP 迁移**：ACP 主实现迁到 `microclaw-code acp`（基于 SDK），`microclaw acp` 保留为兼容别名；
   接上 `session/request_permission`，让编辑器内直接审批。
2. **Git 与并行**：`/commit`（模型起草、人确认）、子 Agent 在 `git worktree` 中并行。
3. **与 Work 互通**：同一项目的会话在 Code 和 Work 之间互相打开。
4. **评测**：在 `microclaw eval` 中加入编码任务集（从本仓库历史挑修 bug 的提交，回退后让 Agent 重修，用原测试判定），
   以及部分 Terminal-Bench 题目；用通过率、token、迭代次数决定是否做 LSP。
5. **自进化接入**：把验证结果作为确定性证据写入 long-horizon learning，技能按仓库限定范围；
   "改测试骗通过"单独记为一类失败。
6. **发布**：release 归档同时包含 `microclaw` 和 `microclaw-code`；Homebrew formula；去掉 Preview 标签的条件是评测达标且本仓库日常开发在用。
