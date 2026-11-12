# MicroClaw Code 桌面版（macOS，GPUI）计划

状态：**M1 预览已实现（未签名；真实模型往返未验证；待合并）；M2 未开始**
更新：**2026-11-12**
基线：**v0.30.0**（原计划基线 v0.26.0）

> 进度见第 11 节“交付记录”。M1 作为 0.31 的并行轨道推进，不阻塞 0.31 主线（N5/N6/N7）。

MicroClaw Code 目前只有命令行形态，包括全屏 TUI、`-p` / `--json`、`mccode acp` 和 `mccode mcp-server`。
这份计划用 Rust + GPUI 给它加一个 macOS 桌面版。

- 桌面版和命令行版是**同一个产品的两个前端**：共用 `~/.mccode`，也共用会话、设置、信任和规则。
- 桌面版和 MicroClaw Server 仍然完全分开。

---

## 0. 结论

1. **桌面版不重写 Agent 逻辑。**
   - `microclaw-code-core` 的 `CodeSession::turn` 已经是一套和界面无关的接口。
   - 前端发出 `Control`：引导、取消或审批。
   - driver 发回 `Update`：运行事件、审批请求、检查、修复回合和用量。
   - TUI、`-p`、ACP 和 MCP 都是它上面的薄前端，桌面版是第五个。
2. **桌面版在同一个进程里直接调用 code-core，不走 IPC 协议。**
   - 界面是 Rust，所以没有语言边界，`Update` 和 `Control` 两个 channel 直接接上 GPUI 就行。
   - 引擎跑在 App 自己持有的一个长期 Tokio 运行时上，界面线程只接收事件，Agent 卡住也不会卡界面。
   - 桌面版只依赖 `microclaw-code-core` 和 `microclaw-sdk`，继续遵守“只通过 SDK 访问引擎”的 CI 约束。
3. **GPUI 现在可以只从 crates.io 依赖，这是和旧 Work 最大的不同。**
   - `gpui-component` 0.9.0 依赖 `gpui-pre =0.3.11`。`gpui-pre` 是 gpui-component 作者 huacnlee 发布的 Zed gpui 快照，
     目前对应 zed@f816e1f，2026-11-02 更新，下载 41 万次。
   - 不再有 git 依赖，Cargo.lock 也稳定。
   - 官方 crates.io 上的 `gpui` 停在 0.2.2（2025-10），不用它。
4. **吸取旧 Work 的教训。**
   - Work 有自己的一套 runtime，绕开了 SDK。
   - 它的 `main.rs` 有 4700 多行。
   - 它每做一次操作就新建一个 Tokio 运行时。
   - 这次桌面版只是 Code 的前端，状态管理和视图分开写，整个 App 只有一个运行时。详见第 2 节。
5. **先做一步重构（M0）。** 会话装配现在散在 `main.rs`、`acp.rs`、`mcp_server.rs` 和 `eval.rs` 四处，
   先收进 core，新建 `code-core::launch`。同时把环境变量隔离、改动审阅和首次设置的逻辑也移到 core，并加上会话锁。
   这一步对 CLI 本身也有好处，而且不碰界面。
6. **和 Zed 组合，但不 fork。** 详见 3.1 节。
   - 把 `mccode acp` 提交到 ACP Registry，让 Zed 用户直接在 Agent 面板里用 MC Code。这条成本低，放进 0.27。
   - Fork Zed、或者链接 Zed 的 editor 等 crate 都不做：那些 crate 是 GPL-3.0，和 MIT 冲突，维护成本也太高。
7. **版本节奏：**
   - 0.27：M0，重构，同时做一个 GPUI 技术验证，并完成 Zed 接入；
   - 0.28：M1，可用的预览版 DMG；
   - 0.29：M2，正式版；
   - 之后：M3，差异化功能，比如并行 worktree 任务看板。

---

## 1. 目标与非目标

**目标（v1）**

- 支持 macOS 13 及以上，arm64 和 x86_64 各出一个包。签名、公证后在 App Store 之外分发。
- 打开一个项目目录就能开始对话，下面这些行为和 TUI 一致：
  - plan / ask / auto 三种模式，可以切换模型；
  - 审批、检查与修复回合；
  - 撤回（undo）和回退（rewind）；
  - 会话列表、继续会话、分叉会话（fork）。
- 和命令行版互通：在 TUI 里开的会话可以在 App 里继续，反过来也一样。设置、信任和 allow 规则只有一份。
- 下面几处体验会比 TUI 好：
  - 改动审阅：看 diff，可以按块接受或撤回；
  - 系统通知：需要审批或一轮结束时提醒；
  - 拖入或粘贴图片；
  - 首次启动引导。

**非目标（v1 不做）**

- Windows 和 Linux。GPUI 本身支持这两个平台，以后只需要补打包。
- 内置代码编辑器。Code 不是 IDE，只提供“在编辑器中打开”。
- 内嵌终端（PTY）、远程 Server 配对界面、多 Agent 并行看板，都放到 M3。
- 不和 Server 共享任何东西：不读 `~/.microclaw`，也不读 `MICROCLAW_*` 环境变量。

---

## 2. 现状（读代码得出）

| 部分 | 现状 | 对桌面版的意义 |
|---|---|---|
| driver | `crates/microclaw-code-core/src/driver.rs`：`CodeSession::turn(prompt, &UnboundedSender<Update>, &mut UnboundedReceiver<Control>)`；另有 `history`、`undo`、`rewind`、`checkpoints`、`fork`、`compact`、`review`、`usage`、`context_usage`、`set_model`、`export_markdown` 等 | 现成的界面接口。Tokio 的 mpsc channel 不依赖 Tokio 运行时，可以直接在 GPUI 的 executor 里 `recv().await` |
| 会话装配 | 引擎构建、`CodeToolGate`、角色模型、沙箱、allow 规则、LSP 和 hooks 的装配写在 `apps/microclaw-code/src/main.rs` 里（`gate_parts`、`project_gate`、`role_setup`、`settings_sandbox`、`sandbox_choice` 等函数）。`acp.rs`、`mcp_server.rs`、`eval.rs` 各自调用 `CodeSession::new`，各写一遍装配 | 已经有四份装配代码了，桌面版不能再加第五份 |
| 环境隔离 | `main.rs` 的 `engine_env_overrides` / `isolate_engine_env` 在 Tokio 启动前清掉或替换 Server 的 `MICROCLAW_*` 变量 | 桌面版也要做这一步，所以要移到 core |
| 改动审阅 | `tui/review.rs` 里的 `parse_diff`、`load_changes`、`revert_hunk` 本身和界面无关 | 移到 core，两个前端共用 |
| 首次设置 | `apps/microclaw-code/src/setup.rs`（145 行），提供方预设在 core 的 `presets.rs` | 移到 core，供桌面版的引导页调用 |
| 会话并发 | `sessions.rs` 没有锁 | TUI 和 App 同时驱动同一个会话会互相覆盖，需要加锁 |

**旧 Work（#486，在 #527 删除，约 1.26 万行）的教训**

| 旧 Work 的做法 | 这次的做法 |
|---|---|
| 另一个产品，自带 `microclaw-work-runtime`，直接依赖 `microclaw` 主 crate | 只是 Code 的前端，只依赖 code-core 和 SDK |
| `apps/microclaw-work/src/main.rs` 有 4700 多行，视图、状态和副作用混在一起 | 拆成三层：状态（纯 Rust，可以单元测试）、视图、服务（连接 Tokio）。单个文件控制在大约 800 行以内 |
| 每次操作都 `tokio::runtime::Runtime::new()` 再 `block_on` | 只用一个长期运行时，在 App 启动时创建 |
| gpui、gpui_platform、gpui-component 都用 git 依赖 | 只用 crates.io 依赖，精确锁定版本 |
| 签名和公证流程（`build_work_macos_dmg.sh`、`verify_work_macos_release.sh`）已经跑通 | 从 git 历史（`89c5b4d8^`）里找回来，改成 Code 用的版本 |

---

## 3. 技术栈

| 层 | 选择 | 说明 |
|---|---|---|
| UI 框架 | `gpui-component` 0.9（或总包 `gpui-kit` 0.9），带出 `gpui-pre =0.3.11` | gpui-component 提供 Sidebar、可拖动分栏、虚拟列表、多行输入框（带 tree-sitter 高亮）、Markdown / TextView、Dialog、Notification、Popover / Menu、Kbd、深浅色主题。具体有哪些组件、好不好用，在 M0 的技术验证里确认 |
| 代码高亮 | gpui-component 的 `tree-sitter-*` feature（rust、ts、python、go、diff 等），按需开启 | 不再引入 syntect |
| diff 视图 | 自己实现：用 code-core 的 `parse_diff` 解析，在虚拟列表里逐行渲染，行号加增删底色，每块带“撤回”按钮 | gpui-component 很可能没有现成的 diff 组件，要在技术验证里确认 |
| 异步 | 界面用 GPUI 的 executor（`cx.spawn`）；引擎用一个 Tokio 多线程运行时（2–4 个 worker） | 两边只靠 channel 交流 |
| 打包 | 沿用旧 Work 的脚本思路：生成 `.app` → `codesign` → `notarytool` → staple → DMG | Metal shader 在构建时编译，需要完整的 Xcode；GitHub 的 `macos-15` runner 上有 |

**版本策略**：`gpui-pre` 用 `=` 锁定版本，跟着 gpui-component 的大版本一起手动升级。每次升级单独提一个 PR，并跑界面测试。
gpui 的 API 变化快，这是选 GPUI 要接受的成本。

### 3.1 自己用 GPUI 写，还是和 Zed 组合

“用 Zed”有三种做法，加上自己写，共四种：

| | A. 自研 GPUI App（本计划） | B. 接入 Zed：`mccode acp` 进 ACP Registry | C. Fork Zed 做“MC Code 编辑器” | D. 自研 App 里引用 Zed 的 editor、markdown、multi_buffer 等 crate |
|---|---|---|---|---|
| 做法 | 自己写独立 App，同进程调 code-core | Zed（v1.5 起）在 Agent 面板里托管外部 Agent，通过 ACP Registry 安装。我们提交一个 registry 条目，再补齐 ACP 的缺口 | 拿 Zed 全部源码改品牌、加 Code 功能 | 自研 App，借用 Zed 的编辑器和 diff 组件 |
| 工作量 | 大：M0 + M1 + M2，三个版本 | 小：`mccode acp` 已经支持会话、继续会话、模式、权限请求、计划、diff 和图片 | 极大：Zed 有 252 个 crate，而且要一直跟上游合并 | 大，还要处理 Zed 内部 API 和 git 依赖 |
| 许可证 | gpui 是 Apache-2.0，没问题 | 进程隔离，协议通信，没问题 | **Zed 的 editor、agent_ui、acp_thread、markdown、multi_buffer 都是 GPL-3.0-or-later**，衍生产品必须 GPL，和 MicroClaw 的 MIT 冲突 | 同 C，链接 GPL crate 会让整个 App 变成 GPL |
| 体验 | 完全由我们设计，Code 独有的检查与修复回合、每轮回执、按块撤回、并行 worktree 任务、手机审批都能做成一等功能 | Zed 有编辑器、多文件 diff 审阅、终端、并行线程侧栏，**很长时间内都比我们自己做的好**；但 Code 独有的概念只能借用通用的 ACP 元素（消息、计划、工具调用）来表达 | 最好，但产品就变成了 IDE，和“Code 不做 IDE”相冲突 | 编辑器部分好，其余同 A |
| 覆盖用户 | 所有 macOS 用户，不要求用编辑器 | 只覆盖 Zed 用户；同时 JetBrains、Neovim 等其他 ACP 客户端也能用到 | 需要用户换编辑器 | 同 A |
| 掌控度和品牌 | 完全掌控，有独立的产品形态 | 体验受 Zed 和 ACP 演进的影响，品牌只是 Agent 列表里的一项 | 完全掌控，但维护不动 | 完全掌控 |
| 维护 | 只有一个 gpui 依赖，升级可控 | 只维护 ACP 适配层 | 长期跟进上游，成本最高 | 跟进 Zed 内部 API，成本高 |

**结论：A 和 B 都做，C 和 D 不做。**

- **B 先做，放进 0.27，和 M0 一起。** 工作量小，马上就有“图形界面里的 MC Code”，可以先验证需求。补齐的内容：
  - 斜杠命令（`available_commands`）；
  - 模型选择（session models）；
  - 把检查和修复回合映射成计划条目或消息；
  - 写文件时，如果客户端支持就走 `fs/write_text_file`，让 Zed 能跟踪并审阅改动；
  - 向 `agentclientprotocol/registry` 提交条目。

  这些改进让所有 ACP 客户端都受益。
- **A 按计划推进（M1、M2）。** 定位是“不依赖编辑器的独立 Agent 工作台”：重点放在审批、改动审阅、检查回执和并行任务这些 Zed 的通用 Agent 面板表达不了的东西，不做编辑器。
- **不 fork Zed，也不链接 Zed 的 GPL crate。** 只用 Apache-2.0 的 gpui，通过 gpui-component 引入。
  如果以后需要编辑器级别的组件，就用 gpui-component 自带的 Input / 代码编辑器，或者自己实现。

---

## 4. 架构

### 4.1 进程内结构

```
MicroClaw Code.app  (一个进程)
├─ main：同步阶段完成环境隔离（code-core::home::isolate_engine_env）、读取登录 shell 的 PATH
│        → 创建 Tokio 运行时 → 启动 GPUI Application
├─ 界面线程（GPUI）
│    views/   窗口、侧栏、对话、审批卡片、diff、设置……（只读状态，只发命令）
│    state/   AppState、ProjectState、SessionState：纯 Rust，按 Update 更新（reducer），可以单元测试
├─ service/  （跑在 Tokio 上）
│    ProjectService：每个项目一个，持有 code-core::launch 构建的引擎和 CodeSession
│      命令：UiCommand → Control / session 方法
│      事件：Update → UiEvent → 界面线程（cx.spawn 循环接收，更新 state，cx.notify）
└─ microclaw-code-core → microclaw-sdk → Agent Engine
```

- **数据**：全部放在 `~/.mccode`（`MCCODE_HOME`），和命令行版共用。App 自己的界面状态（窗口位置、打开过的项目）放在 `~/.mccode/desktop/`。
  不用 `~/Library/Application Support`，这样“Code 的状态都在 `~/.mccode`”这条规则继续成立。
- **环境变量（重要）**：
  - 从 Finder 启动的 App 只拿到很短的 `PATH`，找不到 `cargo`、`npm`、`brew`，检查和 LSP 都会失败。
  - 所以在 `main` 的同步阶段，用 `$SHELL -ilc 'env -0'` 读一次登录 shell 的环境（设超时，结果缓存）。
  - 再照常执行 `isolate_engine_env`，清掉或替换 Server 的 `MICROCLAW_*` 变量。
  - 和 mccode 一样，这些都要在任何线程启动之前做完：edition 2024 下 `set_var` 是 unsafe。
- **沙箱**：App 不开 App Sandbox，因为它要运行任意开发工具，所以不能上架 App Store。shell 命令照常走 Seatbelt 本地沙箱，和 CLI 一样。
- **后台进程**：
  - 窗口关闭或 App 退出时，丢弃对应的 `ProjectService`。
  - 注册表持有的 `ProcessRegistry` 在 drop 时会结束 `run_in_background` 起的进程。
  - 这条要专门写测试覆盖。
- **会话锁**：
  - 打开会话时在 `~/.mccode/sessions/<id>.lock` 写入 pid 和时间。
  - 另一个前端（TUI 或另一个窗口）再打开同一个会话时，可以选择只读查看或“接管”。
  - 如果锁里的 pid 已经不存在，视为失效锁，自动清理。

### 4.2 M0：code-core 需要新增和移动的部分

| 项 | 内容 |
|---|---|
| `code-core::launch` | `Launch::for_project(cwd, options)` 返回构建好的引擎、gate、角色模型、沙箱信息和 allow 规则，以及一个配好的 `CodeSession`。TUI、`-p`、ACP、MCP 和 eval 都改用它，删掉四份重复代码 |
| `home::isolate_engine_env` | 从 `main.rs` 移过来，mccode 和桌面版共用 |
| `review` | 把 `parse_diff`、`load_changes`、`revert_hunk` 从 `tui/review.rs` 移过来，TUI 只留下渲染 |
| `setup` | 把提供方选择、测试连接和写入 `settings.yaml` 的逻辑从 `apps/.../setup.rs` 移过来 |
| `sessions` 锁 | 见 4.1 |

### 4.3 工程目录

```
apps/microclaw-code-desktop/
  Cargo.toml        # 独立 workspace，自己的 Cargo.lock（同 tests/sdk-consumer）；path 依赖 code-core 和 sdk
  src/main.rs       # 只做启动
  src/state/        # 纯状态 + reducer
  src/service/      # Tokio 服务层
  src/views/        # GPUI 视图，一个文件一个组件
  resources/        # Info.plist、图标、entitlements
  scripts/          # bundle / sign / notarize / dmg（从 Work 的脚本改写）
```

**为什么不放进根 workspace**：gpui 依赖树很大，而且只在 macOS 上构建。放进根 workspace 会拖慢所有人的
`cargo build` / `cargo test --workspace`，Linux CI 还要装 X11/Wayland 依赖。单独一个 workspace，单独一个 macOS CI job。

**CI 检查**：
- 桌面版不能直接依赖 `microclaw-engine`，沿用现有检查；
- 版本号对齐（`check_version_alignment.sh`）；
- macOS job 跑 `cargo clippy`、`cargo test` 和一次 bundle 冒烟。

---

## 5. 界面（v1）

```
┌───────────┬──────────────────────────────────────┬──────────────────┐
│ 项目       │  对话                                 │ 侧栏（可收起）     │
│  ▸ microclaw│  用户消息 / Agent 回复（流式 Markdown）  │  [改动] [计划]    │
│    会话 A  │  工具调用（可折叠，带 diff）            │  [检查] [用量]    │
│    会话 B  │  ┌ 审批卡片：允许一次 / 总是允许 / 拒绝 ┐ │                  │
│  ▸ other   │  每轮回执：改了 3 个文件 · 检查通过 ·   │  文件 diff，按块  │
│            │  沙箱开 · 用了 12k tokens             │  接受 / 撤回       │
│ ＋ 打开项目 ├──────────────────────────────────────┤                  │
│            │ [plan|ask|auto] [模型▾]  输入框 @文件  │                  │
│            │  拖入图片 · ⏎发送 · ⌘⏎引导 · ⌘.停止      │                  │
└───────────┴──────────────────────────────────────┴──────────────────┘
```

- **首次启动**：
  - 没有模型配置时进入引导：选提供方、填 key、测试连接，然后写入 `~/.mccode/settings.yaml`。调用的是 `code-core::setup`。
  - 打开第一个项目时询问是否信任。
- **对话**：
  - 用虚拟列表渲染，长会话不会卡。
  - 流式 Markdown 按块提交：已经完成的块缓存起来，只重排最后一块。TUI 的 `transcript.rs` 已经这样做。
  - 工具调用默认折叠。
- **审批**：
  - 审批卡片直接嵌在对话里。
  - 窗口不在前台时发系统通知。
  - Dock 角标显示有几项在等审批。
- **改动审阅**：
  - 侧栏按文件列出本轮的改动。
  - 可以撤回某一块、撤回整轮，或者回退到某个检查点。
  - 这比 TUI 的 `/review` 直观得多，是桌面版最主要的价值之一。
- **快捷键和菜单**：

  | 快捷键 | 作用 |
  |---|---|
  | ⌘O | 打开项目 |
  | ⌘N | 新会话 |
  | ⌘K | 命令面板（对应 TUI 的斜杠命令） |
  | ⌘. | 停止 |
  | ⌘, | 设置 |

  另外有“在编辑器中打开”，用 `$EDITOR` 或系统默认程序。
- **设置**：
  - 按用户、项目、本地三层编辑，并显示合并后的结果；
  - 规则（allow / ask / deny）可以编辑；
  - hooks 在 v1 只读。
- **主题**：
  - 跟随系统的深浅色；
  - 颜色取自 TUI 的主题 token（`ui/theme`），两端风格一致。

---

## 6. 阶段与版本

| 阶段 | 版本 | 内容 | 完成标准 |
|---|---|---|---|
| **Z 接入 Zed** | 0.27 | 按 3.1 节补齐 ACP（斜杠命令、模型选择、检查与修复回合、通过客户端写文件），提交 ACP Registry 条目，补一篇 Zed 使用文档 | 在 Zed 里从 Registry 安装 MC Code，完成一次“改代码 → 检查 → 修复”，并在 Zed 里审阅改动 |
| **M0 地基 + 技术验证** | 0.27 | 完成 4.2 节全部内容。同时在独立分支做 GPUI 技术验证：一个窗口，带输入框、流式 Markdown、虚拟列表、diff 渲染，对接真实的 `CodeSession` 跑通一轮对话 | 现有 1894 个测试全部通过；TUI、`-p`、ACP、MCP 和 eval 都改走 `launch`；技术验证给出组件清单、缺口和性能数据（长对话滚动帧率、冷启动时间、包体大小），据此确认 M1 范围 |
| **M1 预览** | 0.28 | 打开项目、信任、首次引导、会话列表、对话（流式回复、工具调用、审批卡片）、模式和模型切换、停止和引导、登录 shell 环境、会话锁。出签名、公证后的 arm64 / x86_64 DMG，作为 Release 附件 | 用 DeepSeek 真实模型在本仓库完成一次“改代码 → 检查 → 修复”；App 里开的会话能在 TUI 里继续，反过来也可以 |
| **M2 正式** | 0.29 | 改动侧栏（按块撤回、undo、rewind）、检查和用量面板、设置界面、系统通知和 Dock 角标、命令面板、自动更新、Homebrew cask | 每个 TUI 功能都在对照表里有对应的入口；能从上一个版本自动更新到新版本 |
| **M3 差异化** | 0.30+ | 多个 Agent 在各自的 worktree 里并行跑任务，用看板展示（基于 `--worktree`）；审批推送到手机（复用 `remote_notify`）；PTY 终端面板；远程 Server 配对；多窗口 | 另出一份计划 |

---

## 7. 发布与分发

- **版本号**：和 workspace 保持一致。`check_version_alignment.sh` 要加上 `apps/microclaw-code-desktop/Cargo.toml` 和 `Info.plist`。
- **构建**：在 Release Assets 里加一个 `macos-15` job，产物是 `MicroClaw-Code-X.Y.Z-{arm64,x86_64}.dmg`，并写入 `SHA256SUMS.txt`。
- **签名**：沿用原 Work 的 Developer ID 身份。M1 先在本地构建、签名、公证再上传，和以前的 Work DMG 一样；M2 改成在 CI 里做，证书和 notarytool 凭据存成 Actions secrets。
- **更新**：倾向 Sparkle（appcast 放在 GitHub Release），需要在 M2 验证 Rust 程序能不能干净地接入 Sparkle 框架。备选是自己实现：检查 Release、下载 DMG、校验签名后替换。
- **Homebrew**：tap 加一个 cask `microclaw-code`，由 `release_finalize.sh` 生成。它和 formula `mccode` 互不依赖，用户可以只装其中一个，也可以都装，因为数据都在 `~/.mccode`。
- **App 名和 bundle id**：`MicroClaw Code.app`，`ai.microclaw.code`。

---

## 8. 测试

- **状态层**：用一串 `Update` 驱动 reducer，断言状态的变化。这部分不依赖 GPUI，测得最快。
- **视图层**：用 GPUI 的 `TestAppContext`（`#[gpui::test]`，gpui-component 的 `test-support` feature）做无头测试，覆盖输入、审批卡片和 diff 的撤回按钮。
- **服务层**：用真实的 `ProjectService`，配一个本地模拟的 OpenAI 兼容服务，覆盖这些流程：
  - 对话；
  - 审批；
  - 取消；
  - 检查失败后修复；
  - 撤回；
  - 继续会话；
  - 锁冲突；
  - 退出时结束后台进程。
- **打包冒烟**：
  1. 打包后启动 `.app`；
  2. 用 `MCCODE_HOME` 指向一个临时目录；
  3. 加一个 `--smoke` 参数，让 App 打开一个示例项目、跑完一轮模拟对话后退出。
- **真实模型**：每个阶段结束时用 DeepSeek 在本仓库跑一遍验收任务，写进交付证据。

---

## 9. 风险

| 风险 | 应对 |
|---|---|
| gpui 的 API 变化快，`gpui-pre` 是个人维护的快照 | 精确锁定版本，升级单独提 PR；视图层集中在 `views/`，状态和服务层不依赖 GPUI；如果快照停止更新，退回 git 依赖指向某个 Zed commit |
| 组件缺口（diff、长文本选择复制、输入法） | M0 的技术验证专门检查这些，特别是中文输入法和长 Markdown 的选择复制，结论决定 M1 的范围 |
| 两个界面的维护成本翻倍 | 逻辑都放在 code-core，界面只负责展示；新功能先进 core，再分别加界面入口；M2 起维护一张 TUI 与桌面版的功能对照表 |
| 重蹈 Work 的覆辙 | 见第 2 节的对照表；桌面版没有自己的 Agent 逻辑，最坏情况下删掉它也不影响 CLI |
| 从 Finder 启动时 PATH 不全 | 按 4.1 读取登录 shell 的环境；在 `doctor` 面板里显示实际生效的 PATH |
| 构建慢、包体大 | 独立 workspace，单独的 CI job；release profile 打开 LTO 和 strip；在技术验证里测一下包体大小 |
| 同一会话被两端同时驱动 | 会话锁（4.1） |

---

## 10. 待确认

1. **名称与分发**：App 名用 `MicroClaw Code.app`，cask 名用 `microclaw-code`，和 formula `mccode` 互相独立。这样可以吗？
2. **节奏**：M0 放进 0.27 单独发版，技术验证不进 Release。这样可以吗？
3. **签名**：M1 先在本地签名和公证，M2 再搬到 CI。这样可以吗？

---

## 11. 交付记录

### 11.1 M0 实际情况（2026-11-12 核对）

| 项 | 状态 |
|---|---|
| `code-core::launch` | 已完成（0.27–0.30 期间）。ACP、MCP 走 `launch::project_engine`；TUI / `-p` 仍在 `main.rs` 里自己装配引擎，但已经复用 `launch` 的 `tool_gate`、`role_setup`、`ModelSource` |
| GPUI 技术验证分支 / crate | 不存在：仓库里没有 spike 分支，也没有桌面 crate。M1 直接在新 crate 里做，技术验证的结论并入下表 |
| `isolate_engine_env` 移到 core | 随 M1 完成：`code-core::env`（`engine_env_overrides` / `isolate_engine_env`），mccode 改用它 |
| 会话锁 | 随 M1 完成：`code-core::session_lock` |
| 首次设置移到 core | 随 M1 完成：`code-core::setup`（`providers` / `resolve` / `write`），`mccode setup` 只剩交互提问 |
| 沙箱选择移到 core | 随 M1 完成：`launch::sandbox_choice` / `settings_sandbox` / `sandbox_info`，mccode 和桌面版共用 |
| `review`（`parse_diff` / `revert_hunk`）移到 core | 未做，留给 M2 的改动侧栏 |

### 11.2 M1 交付内容

新 crate `apps/microclaw-code-desktop/`（二进制 `microclaw-code-desktop`，bundle `MicroClaw Code.app` / `ai.microclaw.code`）：

- **独立 workspace，独立工具链。** 有自己的 `Cargo.lock` 和 `rust-toolchain.toml`（1.98.1）：
  `gpui-pre` 0.3.11 / 0.3.12 用到了 `Option::map_or_default`，需要 Rust 1.97+，根 workspace 仍是 1.96.1。
  根 workspace 的 `cargo build` / `cargo test` 和 Linux、Windows CI 都不编译它。
- **依赖**：`gpui-kit =0.9.1`（带出 `gpui-pre =0.3.12`、`gpui-component 0.9.1`），全部来自 crates.io；
  引擎只经 `microclaw-sdk` 和 `microclaw-code-core`。`check_runtime_boundaries.sh` 用 `cargo metadata --no-deps`
  检查这一点（不解析 GPUI，所以在 Linux 上也能跑），`check_version_alignment.sh` 加上了它的 `Cargo.toml` 和 `Info.plist`。
- **分层**（第 2 节的要求，单文件都在 700 行以内）：
  - `state.rs`：纯 reducer，`Update` → 对话条目（流式文本合并、工具调用状态、diff、审批卡、检查、回执），有单元测试；
  - `service.rs`：每个项目一个 Tokio 服务，`launch::project_engine` 建引擎，`CodeSession::turn` 跑回合，
    `Command` / `Event` 两个 channel 和界面通信；
  - `views/`：`workspace`（侧栏：项目、会话）、`project`（标题栏、横幅、对话、输入框）、`transcript`（逐条渲染）、`onboarding`；
  - `headless.rs`：`--smoke <dir> <prompt>`，不开窗口跑一轮，用于打包冒烟和脚本验证。
- **功能**（对照第 6 节 M1 范围）：

  | M1 项 | 状态 |
  |---|---|
  | 打开项目 | ⌘O / 侧栏按钮选目录；最近项目记在 `~/.mccode/desktop/state.json`；命令行参数可直接给目录 |
  | 信任 | 未信任项目显示横幅，“Trust” 写入 `trusted-projects.json`（与 `mccode trust` 同一文件）并重建引擎 |
  | 首次引导 | 没有模型配置时显示引导页（提供方、模型、key、base URL），经 `code-core::setup` 写 `~/.mccode/config.yaml` 后自动启动 |
  | 会话列表 | 侧栏列出当前项目的会话（`sessions.json`，与 TUI 同一份）；⌘N 新会话；点击继续会话并显示历史 |
  | 对话 | 流式 Markdown（`TextView`）、工具调用（状态、耗时、命令输出尾部）、文件 diff、检查与修复回合、每轮回执；虚拟列表（`MessageScroller`，跟随末尾） |
  | 审批卡片 | `interactive: true`，与 TUI 同一条 SDK 路径：driver 发 `ApprovalRequested`，按钮发 `Control::Approve`（含“在本项目总是允许”选项）；回合中途回答，回合继续 |
  | 模式切换 | 标题栏 plan / ask / auto（⇧⇥ 循环），遵守 `disabled_modes`；回合中切换从下一回合生效 |
  | 模型切换 | 可搜索的下拉框：settings 里 profile 的模型 + 当前提供方的已知模型，走 `CodeSession::set_model` |
  | 停止和引导 | ⌘. / Stop 发 `Control::Cancel`；回合进行中 ⌘⏎ / Guide 发 `Control::Steer` |
  | 登录 shell 环境 | 启动时（任何线程之前）跑一次 `$SHELL -ilc`，合并 `PATH`、补齐缺失变量（`code-core::env::import_login_shell_env`，5 秒超时），然后照常 `isolate_engine_env` |
  | 会话锁 | `~/.mccode/sessions/<id>.lock`（pid、前端、时间、token）。TUI、`-p` 和 App 都加锁；被占用时 App 显示只读横幅和“Take over”，mccode 报错并提示 `--take-over`；进程不在了的锁自动清理；被接管的一方在下一回合前发现并停下 |
  | 退出 | ⌘Q 时等服务停下：取消进行中的回合、跑 `session_end` hook、释放锁，丢弃引擎（后台进程随 `ProcessRegistry` 结束） |
  | 签名、公证后的 DMG | **未做**（见 11.4）。目前 `scripts/bundle.sh` 生成未签名（ad-hoc）的 `.app` |

- **与 TUI 互通**：两边用同一个 `SessionIndex`、同一个引擎数据目录（`home::data_dir()`）和同样的会话 id，
  App 里开的会话可以 `mccode --session <id>` 继续，TUI 的会话在 App 侧栏里点开继续。

### 11.3 验证

- 桌面 crate：`cargo clippy --all-targets -- -D warnings`、`cargo test`（9 个测试：reducer 5、回执 1、最近项目 1、
  所有对话条目在 GPUI 测试平台上渲染 1、服务层端到端 1）、`cargo fmt --check`。CI 新增 `desktop-macos` job（macos-15）跑这些，
  再打包一次 debug `.app`，并在空 `MCCODE_HOME` 下跑 `--smoke`（期望“需要设置”，退出码 2）。
- **服务层端到端测试（模拟提供方）**：`service_tests.rs` 起一个本地 OpenAI 兼容服务（SSE），在临时 `MCCODE_HOME` 里写一个
  settings profile 指向它，引擎照常由 `launch::project_engine` 构建，回合照常走 `CodeSession::turn`。按顺序覆盖：
  1. 普通回合，流式回复进入对话；
  2. 模型调用 `bash`，回合中出现审批卡，回答“允许一次”后命令在沙箱里执行、输出回到对话，模型继续回复；
  3. 模型迟迟不回复时“停止”结束回合（回执含 stopped）；
  4. 关闭服务后会话锁释放；
  5. 另一个前端用同一个会话 id 打开（相当于 `mccode --session <id>`），历史、会话索引（标题、轮数）都在；
  6. 此时 TUI 加锁被拒；TUI 接管后 App 发送会被拦下（`SessionLocked`），TUI 放手后 App 可以继续。
- code-core 新增测试：会话锁 4 个（占用、接管、失效锁、id 不能逃出目录）、env 3 个、setup 2 个。
- 实机：在本仓库启动 `.app`（从 `open` 启动，验证登录 shell 环境）、加锁、⌘Q 后锁被释放；
  App 持有会话时 `mccode --session <id> -p` 被拒绝，加 `--take-over` 后可以继续。
- 模型出错的路径：用当前配置（anthropic，key 无效）启动，引擎正常就绪，回合以 `authentication_error: invalid x-api-key`
  结束，错误进入对话、回执为 failed，`--smoke` 退出码 1，锁随退出释放。
- **真实模型往返：未验证。** 本机没有可用的模型配置（唯一的 anthropic key 无效），没有用真实模型跑“改代码 → 检查 → 修复”。
  需要用户提供一个有效的 key 或 settings profile 后，用 `--smoke` 和 App 各跑一次，再把结果补到这里。

### 11.4 遗留（M1 之后）

- **真实模型往返**：未验证，等用户提供有效的模型 key（见 11.3）。这是 M1 完成标准里唯一没做的一项。
- **签名、公证的 arm64 / x86_64 DMG**：没做。需要 Developer ID 身份和 notarytool 凭据，按第 7 节从旧 Work 的脚本（`89c5b4d8^`）改写，
  作为 Release 附件；`scripts/bundle.sh` 只产出 ad-hoc 签名的 `.app`。
- **视图层交互测试**：`gpui-kit` 0.9.1 的 `test-support` feature 在依赖解析时冲突（`gpui-fast` 精确锁定 `taffy =0.15.0`，
  而 `gpui-pre` 已选 0.15.1），所以视图测试改用 `gpui-pre` 自己的 `test-support`，只覆盖渲染，没有模拟点击。
  等 gpui-kit 修复后补上审批按钮、输入框的点击测试。
- **一个窗口只跑一个项目**：切换项目会停掉上一个项目的引擎。多窗口放 M3。
- **TUI 的 `/review` 渲染逻辑还在 TUI 里**（`parse_diff` / `revert_hunk` 未移到 core），M2 改动侧栏时一起做。
- **TUI / `-p` 的引擎装配**仍在 `main.rs`（只是复用了 `launch` 的零件），没有完全收进 `launch::project_engine`。
- 第 5 节里属于 M2 的部分：改动侧栏（按块撤回、undo、rewind）、检查和用量面板、设置界面、系统通知和 Dock 角标、命令面板、
  图片拖入、自动更新、Homebrew cask。
- debug 构建链接时 ld 报 `__eh_frame section too large`（只影响 debug 的异常展开性能），在 crate 里 `allow(linker_messages)`。
