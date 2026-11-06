# MicroClaw Code：追平与创新计划（可配置性、交互、TUI）

状态：**已发布（0.25.0）**（原 0.24 / 0.25 / 0.26 三步一次完成，见第 10 节）
更新：**2026-11-05**
基线：**v0.23.1**
前一份计划：[`mccode-next-plan-cn.md`](./mccode-next-plan-cn.md)（0.21–0.23 已交付，重点是上下文引擎）

上一份计划补的是“引擎能力”：上下文、LSP、hooks、worktree、图片。这一份补的是**用户每天直接感受到的部分**：
能配置什么、怎么交互、TUI 好不好看。对比对象是 Claude Code、OpenAI Codex CLI、OpenCode 2.x、
Kimi Code CLI，顺带参考 Gemini CLI、Crush、Aider。

> 竞品资料来自各自的官方文档、源码（Codex `codex-rs/tui`、OpenCode `packages/tui`、Kimi `apps/kimi-code`）
> 和 2026 年的发布说明，调研日期 2026-11-05。这几个产品几乎每天发版，具体键位和配置名会变，只作设计参考。
> 标“未核实”的条目来自二手资料。

---

## 0. 结论

1. **引擎层面我们已经不落后**：OS 沙箱、文件级回退、验证 + 修复回合、项目信任绑定哈希、多模型、
   Server / SDK 共用一个引擎，这些竞品里没有一家全有。
2. **差距集中在“表皮”**：配置只有两个文件、没有分层和规则语法；交互缺少排队、历史搜索、命令面板、
   鼠标、外部编辑器等基本功；TUI 是 16 色硬编码、没有主题、Markdown 只认代码块、diff 没有底色和行号，
   而且每帧重新排版整段对话，长会话会卡。
3. **追平的成本不高**：Codex 用的就是 ratatui，它的做法（syntect + two-face 高亮、主题自适应的 diff 配色、
   流式 Markdown 分块提交、内联 / 全屏两种模式）可以直接参考；OpenCode 的主题 token 体系可以做成兼容格式，
   一次拿到 30 多套主题。
4. **创新点**放在我们独有的东西上：把审批推到手机上的聊天渠道、每轮“回执”（改了什么、检查过没过、
   沙箱和网络状态、花了多少）、按块接受或撤回 agent 的改动、一份承诺稳定的配置格式，以及从 Claude Code /
   Codex / OpenCode 一键迁移。
5. 建议顺序：**0.24 先改 TUI 和交互（“好看、好用”）→ 0.25 配置体系（“可配置”）→ 0.26 差异化功能**。
   原计划里的模型预设、VS Code、Windows ARM 和 Windows 沙箱并行推进（见第 7 节）。

---

## 1. MC Code 现状（读代码得出）

### 1.1 可配置性

| 层 | 文件 | 能配什么 |
|---|---|---|
| 模型凭据 | `~/.microclaw/code/config.yaml`，否则 `MICROCLAW_CODE_CONFIG` / `MICROCLAW_CONFIG` / `~/.microclaw/microclaw.config.yaml`（`crates/microclaw-code-core/src/home.rs`） | 一份完整的 MicroClaw 配置，Code 实际只用 provider / model / key / base_url；**先找到哪个用哪个，不合并** |
| 项目 | `.microclaw/project.yaml`（`project.rs`，仅受信任项目生效） | `mode`、`checks`、`verify`、`max_fix_rounds`、`instructions`、`always_ask`、`compact_instructions`、`lsp`、`hooks.after_edit/after_turn`、`context_tools`、`max_session_tokens` |
| 命令放行 | `~/.microclaw/code/allow-rules.json` | 单条简单命令的前缀，按项目 |
| 自定义命令 | `.microclaw/commands/*.md`、`~/.microclaw/code/commands/` | 带参数的提示词模板 |
| 项目 agent | `.microclaw/agents/` | 给 `explore` 工具用 |
| MCP | 引擎 `data_dir/mcp.json` | Code 里没有查看或管理入口 |
| 命令行 | 约 20 个参数 + `MICROCLAW_CODE_SANDBOX` 等环境变量 | 模式、沙箱、网络、worktree、预算等 |

缺的：

- **没有用户级的 Code 设置**：主题、键位、状态栏、通知、动画、diff 样式、默认模式都没地方配。
- **没有分层合并**：用户 / 项目（提交到仓库）/ 本地（不提交）/ 企业托管，四层都应该有，现在只有“项目”一层。
- **权限规则太弱**：只有命令前缀放行和 `always_ask`；没有 deny，没有按路径的读写规则，没有 MCP 工具、网络域名规则。
- **hooks 只有两个事件**，且只是“跑一条命令”，不能拦截、改写、给 agent 补上下文；格式与 Claude Code 生态不兼容。
- **没有 JSON Schema**，编辑器里写配置没有补全和校验；没有 `mccode config` 命令，`/status` 不显示配置来源。
- 模型配置复用 Server 的整份配置，对只想写代码的用户来说太重。

### 1.2 交互

已有：Enter 发送、运行中输入即引导（steer）、Shift+Tab 切换 plan / ask / auto、`@文件` + Tab 补全、
斜杠命令 Tab 补全、↑↓ 历史、PgUp/PgDn 滚动、Esc 停止、Ctrl+C 两次退出、运行中审批对话框（按数字键）、
项目信任对话框、计划执行确认、`/undo` `/rewind` `/fork` `/handoff` `/review` 等。

缺的（竞品都有或多数有）：

| 项 | 竞品做法 |
|---|---|
| 消息排队（与引导区分） | Codex：Enter 引导、Tab 排队、可编辑队列；Kimi：Ctrl+S 引导、默认排队；Claude Code：排队消息在工具调用之间注入 |
| 斜杠 / `@` 弹出菜单 | 四家都是输入即弹出、模糊匹配、带说明；我们只有 Tab 补公共前缀 |
| 命令面板 | OpenCode Ctrl+P；Claude Code / Codex 用 `/` 菜单 |
| 历史搜索 + 持久化 | Ctrl+R；我们的历史只在内存里，重启就没了 |
| 外部编辑器 | Ctrl+G 打开 `$EDITOR` 写长提示词 |
| `!` shell 模式 | 四家都有，输出作为上下文给 agent |
| 粘贴折叠 / 图片粘贴 | `[Pasted text #1 +120 lines]`、Ctrl+V 贴截图（Kimi 还支持视频） |
| 展开工具输出 / 对话全文模式 | Claude Code Ctrl+O（带搜索）、Codex Ctrl+T + F3 查找、Kimi Ctrl+O |
| 双击 Esc 回退时间线 | 选一条之前的消息，回退对话、代码或两者 |
| 鼠标 | 滚轮滚动、点击展开、拖选复制（OSC 52） |
| 后台化 | Ctrl+B 把正在跑的命令或子代理放到后台 |
| 旁路提问 | `/btw`、`/side`：在临时分支里问一句，不污染主线 |
| 选择器对话框 | `/model`、`/sessions`、`/theme` 弹出可搜索列表，主题实时预览 |
| 系统通知 | 终端失焦时 OSC 9 / bell / 桌面通知，“需要你审批”“任务完成” |
| 审批框 | 方向键选择、“否，并告诉它该怎么做”、显示将写入的规则 |
| 终端标题 | 显示运行状态和项目名 |

### 1.3 TUI 观感与实现问题

文件：`apps/microclaw-code/src/tui/{view,transcript,input,mod}.rs`，ratatui 0.30 + crossterm 0.29。

| 区域 | 现状 | 问题 |
|---|---|---|
| 颜色 | 全部 `Color::Cyan/Green/Yellow/DarkGray` 16 色硬编码 | 没有主题；浅色终端下黄色代码块几乎看不清；无法做底色层次 |
| 顶栏 | 青底黑字 “MicroClaw Code” + 项目、分支、模式、会话 id | 信息还行，但块状色标显得粗；会话 id 对用户没意义 |
| Markdown | 只识别 ```` ``` ```` 切换和 `#` 开头加粗；代码一律黄色 | 行内代码、粗体、列表、表格、链接都按原文显示；没有语法高亮（`pulldown-cmark` 已在依赖里） |
| 工具调用 | `● name summary 123ms`，bash 只留最后 4 行 | 不能展开；连续的读 / 搜索不合并；所有工具一个样子 |
| Diff | `+`/`-` 绿红前景色，最多 60 行 | 没有行号、没有底色、没有词级高亮、没有语法高亮、没有并排视图 |
| 计划 | `[x] [~] [ ]` | 可以，但不够醒目，也不固定在视野里 |
| 状态栏 | 运行中：盘点式 spinner + “Working… Ns”；空闲：一长串快捷键提示 + `ctx N%` | 不显示模型、token、花费；窄终端下提示被截断 |
| 输入框 | 灰色直角边框，标题写操作提示 | 不随模式变色；没有弹出菜单 |
| 对话框 | 居中、青色边框 | 预览最多 10 行；只能按键选 |
| 子代理、压缩 | 一行灰字通知 | 看不出并行了几个、在干什么 |
| 屏幕模式 | 始终进入备用屏幕（alternate screen） | 退出后终端里什么都不留；不能用终端自己的滚动和搜索 |
| **性能** | 每次重绘（至少每 120ms 一次）都把整段对话重新折行（`Transcript::lines`） | 对话越长越慢，几百条工具调用后会明显卡顿 |
| 测试 | 只有一个顶栏的 `TestBackend` 测试 | 改版没有视觉回归保护 |

一句话：**功能对、样子朴素**，处在 Claude Code 2024 年初的水平。

---

## 2. 竞品要点

### 2.1 可配置性

| | Claude Code | Codex CLI | OpenCode 2.x | Kimi Code CLI | **mccode** |
|---|---|---|---|---|---|
| 格式 | JSON，有公开 schema | TOML | JSON/JSONC，有 schema | TOML | YAML，无 schema |
| 分层 | 托管 > CLI > 项目本地 > 项目 > 用户，列表合并 | 用户 / 项目（需信任）/ profile / 管理员 `requirements.toml` 只设上限 | 远程组织默认 > 用户 > 项目 > `.opencode/` > 托管（MDM），深合并 | 用户 / 项目本地 | 只有项目 |
| 权限规则 | `allow/ask/deny`：`Bash(git push *)`、`Read(./.env)`、`Edit(src/**)`、MCP、子代理 | Starlark `prefix_rule(...)`，规则内带正反例，`codex execpolicy check` 可测；命名权限 profile 可 `extends` | 有序数组 `{action, resource, effect}`，另有管理员 `policies` | 兼容 Claude Code 语法 | 命令前缀放行 + `always_ask` |
| Hooks | 33 个事件；command / http / mcp_tool / prompt / agent 五种处理器；可拦截、改写输入、补上下文 | 14 个事件，输出格式兼容 Claude Code | JS/TS 插件钩子 | 约 20 个事件，兼容 Claude Code，仅用户级 | 2 个事件，只跑命令 |
| 主题 | 6 套内置 + 自定义 JSON（约 50 个 token），实时预览编辑器 | syntect 主题，可加 `.tmTheme` | **约 33 套**，token 化 JSON，`system` 主题从终端背景推导 | auto/dark/light + 自定义；**让 agent 帮你写主题**（`/custom-theme`） | 无 |
| 键位 | `keybindings.json`，按上下文，支持组合键 | `tui.keymap.<context>.<action>`，支持组合键 | leader 键（Ctrl+X）+ 约 80 个动作 | 不可配（未核实） | 不可配 |
| 状态栏 | 脚本驱动，stdin 收 JSON | 内置条目清单，`/statusline` 里勾选排序 | 侧栏插件槽 | — | 固定 |
| 子代理定义 | Markdown + frontmatter，可设工具、模型、权限、worktree 隔离 | TOML | Markdown / JSON，可设模型、权限、颜色 | Markdown | `.microclaw/agents/` 只给 `explore` 用 |
| 迁移 | `/import codex\|gemini` | `/import` Claude Code | — | 导入 Claude Code / Codex 的会话和设置 | 无 |

### 2.2 交互

共同趋势：**全屏 + 内联两种模式都给**、**引导与排队分开**、**旁路提问**、**后台任务 + worktree 隔离**、
**模型辅助审批**（Claude Code auto 模式分类器、Codex `auto_review`）、**双击 Esc 回退**、**`/goal` 长任务**。

各家独特的：

- Claude Code：全屏模式下对话全文可搜索、`[` 把内容倒回终端原生滚动区；`/focus` 只看结论；Agent view 管多个后台会话。
- Codex：Esc Esc 回到某条提示词并把它放回输入框改写；提示词预设 0–9；`/side` 旁路对话。
- OpenCode：Tab 切 build / plan agent；`/undo` `/redo` 同时回退消息和文件；时间线对话框；GitHub 评论 `/oc` 触发。
- Kimi：`!` shell 模式边框变紫；`/tower` 多 worktree 任务；`kimi vis` 浏览器里看会话；SSH / Docker 执行环境。

### 2.3 TUI

| | Claude Code | Codex | OpenCode | Kimi | Crush |
|---|---|---|---|---|---|
| 技术 | React/Ink（经典）+ 自研全屏 | **ratatui**（自带 Terminal 分支） | OpenTUI（Zig 内核 + SolidJS） | pi-tui（差量渲染） | Bubble Tea v2 + Ultraviolet |
| 默认模式 | 新用户全屏 | 全屏，可切回滚动区 | 全屏 + 右侧栏 | 内联，全屏实验中 | 全屏 |
| 高亮 | 有 | syntect + two-face（约 250 种语法） | tree-sitter 级 | 有，含 LaTeX | Glamour |
| Diff | 统一视图，行号、底色、词级高亮 | 统一视图，行号、语法高亮，底色随主题和色深自适应 | **宽屏自动并排**，独立 diff 浏览器（文件树、已看标记） | Ctrl+E 全屏 diff | 有 |
| 动效 | spinner + 闪光渐变文字 + 提示 | 余弦闪光（truecolor，低色深降级）、欢迎动画 | 闪光标题、淡入、单格 spinner、标签脉冲，可关 | — | — |
| 其他 | 鼠标、跳到底部提示、粘性顶栏、模式色边框 | OSC 8 链接、屏幕阅读器模式、子代理按颜色区分 | 命令面板、toast、滚动加速、侧栏显示 token / 花费 / MCP / 待办 / 改动文件 | 粘性用户消息摘要、待办卡片 | 主题编辑器 |

OpenCode 被认为“好看”的原因不是某个控件，而是三件事：**用底色层次而不是边框分区**、**一套完整的语义色 token**
（所有组件跟着主题统一变色）、**细小但一致的动效**。这三件在 ratatui 里都能做。

---

## 3. 差距清单（追平）

按“用户每天会碰到几次”排序。编号后面的计划沿用。

### P0：不做就显得落后

| 编号 | 项 | 说明 |
|---|---|---|
| U1 | 主题系统 | 语义色 token（见 5.2），内置 dark / light / auto（按终端背景）/ ansi（只用 16 色）+ 至少 6 套流行主题；truecolor / 256 / 16 色三档降级 |
| U2 | Markdown 渲染 | 用已有的 `pulldown-cmark`：标题、粗斜体、行内代码、列表、引用、表格、链接（OSC 8）；流式输出时按行提交，表格暂缓到完整再排 |
| U3 | 语法高亮 | 代码块和 diff 都高亮；`syntect` + `two-face`（与 Codex 相同），文件大小上限防卡 |
| U4 | Diff 渲染 | 行号、增删底色（随主题）、词级高亮、语法高亮；宽度 ≥ 160 列自动并排，可配 `auto/split/unified` |
| U5 | 工具调用卡片 | 每类工具一个样式；连续的 read / grep / glob 合并成“已浏览 N 个文件”；结果默认折叠为 `… +N 行`，Ctrl+O 展开 |
| U6 | 弹出补全 | `/` 与 `@` 输入即弹出，模糊匹配，显示说明，↑↓ 选、Tab/Enter 确认；自定义命令和项目 agent 一起列出 |
| U7 | 排队与引导分开 | Enter = 排队（当前工具调用结束后注入），Ctrl+Enter / Ctrl+S = 立即引导；队列显示在输入框上方，可编辑和撤回 |
| U8 | 历史 | 按项目持久化输入历史；Ctrl+R 反向搜索 |
| U9 | 渲染性能 | 每个条目缓存“按宽度折好的行”，只有最后一个流式条目和宽度变化时重算；只渲染可见区；空闲时不重绘 |
| U10 | 状态栏 | 运行中：闪光 “Working” + 用时 + token + “esc 停止”；空闲：模型、模式、ctx%、本会话花费、分支、沙箱/网络；窄屏按优先级省略 |
| U11 | 鼠标与滚动 | 滚轮（带加速）、点击展开工具卡片、拖选复制（OSC 52）；`--no-mouse` 关闭以保留终端原生选择 |
| U12 | 视觉回归测试 | `TestBackend` + `insta` 快照覆盖每种条目、三档色深、窄 / 宽屏 |

### P1：交互完整度

| 编号 | 项 | 说明 |
|---|---|---|
| I1 | 外部编辑器 | Ctrl+G 用 `$VISUAL`/`$EDITOR` 编辑输入；计划模式下编辑计划 |
| I2 | `!` shell 模式 | 空输入框按 `!` 进入，边框变色；命令走同一套沙箱和审批，输出作为上下文 |
| I3 | 粘贴 | 大段粘贴折叠为 `[Pasted #1 +120 lines]`；Ctrl+V 贴剪贴板图片（复用 0.23 的图片管线） |
| I4 | 全文模式 | Ctrl+T 进入只读全文视图：`/` 搜索、`n/N`、按提示词跳转、`v` 用编辑器打开、导出到终端滚动区 |
| I5 | 回退时间线 | Esc Esc 打开时间线，选一条消息：回退对话 / 代码 / 两者 / 从此处摘要；选中的提示词回填输入框 |
| I6 | 选择器对话框 | `/model`、`/sessions`、`/theme`（实时预览）、`/agents`、`/mcp` 都做成可搜索列表 |
| I7 | 审批框 | ↑↓ 选择 + 数字键；“否，并说明原因”直接写给 agent；显示“总是允许”会写入哪条规则、写到哪一层 |
| I8 | 通知 | 终端失焦时：需要审批、任务完成、检查失败 → OSC 9 / OSC 777 / bell；可配置条件 |
| I9 | 后台化 | Ctrl+B 把正在跑的 bash 或子代理转后台；`/tasks` 列出，完成时通知 agent 和用户 |
| I10 | 旁路提问 | `/btw <问题>`：在当前会话的临时分支里回答，不写回主线 |
| I11 | 终端标题 | `● mccode · repo · 运行中`，等待审批时换符号 |
| I12 | 内联模式 | `--inline` / `tui.screen: inline`：不进备用屏幕，完成的条目写入终端原生滚动区（参考 Codex `insert_history`），只重绘底部；在 tmux / Zellij 下作为默认 |

### P1：配置体系（详见第 5 节）

| 编号 | 项 |
|---|---|
| C1 | 四层配置：托管 > 项目本地 > 项目 > 用户，加 CLI 覆盖；列表合并，标量覆盖 |
| C2 | 发布 JSON Schema（YAML 语言服务器可用），`mccode config doctor` 校验并指出被忽略的项 |
| C3 | 权限规则 `allow / ask / deny`，覆盖 bash、读、写、网络域名、MCP 工具、子代理 |
| C4 | Hooks v2：事件扩充 + 兼容 Claude Code 的 stdin/stdout JSON 协议 + 可拦截 |
| C5 | `tui.*` 设置：主题、键位、状态栏条目、屏幕模式、动画、diff 样式、通知 |
| C6 | 子代理定义：`.microclaw/agents/*.md` 扩展为可被主 agent 调用的完整子代理（工具、模型、权限、worktree 隔离） |
| C7 | `/config` 交互面板 + `mccode config get/set/edit`；`/status` 显示每一项的来源层 |
| C8 | Code 专用的轻量模型配置（profiles），不再要求整份 Server 配置 |

---

## 4. 创新点（超车）

只挑**竞品做不了或没做好、而我们有现成基础**的：

| 编号 | 想法 | 为什么我们能做 |
|---|---|---|
| X1 | **审批推到手机** | MicroClaw 本来就有 Telegram / Slack / Discord / 飞书渠道和按钮式审批。TUI 运行时离开电脑，审批、完成通知、检查失败推到你的聊天应用里，点按钮就继续。竞品要么只有自家 App，要么没有 |
| X2 | **每轮回执** | 每轮结束显示一张卡片：改了哪些文件（`+N -M`）、哪些检查通过、用了沙箱没有、有没有联网、token 和花费、可回退的检查点 id。验证 + 检查点是我们独有的，把它们变成看得见的东西 |
| X3 | **按块审阅 agent 的改动** | `/review` 进入 diff 浏览器（文件树 + 并排 diff），对每个 hunk：保留 / 撤回 / 写评语给 agent。基于已有的影子 git 检查点。Claude Code、Codex 都没有终端内按块撤回；OpenCode 只能看 |
| X4 | **稳定的配置承诺** | 配置有版本号和 schema，破坏性改动必须带自动迁移（`mccode config migrate`）。OpenCode 2.0、Kimi 重写、Codex 频繁改名都在被抱怨 |
| X5 | **一键迁移** | `mccode import claude\|codex\|opencode`：导入 CLAUDE.md / AGENTS.md、权限规则、MCP、自定义命令、子代理、hooks（hooks 协议兼容后可直接用）；OpenCode 主题 JSON 直接可读 |
| X6 | **沙箱和网络可视化** | 状态栏常驻沙箱 / 网络图标；命令要联网时按域名临时放行（一次 / 本会话 / 规则）；回执里列出本轮访问过的域名 |
| X7 | **让 agent 改自己的配置** | 内置 `config` 技能：“把主题换成浅色并把 diff 改成并排”“以后 git push 都问我”→ 生成配置修改，用 diff 展示，确认后写入。Kimi 只做了主题这一项 |
| X8 | **按角色选模型** | 计划 / 编辑 / 审阅 / 子代理 / 摘要各用一个模型（例如计划用强模型、执行用便宜模型），状态栏显示当前角色；多模型是我们相对 Codex 的天然优势 |
| X9 | **“验证优先”的界面** | 检查面板固定在侧栏或底部：每个检查的状态、耗时、上次失败摘要；修复回合以进度显示；`/goal` 的完成条件直接写成“这些检查必须通过”，比 OpenCode 用评审 agent 判断更可靠 |
| X10 | **同一会话多端接力** | 通过已有的 Server 配对，TUI、Web、聊天渠道看同一个会话：在终端开始，在手机上看进度和回执、批准，回到电脑继续 |

---

## 5. 设计方案

### 5.1 TUI 布局

默认全屏，宽屏（≥ 130 列）显示右侧栏，窄屏自动隐藏；`tui.screen: inline` 走内联模式（I12）。

```
 ◆ microclaw  main  ·  ask  ·  deepseek-v4-pro                       sandbox ● net ○   ctx 34%  $0.42
──────────────────────────────────────────────────────────────────────┬──────────────────────────────
 › 修一下 parser 里的空行 bug，并补测试                               │ 计划
                                                                      │  ✓ 定位空行处理
   先看一下解析入口和现有测试。                                        │  ● 修改 parse_block
                                                                      │  ○ 补测试
 ⏺ 已浏览 6 个文件 · 2 次搜索                              0.8s   ▸   │
 ⏺ edit  src/parser.rs                                     +12 −3     │ 检查
   │  41   fn parse_block(input: &str) -> Block {                     │  ✓ cargo check   4.1s
   │  42 -     let lines = input.lines();                              │  ● cargo test    运行中
   │  42 +     let lines = input.lines().filter(|l| !l.is_empty());    │
   │  … +9 行  (ctrl+o 展开)                                           │ 改动
 ⏺ bash  cargo test parser                                 2.3s       │  src/parser.rs   +12 −3
   │  test result: ok. 14 passed; 0 failed                            │  tests/parse.rs  +28
                                                                      │
 ✦ Working  12s · ↑3.1k ↓420 · esc 停止                               │ 子代理 1 个运行中
──────────────────────────────────────────────────────────────────────┴──────────────────────────────
╭─ ask ──────────────────────────────────────────────────────────────────────────────────────────────╮
│ › 顺便看看 lexer 有没有同样的问题▌                                                                 │
╰────────────────────────────────────────────────────── 排队 1 条 · Ctrl+S 立即引导 · / 命令 · @ 文件 ╯
```

要点：

- **顶栏**：一行，左边项目 / 分支 / 模式 / 模型，右边沙箱、网络、ctx%、花费；去掉色块，用主题的 `accent` 文字色。
- **对话区**：用户消息用 `›` + 加粗；工具调用用 `⏺` 标题 + `│` 缩进结果；同类读搜索合并；diff 有行号和底色。
- **侧栏**：计划、检查、改动文件、子代理、MCP 状态；用 `background.panel` 底色分区，不画边框。
- **输入框**：圆角边框，颜色随模式变（plan 蓝、ask 绿、auto 黄、shell 紫）；右下角是上下文相关的提示，不再是固定长串。
- **每轮回执**（X2）在一轮结束时插在对话里：

```
 ╭ 本轮 ─────────────────────────────────────────────────────────╮
 │ 2 个文件 +40 −3 · cargo test ✓ · 沙箱内运行 · 未联网           │
 │ 18.4k tokens · $0.06 · 检查点 c7  (esc esc 回退)               │
 ╰───────────────────────────────────────────────────────────────╯
```

### 5.2 主题 token

一个主题是一组语义色，组件只引用 token，不直接写颜色：

```yaml
# ~/.microclaw/code/themes/my-theme.yaml
name: my-theme
base: dark            # 未定义的 token 从这里继承
palette:              # 可选，定义可复用的颜色
  blue: "#7aa2f7"
tokens:
  text: "#c0caf5"
  text_muted: "#565f89"
  accent: blue
  background: none     # none = 用终端背景
  background_panel: "#1f2335"
  background_element: "#292e42"
  border: "#3b4261"
  border_active: blue
  success: "#9ece6a"
  warning: "#e0af68"
  error: "#f7768e"
  mode_plan: blue
  mode_ask: "#9ece6a"
  mode_auto: "#e0af68"
  mode_shell: "#bb9af7"
  diff_added_bg: "#20303b"
  diff_removed_bg: "#37222c"
  diff_added_word: "#2f5a49"
  diff_removed_word: "#713137"
  diff_line_number: "#3b4261"
  syntax_theme: "tokyo-night"   # syntect 主题名或 .tmTheme 路径
```

- 颜色值可以是 `#rrggbb`、ANSI 0–255、palette 名、`{dark: …, light: …}` 或 `none`。
- 加载器也接受 **OpenCode 主题 JSON**（token 名做映射表），这样它的 30 多套主题直接能用。
- `auto` 主题通过 OSC 11 查询终端背景色决定深浅；查询失败默认 dark。
- 16 色终端统一降级到 `ansi` 主题，不在每个组件里分支。

### 5.3 渲染架构

- `transcript.rs` 的 `Item` 变成 `Cell` trait（`desired_height(width)`、`render(area, buf, theme)`、`is_live()`），
  每个 cell 缓存“宽度 → 行”的结果；已完成的 cell 不再重算（U9）。
- 流式 Markdown：参考 Codex 的“按行提交”——只有遇到换行才提交一行，表格和未闭合代码块暂留在可变尾部；
  落后太多时一次追赶，避免每个 token 都重排。
- 内联模式（I12）：完成的 cell 用滚动区域写进终端原生回滚，只重绘活动 cell 和底部；参考
  Codex `insert_history.rs` / `custom_terminal.rs`。
- 动效统一走一个 `Animator`，`tui.animations: false` 或 `NO_COLOR` 时全部关闭；空闲时停止 tick。
- 新依赖：`syntect`、`two-face`、`textwrap`（可选）、`arboard`（剪贴板，可选 feature）、`insta`（dev）。
  都是纯 Rust 或已在 Codex 生产使用，单二进制不变。

### 5.4 配置格式

保持 YAML（与 `project.yaml`、Server 配置一致），新增一个 Code 设置文件，四层同名：

| 层 | 路径 | 说明 |
|---|---|---|
| 托管 | `/etc/microclaw/code/managed.yaml`、macOS `/Library/Application Support/MicroClaw/code/managed.yaml` | 只能收紧：deny 规则、禁用的模式、强制沙箱 |
| 项目本地 | `.microclaw/settings.local.yaml` | 不提交（`/init` 时写入 `.gitignore`）；“总是允许”默认写这里 |
| 项目 | `.microclaw/settings.yaml`（与 `project.yaml` 合并，旧文件继续支持） | 提交到仓库；需要项目信任 |
| 用户 | `~/.microclaw/code/settings.yaml` | 个人偏好 |

示例：

```yaml
# yaml-language-server: $schema=https://microclaw.ai/schema/code-settings.v1.json
version: 1

model:
  default: deepseek/deepseek-v4-pro
  roles:                      # X8
    plan: anthropic/claude-opus-5-5
    review: anthropic/claude-sonnet-5-5
    subagent: deepseek/deepseek-flash
  profiles:                   # C8：Code 自己的轻量 provider 配置
    deepseek: { type: openai, base_url: https://api.deepseek.com, api_key_env: DEEPSEEK_API_KEY }

permissions:
  default_mode: ask
  allow:
    - bash(cargo test *)
    - bash(git status)
    - edit(src/**)
  ask:
    - bash(git push *)
    - net(*)
  deny:
    - read(**/.env)
    - bash(rm -rf /*)
    - mcp(github.delete_*)

sandbox:
  backend: local
  network: ask               # off | ask | on
  allow_domains: [crates.io, static.crates.io, github.com]

hooks:                        # C4，协议兼容 Claude Code
  pre_tool_use:
    - matcher: "bash"
      command: ./scripts/guard.sh
  post_edit:
    - command: cargo fmt -- {file}
  stop:
    - command: ./scripts/notify.sh

tui:
  theme: auto
  screen: auto                # auto | fullscreen | inline（Zellij 下 auto = inline）
  sidebar: auto
  diff: auto                  # auto | split | unified
  animations: true
  mouse: true
  status_line: [mode, model, context, cost, branch, sandbox]
  notifications: { method: auto, when: unfocused }
  keymap:
    chat.steer: ctrl+s
    chat.queue: enter
    app.palette: ctrl+p
    transcript.open: ctrl+t

notify_channel:               # X1：通过配对的 Server 推送
  server: default
  chat: telegram:123456789
  events: [approval, done, check_failed]
```

规则语法：`<种类>(<模式>)`，种类为 `bash`、`read`、`edit`、`net`、`mcp`、`agent`；**deny 优先，其次 ask，再 allow**；
bash 按解析后的单条命令匹配（`&&`、`|`、`;` 拆开逐条判断）；与 Claude Code 写法接近，方便迁移。
现有 `allow-rules.json` 和 `always_ask` 自动转换为规则（C1 的迁移步骤）。

Hooks 事件（第一版）：`session_start`、`user_prompt_submit`、`pre_tool_use`（可 allow / deny / ask / 改写输入）、
`post_tool_use`、`post_edit`、`permission_request`、`pre_compact`、`stop`、`notification`、`session_end`。
处理器先支持 `command` 和 `http`。

---

## 6. 不做或暂缓

- **插件市场 / UI 插件槽**：Claude Code、OpenCode 都有，但维护成本高；先把 hooks、命令、子代理、主题做成
  可分发的目录格式，市场等有社区再说。
- **云端任务**：我们的等价物是 Server + 配对（X10），不另做云。
- **宠物、欢迎动画、彩虹字**：不做；动效只用于表达状态（运行中、等待审批）。
- **语音输入**：暂缓。

---

## 7. 版本计划

原先建议分三步（0.24 好看好用、0.25 可配置、0.26 差异化），维护者决定**合并为一个 0.25 一次做完**。
原计划里的 VS Code（ACP 桥接）、Windows ARM、Windows 沙箱不在 0.25 范围内，仍按
[`next-plan-2026-11-cn.md`](./next-plan-2026-11-cn.md) 作为并行轨道。

| 版本 | 内容 | 验收 |
|---|---|---|
| **0.25** | U1–U12、I1–I8、I10–I12、C1–C8、X1–X10、模型预设（原 D4） | 单元测试与渲染快照测试通过；浅色 / 深色 / 16 色主题渲染走查；expect 驱动的 TUI 冒烟测试；发版前用真实模型按 0.23.1 的方式逐项手测 |
| 并行 | VS Code（ACP 桥接）、Windows ARM、Windows 沙箱 | 按原计划 |

---

## 8. 实施注意

- TUI 改版按 cell 逐个替换，每替换一种就补快照测试；不一次性重写 `mod.rs`。
  先拆 `tui/mod.rs`（1358 行）：命令处理、补全、对话框各自成模块。
- 主题、键位、状态栏条目都放在 `microclaw-code-core`（与 UI 无关的配置解析），`apps/microclaw-code` 只负责渲染；
  ACP / `-p` 模式忽略 `tui.*`。
- 权限规则的判定放在引擎的 `tool_runtime`（Server 渠道以后也能用），Code 只负责加载和展示。
- hooks 协议兼容 Claude Code 时，要在文档写清楚哪些字段支持、哪些忽略，避免“看起来兼容、实际不一样”。
- 内联模式在不同终端差异很大（Windows ConPTY、tmux `-CC`），需要明确的降级路径：失败就回到全屏。
- 所有新配置项带默认值；默认行为对现有用户不变（主题默认 `auto`，排队 / 引导的键位变化要在升级说明里写明）。

---

## 9. 来源

- Claude Code 文档：<https://code.claude.com/docs/en/settings>、`interactive-mode`、`hooks`、`permission-modes`、
  `fullscreen`、`statusline`、`sub-agents`、`agent-view`、`memory`
- OpenAI Codex：<https://github.com/openai/codex>（`codex-rs/tui/src/` 下 `slash_command.rs`、`keymap.rs`、`shimmer.rs`、
  `insert_history.rs`、`custom_terminal.rs`、`transcript_mode.rs`、`diff_render.rs`、`streaming/chunking.rs`、
  `streaming/table_holdback.rs`、`bottom_pane/footer.rs`）；配置参考 <https://learn.chatgpt.com/docs/config-file/config-reference>；
  滚动区问题 <https://github.com/openai/codex/issues/10331>
- OpenCode：<https://opencode.ai/docs/config/>、`/docs/themes/`、`/docs/keybinds/`、`/docs/permissions/`、`/docs/tui/`、
  <https://opencode.ai/v2/docs/>、<https://github.com/anomalyco/opencode>、<https://github.com/sst/opentui>、
  <https://anoma.ly/notes/opencode-2-0/>
- Kimi Code CLI：<https://github.com/MoonshotAI/kimi-code>、<https://moonshotai.github.io/kimi-code/en/>
  （configuration、interaction、slash-commands、hooks、changelog）；旧版 <https://github.com/MoonshotAI/kimi-cli>（已归档）
- Gemini CLI：<https://github.com/google-gemini/gemini-cli>；Crush：<https://github.com/charmbracelet/crush>；
  Aider：<https://aider.chat/docs/>

---

## 10. 0.25 交付情况

随 0.25.0 发布（#546，tag 打在 #547 上），发布证据见 [`v0.25.0-plan.md`](./v0.25.0-plan.md)。

| 编号 | 状态 | 实现位置 |
|---|---|---|
| U1 主题 | 完成 | `apps/microclaw-code/src/ui/theme.rs`：语义 token，11 套内置主题，YAML 自定义主题，OpenCode 主题 JSON，truecolor / 256 / 16 色降级 |
| U2 Markdown | 完成 | `ui/markdown.rs`：pulldown-cmark；标题、行内代码、列表、任务列表、引用、表格、代码块；流式稳定行 |
| U3 语法高亮 | 完成 | `ui/highlight.rs`：syntect + two-face（fancy-regex，不依赖 onig），大文件跳过 |
| U4 Diff | 完成 | `ui/diff.rs`：行号、底色、词级高亮、语法高亮，≥ 160 列自动并排 |
| U5 工具卡片 | 完成 | `tui/transcript.rs`：读 / 搜索合并为“Explored”，折叠输出，Ctrl+O 或鼠标点击展开 |
| U6 弹出补全 | 完成 | `tui/popup.rs`：`/`、`@` 模糊匹配 |
| U7 排队 / 引导 | 完成 | Enter 排队、Ctrl+S 引导、↑ 取回排队消息、`/queue` |
| U8 历史 | 完成 | `tui/input.rs`：按项目持久化（`~/.microclaw/code/history.jsonl`），Ctrl+R |
| U9 渲染性能 | 完成 | 按条目 + 宽度缓存，只渲染可见窗口，空闲时不重绘 |
| U10 状态栏 | 完成 | 运行中闪光 + 用时；空闲时 `tui.status_line` 可配置条目 |
| U11 鼠标 | 完成 | 滚轮、点击展开；全屏模式默认开启（`tui.mouse`） |
| U12 视觉回归 | 完成 | `tui/preview.rs`：TestBackend 断言 + `MCCODE_PREVIEW_DIR` 导出 HTML 预览（`insta` 不在离线缓存中，用普通断言） |
| I1 外部编辑器 | 完成 | Ctrl+G；全文模式 `v` |
| I2 `!` shell | 完成 | 输出作为下一条消息的上下文 |
| I3 粘贴 | 完成 | 大段粘贴折叠；Ctrl+V 剪贴板图片（macOS osascript、Linux wl-paste / xclip、Windows PowerShell） |
| I4 全文模式 | 完成 | Ctrl+T：搜索、n/N、g/G、`v` 编辑器 |
| I5 回退时间线 | 完成 | Esc Esc / `/rewind`：恢复文件并回填提示词。**对话本身不回退**（SDK 没有截断对话的接口） |
| I6 选择器 | 完成 | 命令面板、`/model`、`/theme`（实时预览）、`/sessions` |
| I7 审批框 | 完成 | 方向键选择、“否，并告诉 agent 该怎么做”、显示将保存的规则 |
| I8 通知 | 完成 | `tui/notify.rs`：OSC 9 / 777 / bell，tmux 透传 |
| I9 后台化 | **未做** | Ctrl+B 现在是侧栏开关。把正在前台运行的命令转后台需要引擎 bash 工具支持，留作后续 |
| I10 `/btw` | 完成 | 在会话分支里只读回答，可在运行中使用 |
| I11 终端标题 | 完成 | |
| I12 内联模式 | 完成 | `tui.screen`；Zellij 下自动；终端不支持时回退全屏 |
| C1 四层配置 | 完成 | `crates/microclaw-code-core/src/settings.rs` |
| C2 Schema + doctor | 完成 | `docs/schema/code-settings.v1.json`，`mccode config doctor` |
| C3 权限规则 | 完成 | `rules.rs` + 引擎 `ToolGate`（`crates/microclaw-engine/src/tool_gate.rs`），主 agent 与子代理都受约束 |
| C4 Hooks v2 | 完成 | `user_hooks.rs` + `gate.rs` + driver：10 个事件，Claude Code 协议，command / http |
| C5 `tui.*` | 完成 | 主题、屏幕、侧栏、diff、动画、鼠标、状态栏、通知、键位（`tui/keymap.rs`） |
| C6 子代理定义 | 部分 | 规则可按 `agent(...)` 约束；`.microclaw/agents` 仍只给 `explore` 用 |
| C7 `/config` | 完成 | TUI `/config`、`mccode config` 子命令 |
| C8 Code 模型 profile | 完成 | `model.profiles` + `model.default`，无需完整 MicroClaw 配置 |
| X1 审批推到聊天 | 完成 | Server：`src/remote_approvals.rs`、`src/web/code_remote.rs`；客户端 `remote_notify.rs`。Telegram / Discord / Slack 按钮，飞书文字选项 |
| X2 每轮回执 | 完成 | 文件、检查、沙箱、联网域名、token、花费（价格已知时）、检查点 |
| X3 按块审阅 | 完成 | `tui/review.rs`：撤回单个 hunk（备份补丁）、标记已看、评语变成提示词 |
| X4 配置版本与迁移 | 完成 | `version` 字段，`mccode config migrate` |
| X5 一键迁移 | 完成 | `import.rs`，`mccode import` / `/import` |
| X6 沙箱与网络可视化 | 完成 | 顶栏图标、`sandbox.network: ask`（按域名询问）、回执列出访问的域名 |
| X7 让 agent 改配置 | 完成 | `/configure <要求>`：模型给出改动，确认后写入 |
| X8 按角色选模型 | 部分 | `plan`、`review`、`summary`；`subagent` 角色未接（引擎没有子代理模型设置） |
| X9 验证优先界面 | 完成 | 侧栏检查面板；`/goal` 以检查通过为完成条件 |
| X10 多端接力 | 部分 | 通过 X1 在聊天里接收通知和审批；没有新的会话同步机制 |
| D4 模型预设 | 部分 | `presets.rs`：窗口与引擎表一致；**价格与最大输出为空**（仓库里没有可靠来源），所以花费只在价格已知时显示 |
| ACP / MCP 服务模式 | 完成 | 同样加载设置、规则、hooks、角色模型 |

已知限制：

- 无模型冒烟测试（expect 驱动）覆盖了启动、弹出补全、shell 模式、`/config`、`/permissions`、
  主题选择器、全文模式、内联模式与回退。真实模型测试见下一节。
- `read(...)` 规则不覆盖 bash（`cat .env` 不被 `read(**/.env)` 拦截，靠沙箱和路径保护）；`net(...)`
  只覆盖 `web_fetch`。
- 终端背景深浅只从 `COLORFGBG` 判断，没有做 OSC 11 查询；判断不了时按深色。
- Server 重启会丢失待处理的远程审批（客户端看到 `Gone`，回到终端里答）。

### 10.1 真实模型测试（DeepSeek）

用 `deepseek-flash` 和 `deepseek-v4-pro`（macOS arm64，独立 `MICROCLAW_CODE_HOME`，设置里的
`ds` profile，`type: deepseek` + `api_key_env`）测试；TUI 用伪终端驱动并渲染屏幕检查。

| 项目 | 做法 | 结果 |
|---|---|---|
| profile 启动 + plan 模式 | `-p --mode plan` | **bug**：角色模型把 `ds/deepseek-flash` 原样当模型名发出 → 修复（`settings::role_model_for`，同 profile 才切换，其他 profile 跳过并警告） |
| auto 模式修 bug + 检查 | `-p --mode auto --trust` | 一次修好，lsp 与 build 检查通过 |
| deny / allow 规则、pre_tool_use hook 拦截、user_prompt_submit 加上下文 | `-p --mode ask` | 全部生效 |
| `ask` 规则 | auto 模式下 `edit(src/**)` | **bug**：auto 模式直接批准了规则要求问人的调用 → 修复（gate 记录规则/hook 的 ask，driver 不再自动批准；文本路径不再二次判断） |
| 暂停后 `-p 1` 继续 | 同上 | **bug**：prompt hook 给 `1` 加了上下文，引擎认不出是审批，反复要求批准 → 修复（`1`/`2`/`3` 不跑 prompt hook） |
| shell 工具 | TUI 里模型的 `grep --include=*.rs` | **bug**：命令用 `$SHELL`（zsh）执行，未匹配的通配符直接报错 → 修复（有 bash 就用 bash） |
| TUI 一轮 + 审批对话框 + 回执 | ask 模式，4 次审批 | 对话框、回执（文件、检查、沙箱/网络、token、检查点）正常 |
| `/btw`、`/configure` | 同一会话 | 侧问回答正确；`/configure` 提议 `user · tui.theme = github-light`，确认后写入并即时换主题 |
| `/goal` | 带溢出测试的失败用例，auto 模式 | 1 轮达成，3/3 测试通过；`ask` 规则在 auto 模式下仍要求了 1 次批准 |
| review 角色 | `mccode review`，`review: ds/deepseek-v4-pro` | 用 v4-pro 审查（换成不存在的模型名会被 API 拒绝，证明角色生效），找到除零与 `i64::MIN / -1` |
| 本地设置文件 | review 指出 `settings.local.yaml` 未被忽略 | 改进：写本地层时加入 `.git/info/exclude` |
| 后台命令 `bash_kill` | 改用 bash 后的单元测试 | **bug**：只杀 shell，子进程（如 `npm run dev` 下的 node）留着并占住输出，状态一直是 running → 修复（独立进程组，`killpg`；杀掉后最多等 2 秒输出）。Linux bubblewrap 用 `--new-session`，沙箱里的孙进程仍可能残留，需要 `--unshare-pid`，留待以后 |
