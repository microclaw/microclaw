# MicroClaw Work：桌面端与服务端双产品提案

状态：**已批准，分阶段开发中** · 日期：**2026-08-25**

> 执行范围已于 2026-08-26 收敛为 macOS-first。当前阶段、验收线和延期范围以
> [`microclaw-work-macos-execution-plan.md`](./microclaw-work-macos-execution-plan.md)
> 为准；本文保留为最初的双产品方向提案。

本文是 [`product-direction-2026-08.md`](./product-direction-2026-08.md) 的中文实施提案，
用于约束下一次大版本的产品边界和阶段验收；具体发布日期仍由各阶段验证结果决定。

## 一、提议

下一次大版本把 MicroClaw 明确为两个产品，但继续共享同一个 Rust 内核：

```text
MicroClaw Work                         MicroClaw Server / Cloud
原生桌面工作助手                        常驻 Agent 服务
macOS / Windows / Linux               本地服务器 / VPS / NAS / 云主机
GPUI + GPUI Component                 CLI + API + Web 管理端
前台、交互式、可随时介入                 后台、持久化、无人值守
项目、计划、工具、Diff、产物              渠道、计划任务、投递、远程运行
                 \                    /
                  共享 MicroClaw Core
         Agent Loop、模型、工具、权限、记忆、存储、恢复
```

这不是把现有 Web 页面套进一个桌面壳，也不是另外重写一套 Agent。Work 和
Server 可以拥有不同的任务策略和交互方式，但必须复用 provider-neutral Agent
Engine、工具执行、安全策略、记忆、SQLite、Checkpoint 和完成契约。

长期目标是打造一套纯 Rust、开源、可自托管的 Agent 产品架构：用户既可以把
Work 当成本地工作伙伴单独使用，也可以部署 Server 作为自己的 Agent Cloud，
并让两者安全地互相委派任务。

## 二、MicroClaw Work

Work 面向“人在电脑前，与 Agent 一起完成工作”的场景，形态接近新一代工作
伙伴，而不是聊天机器人或完整 IDE。

第一个必须做好的闭环是：

```text
打开工作目录
-> 描述任务
-> 查看和调整计划
-> 观察工具与文件操作
-> 在关键副作用前审批
-> 查看 Diff 和产物
-> 运行验证
-> 接受、继续修改或回退
```

桌面端使用 GPUI + GPUI Component，目标覆盖 macOS、Windows 和 Linux。第一
阶段仍以 macOS 和 Windows 的可发布质量为验收线，Linux 同步保持可编译和社区
预览支持；只有建立持续测试和打包能力后，才承诺三端同等级发布。

Work 的界面围绕工作流组织：

- Workspace、最近任务和搜索；
- 对话与工作画布；
- Plan、实时进度和可中途介入的任务时间线；
- 工具活动、进程输出、文件、Diff 和 Artifact；
- 常驻 Approval Center；
- 模型、权限、诊断和 Server 连接。

第一版不做完整 IDE、自由拖拽 Agent 画布、插件商城、全功能终端模拟器或所有
Server 管理功能。先让一个项目任务从开始到交付真正可靠。

## 三、MicroClaw Server / Cloud

Server 继续长期维护，它不是被桌面端取代的旧产品。它负责桌面端不适合承担的
常驻能力：

- 计划任务、后台任务、重试、恢复和结果投递；
- Telegram、Discord、Slack 等仍有真实需求的渠道；
- 多 Agent 路由、命名 Agent、团队模板和远程 Worker；
- HTTP、SSE、WebSocket、ACP、A2A 和 MCP 边界；
- Web 管理端、远程访问、移动 Web/PWA；
- VPS、NAS、家庭服务器和用户自有云部署。

“Cloud”首先指用户拥有的 MicroClaw Server，而不是立即建设多租户 SaaS。近期
优先做好 Docker Compose、一键云平台模板、私有网络连接、二维码配对、备份和
升级。只有数据证明自托管仍是主要流失原因，才讨论托管控制面或托管运行时。

## 四、精简 Server 的第三方集成

大版本升级可以借机重新划分集成层级，但不应凭感觉删除已有渠道。先收集构建
体积、维护成本、故障率、实际启用率和社区需求，再分为：

1. **Core**：Agent、API、SQLite、基础工具、安全与恢复，默认必须存在。
2. **Standard**：Web 管理端、调度、MCP 和少量高使用率渠道，默认安装。
3. **Optional adapters**：低使用率渠道、重依赖协议和专业能力，改为 feature、
   独立包或插件按需安装。
4. **Deprecated**：长期无人使用且无人维护的适配器，先公告一个大版本周期，再
   移除或移交社区。

建议形成 `microclaw-lite`、`microclaw-server` 和可选集成包，而不是继续让每个
安装包携带全部 SDK。Web 管理端对 Server 仍有价值；Work 则完全不内嵌 Web UI，
避免同时维护两套桌面前端。

## 五、Work 与 Server 如何协同

二者都能独立使用，并通过稳定任务协议协作：

- Work 把“每天检查这个仓库”转为 Server 的计划任务；
- Work 把长时间任务交给 Server，之后在桌面继续检查结果；
- Server 把需要本地代码、凭据或图形环境的任务委派给在线 Work；
- 手机/PWA 连接 Server，查看状态并完成审批，不在手机中运行完整 Agent。

委派协议必须携带身份、Workspace 引用、权限、预算、完成契约、进度、取消和
产物，并默认最小授权。ACP/A2A 可以作为底层协议，但产品语义由 MicroClaw
自己定义。

## 六、大版本与兼容策略

本提案按下一次大版本实施，允许主动打破以下兼容：

- 重新设计配置结构，不保证旧 YAML 原样可用；
- 重新命名 binary、子命令、环境变量和默认目录；
- 调整 HTTP API、事件模型和 Work ↔ Server 协议；
- 将低使用率渠道从默认构建移到 feature、独立包或插件；
- 删除仅为旧内部结构保留的 Rust API 和临时 facade；
- 不保证旧 Web UI 与新 Work UI 功能一一对应。

不兼容不等于丢弃用户数据。以下内容仍是硬约束：

- 会话、任务、记忆和审计数据提供一次性数据库迁移或只读导出；
- 凭据不静默迁移到更宽的权限域，也不写入日志；
- 工具安全、路径保护、审批和审计能力不因重构而降低；
- 发布清楚的迁移指南、废弃列表和回退方式；
- 大版本升级前可以导出用户数据，失败时不破坏旧数据目录。

建议使用新的配置版本标识和数据目录 schema version。新版本可以拒绝启动旧
配置并给出迁移命令，而不是在运行时长期维护多套兼容分支。

## 七、六阶段开发计划

整个开发建议拆成六个有独立验收标准的阶段。每个阶段合并前都必须有可运行的
结果，不能以“后续阶段会补齐”为由留下不可用主干。

### Phase 0：提案和技术验证

- 讨论并确认 Work/Server 产品边界；
- 用两周 GPUI Spike 验证 macOS、Windows，并保持 Linux 编译验证；
- 验证中文 IME、无障碍、GPU、流式内容、长列表、Diff、恢复和签名打包；
- 固定 GPUI/GPUI Component revision，用适配 crate 隔离上游变化；
- 统计 Server 集成的使用、体积和维护成本。

验收标准：同一个原型可以在 macOS 和 Windows 打开 Workspace、流式显示假任务、
请求审批、展示 Diff，并在重启后恢复；Linux CI 至少能够构建和启动窗口。

### Phase 1：共享内核与新应用边界

- 把根 crate 中可复用的 Agent Engine、LLM、工具执行和任务状态收敛到稳定的
  application/runtime API；
- 建立 `microclaw-server` 和 `microclaw-work` 两个 binary/application 入口；
- 定义 Work Task、Plan、Progress、Approval、File Change、Artifact 等领域类型；
- 建立 command + projection + bounded event stream，UI 不直接调用 Agent Engine；
- 建立新配置 schema、数据迁移命令和 Server feature 分层骨架；
- 保持现有安全、恢复和 completion contract 测试覆盖。

验收标准：Server 通过新边界完成现有 headless prompt；无 GPUI 的 Work harness
可以运行一个任务、订阅事件、暂停、取消并恢复，且没有复制 Agent Loop。

### Phase 2：Work 纵向闭环

- 完成“打开项目到交付产物”的单一闭环；
- 建立 Work Application Service 和 UI projection，不复制 Agent Engine；
- 完成 macOS 和 Windows 安装、升级、诊断与崩溃恢复；
- Linux 提供开发预览和持续构建。

验收标准：新用户能够安装、配置模型、打开真实仓库、完成一次带审批和 Diff 的
任务并看到验证结果；退出和崩溃后能够恢复。

### Phase 3：Server 大版本边界

- 拆分 Core、Standard 和 Optional adapters；
- 产品化命名 Agent、隔离权限和少量团队模板；
- 保持 Web 管理端，精简默认渠道和依赖；
- 发布兼容、弃用和迁移说明。

验收标准：Lite/Standard 构建边界真实生效；旧数据可迁移或导出；被移出默认包
的渠道仍能按文档安装；Server 的调度、恢复、投递和 Web 管理可用。

### Phase 4：Work ↔ Server 与自有 Cloud

- 设备配对、远程任务和委派；
- Docker Compose、一键部署、备份和升级；
- PWA 的通知、状态、审批和聊天；
- 根据实际数据决定是否需要托管控制面。

验收标准：Work 能把任务交给用户自有 Server、查看实时状态、取消并接收产物；
权限、预算和凭据范围在委派过程中可见且可审计。

### Phase 5：三端发布与稳定化

- macOS 签名、公证、DMG 和升级；
- Windows 签名安装、升级、Defender/SmartScreen 和高 DPI 验证；
- Linux 根据 Phase 0–4 的维护证据决定正式支持或继续 Preview；
- 完成安装、首次任务、恢复、升级和卸载的端到端测试；
- 完成性能、内存、GPU、长任务和大事件流测试；
- 发布大版本迁移指南和稳定版本。

验收标准：macOS、Windows 达到正式发布质量；Linux 的支持等级有明确结论；
Server 和 Work 均可独立安装运行，也能通过稳定协议协作。

粗略周期：Phase 0 约 2 周，Phase 1 约 4–6 周，Phase 2 约 6–8 周，Phase 3
约 4–6 周，Phase 4 约 4–6 周，Phase 5 约 3–4 周。阶段可以部分重叠，但不能
绕过各自验收门槛。实际周期取决于 GPUI 的 Windows/IME 成熟度和现有 Agent
Engine 从根 crate 抽离的复杂度。

## 八、第一阶段之后暂不承诺的内容

在 Work 纵向闭环完成前，暂不开发完整 IDE、任意 Multi-Agent 画布、插件商城、
原生移动运行时、多租户 SaaS 和新增低频渠道。允许在大版本中删除旧 API，并不
意味着可以同时扩大产品范围。

## 九、关键决策门槛

在进入开发前，需要先回答：

- GPUI 在 Windows、中文 IME、无障碍和旧 GPU 上是否达到发布标准？
- 哪些 Server 渠道有真实用户，哪些只是增加构建和维护成本？
- Work 的本地 loop 与 Server 的持久 loop 共享到哪一层，边界是否可测试？
- 首个 Work 闭环是否比新增功能更能提高安装完成率和七日留存？
- Linux 应是首发正式支持，还是先以社区预览降低同时交付三端的风险？

当前已进入分阶段开发。任何大规模重构仍必须服务于对应阶段的验收标准，不能以
“大版本无需兼容”为由绕过数据安全、权限边界和可验证的运行结果。
