# MicroClaw Work：桌面端与服务端双产品提案

状态：**提案** · 日期：**2026-08-25**

本文是 [`product-direction-2026-08.md`](./product-direction-2026-08.md) 的中文提案摘要，
用于讨论下一次大版本的产品边界。它不代表已经批准开发，也不承诺具体发布日期。

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

## 六、实施顺序

### Phase 0：提案和技术验证

- 讨论并确认 Work/Server 产品边界；
- 用两周 GPUI Spike 验证 macOS、Windows，并保持 Linux 编译验证；
- 验证中文 IME、无障碍、GPU、流式内容、长列表、Diff、恢复和签名打包；
- 固定 GPUI/GPUI Component revision，用适配 crate 隔离上游变化；
- 统计 Server 集成的使用、体积和维护成本。

### Phase 1：Work 纵向闭环

- 完成“打开项目到交付产物”的单一闭环；
- 建立 Work Application Service 和 UI projection，不复制 Agent Engine；
- 完成 macOS 和 Windows 安装、升级、诊断与崩溃恢复；
- Linux 提供开发预览和持续构建。

### Phase 2：Server 大版本边界

- 拆分 Core、Standard 和 Optional adapters；
- 产品化命名 Agent、隔离权限和少量团队模板；
- 保持 Web 管理端，精简默认渠道和依赖；
- 发布兼容、弃用和迁移说明。

### Phase 3：Work ↔ Server 与自有 Cloud

- 设备配对、远程任务和委派；
- Docker Compose、一键部署、备份和升级；
- PWA 的通知、状态、审批和聊天；
- 根据实际数据决定是否需要托管控制面。

## 七、关键决策门槛

在进入开发前，需要先回答：

- GPUI 在 Windows、中文 IME、无障碍和旧 GPU 上是否达到发布标准？
- 哪些 Server 渠道有真实用户，哪些只是增加构建和维护成本？
- Work 的本地 loop 与 Server 的持久 loop 共享到哪一层，边界是否可测试？
- 首个 Work 闭环是否比新增功能更能提高安装完成率和七日留存？
- Linux 应是首发正式支持，还是先以社区预览降低同时交付三端的风险？

在这些门槛通过前，本提案只推进讨论、原型和测量，不启动大规模重构。
