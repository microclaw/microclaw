# MicroClaw

[English](README.md) | [中文](README_CN.md)

[![Website](https://img.shields.io/badge/Website-microclaw.ai-blue)](https://microclaw.ai)
[![Discord](https://img.shields.io/badge/Discord-Join-5865F2?logo=discord&logoColor=white)](https://discord.gg/pvmezwkAk5)
[![Reddit](https://img.shields.io/badge/Reddit-r%2Fmicroclaw-FF4500?logo=reddit&logoColor=white)](https://www.reddit.com/r/microclaw/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)


<p align="center">
  <img src="screenshots/headline.png" alt="MicroClaw headline logo" width="92%" />
</p>

<p align="center">
  <strong>一个可运行在 Telegram、Discord、Slack、飞书、IRC、Web 等渠道上的统一智能体运行时。</strong><br />
  支持多步工具调用、持久化记忆、定时任务、技能系统、MCP，以及本地 Web 控制台。
</p>

<p align="center">
  <a href="#快速开始">快速开始</a> |
  <a href="#安装">安装</a> |
  <a href="#为什么选择-microclaw">为什么选择 MicroClaw</a> |
  <a href="#工作原理">架构</a> |
  <a href="#文档">文档</a>
</p>

<p align="center">
  <strong>快速入口：</strong>
  <a href="docs/generated/tools.md">工具参考</a> ·
  <a href="docs/generated/config-defaults.md">配置默认值</a> ·
  <a href="docs/generated/provider-matrix.md">Provider 矩阵</a> ·
  <a href="docs/operations/runbook.md">运行手册</a> ·
  <a href="docs/operations/http-hook-trigger.md">Web Hook</a> ·
  <a href="docs/clawhub/overview.md">ClawHub</a>
</p>

MicroClaw 是一个面向聊天渠道的智能体运行时。它提供统一的渠道无关 agent loop、provider 无关的 LLM 抽象层，以及可以跨 Telegram、Discord、Slack、飞书/Lark、IRC、Web 等渠道复用的持久化运行时。

它支持 Anthropic 和 OpenAI-compatible provider，具备多步工具调用、跨轮次会话恢复、持久化记忆、定时任务，以及同时通过聊天渠道和本地 Web UI 暴露同一套运行时能力。


<p align="center">
  <img src="screenshots/screenshot1.png" width="45%" />
  &nbsp;&nbsp;
  <img src="screenshots/screenshot2.png" width="45%" />
</p>

## 为什么选择 MicroClaw

- **一套运行时，多种渠道复用**：同一套 agent loop、工具、记忆和策略可以跨聊天平台工作。
- **为 agentic execution 而设计**：工具调用、工具结果反思、子代理、任务规划和中间进度消息都是一等能力。
- **默认持久化**：会话可恢复、记忆可跨重启保留、定时任务可长期后台运行。
- **Provider 无锁定**：可接 Anthropic 或 OpenAI-compatible API，不需要重写运行时。
- **关键扩展点完整**：技能、MCP、插件、Hook、新平台适配器都能在不替换核心的情况下接入。

## 快速开始

安装：

```sh
curl -fsSL https://microclaw.ai/install.sh | bash
```

运行诊断：

```sh
microclaw doctor
```

使用交互式向导生成配置：

```sh
microclaw setup
```

启动运行时：

```sh
microclaw start
```

默认本地 Web UI：

```text
http://127.0.0.1:10961
```

如果你想看源码安装方式，直接跳到 [安装](#安装)。如果你更关心部署和运维，建议先看 [配置](#配置) 和 [文档](#文档)。

## 安装

### 一键安装（推荐）

```sh
curl -fsSL https://microclaw.ai/install.sh | bash
```

### Windows PowerShell 安装

```powershell
iwr https://microclaw.ai/install.ps1 -UseBasicParsing | iex
```

安装脚本仅执行一种方式：
- 从最新 GitHub Release 下载匹配平台的预编译二进制
- 不在 `install.sh` 内回退到 Homebrew/Cargo（请使用下面的独立方式）

后续可直接原地升级：

```sh
microclaw upgrade
```

### 预检诊断（doctor）

在首次启动或排障时，先运行跨平台诊断：

```sh
microclaw doctor
```

如果要提交支持工单，建议附加机器可读输出：

```sh
microclaw doctor --json
```

会检查：PATH、shell 运行时、`agent-browser`、Windows PowerShell 执行策略、以及 `<data_dir>/mcp.json` + `<data_dir>/mcp.d/*.json` 里的 MCP 依赖。

仅沙箱诊断：

```sh
microclaw doctor sandbox
```

### 卸载（脚本）

macOS/Linux：

```sh
curl -fsSL https://microclaw.ai/uninstall.sh | bash
```

Windows PowerShell：

```powershell
iwr https://microclaw.ai/uninstall.ps1 -UseBasicParsing | iex
```

### Homebrew (macOS)

```sh
brew tap microclaw/tap
brew install microclaw
```

### Docker 镜像

Release tag 会发布官方容器镜像到：

- `ghcr.io/microclaw/microclaw:latest`
- `ghcr.io/microclaw/microclaw:<版本号>`
- `docker.io/microclaw/microclaw:latest`，前提是仓库已配置 Docker Hub 发布凭据

第一次从 GHCR 拉取时，可能需要先登录：

```sh
docker login ghcr.io
```

用户名填 GitHub 用户名，密码填带 `read:packages` 权限的 Personal Access Token。

如果你只是想先确认镜像能跑，最短命令是：

```sh
docker pull ghcr.io/microclaw/microclaw:latest
docker run --rm -it \
  -p 127.0.0.1:10961:10961 \
  ghcr.io/microclaw/microclaw:latest
```

如果你准备长期使用，推荐把配置和运行时数据挂载到宿主机：

```sh
mkdir -p data tmp
chmod a+r microclaw.config.yaml
chmod -R a+rwX data tmp

docker run --rm -it \
  -p 127.0.0.1:10961:10961 \
  -v "$(pwd)/microclaw.config.yaml:/app/microclaw.config.yaml:ro" \
  -v "$(pwd)/data:/home/microclaw/.microclaw" \
  -v "$(pwd)/tmp:/app/tmp" \
  ghcr.io/microclaw/microclaw:latest
```

这三个挂载分别用于：

- `microclaw.config.yaml`：把配置保留在容器外，方便修改
- `data/`：持久化数据库、会话、记忆、技能和运行时数据
- `tmp/`：给容器内临时文件一个明确的可写目录

镜像入口是 `microclaw`，因此可以直接覆盖子命令：

```sh
docker run --rm ghcr.io/microclaw/microclaw:latest doctor
docker run --rm ghcr.io/microclaw/microclaw:latest version
```

如果启动时报 `Permission denied (os error 13)`，优先检查上面的 `chmod` 是否执行过，以及挂载路径是否存在。

### 从源码构建

```sh
git clone https://github.com/microclaw/microclaw.git
cd microclaw
cargo build --release
cp target/release/microclaw /usr/local/bin/
```

可选语义记忆构建（默认关闭 sqlite-vec）：

```sh
cargo build --release --features sqlite-vec
```

首次启用 sqlite-vec（最短 3 条命令）：

```sh
cargo run --features sqlite-vec -- setup
cargo run --features sqlite-vec -- start
sqlite3 <data_dir>/runtime/microclaw.db "SELECT id, chat_id, chat_channel, external_chat_id, category, embedding_model FROM memories ORDER BY id DESC LIMIT 20;"
```

在 `setup` 里至少设置：
- `embedding_provider` = `openai` 或 `ollama`
- 对应 provider 的 key/base URL/model

## 工作原理

每条消息都会进入统一的 **agent loop**：

1. 加载文件记忆、结构化记忆、技能和可恢复的会话状态
2. 使用工具 schema 和运行时上下文调用所配置的模型
3. 执行工具调用，追加结果，并持续循环直到任务结束
4. 持久化更新后的会话、记忆信号和可观测性数据

这样可以让交互式聊天、定时任务、Web 触发自动化、子代理执行等能力共享同一套运行时行为。

<p align="center">
  <img src="docs/assets/readme/microclaw-architecture.svg" alt="MicroClaw 架构总览" width="96%" />
</p>

## 博客文章

关于项目架构与设计取舍的介绍文章：**[Building MicroClaw: An Agentic AI Assistant in Rust That Lives in Your Chats](https://microclaw.ai/blog/building-microclaw)**

## 功能特性

- **智能体工具调用** -- bash 命令、文件读写编辑、glob 搜索、正则 grep、持久化记忆
- **会话恢复** -- 完整对话状态（包括工具交互）持久化保存；模型可跨调用延续工具调用状态
- **上下文压缩** -- 会话过长时自动总结旧消息，保持在上下文限制内
- **子代理** -- 将独立子任务委派给有限制工具集的并行代理
- **技能系统** -- 可扩展的技能系统（兼容 [Anthropic Skills](https://github.com/anthropics/skills) 标准）；技能从 `<data_dir>/skills/` 自动发现，按需激活
- **计划与执行** -- todo 工具，将复杂任务拆解为步骤，逐步跟踪进度
- **可扩展的平台架构** -- 共享智能体循环/工具系统/存储层，通过平台适配器处理各渠道差异
- **网页搜索** -- 通过 DuckDuckGo 搜索和抓取网页
- **定时任务** -- 基于 cron 的循环任务和一次性定时任务，通过自然语言管理
- **会话中发消息** -- 智能体可以在最终回复前发送中间进度消息
- **提及追赶（Telegram 群）** -- 在 Telegram 群里被 @ 时，机器人会读取上次回复以来的所有消息
- **持续输入指示** -- 处理期间持续显示"正在输入"状态
- **持久化记忆** -- 全局、bot/账号级、每聊天三级 AGENTS.md 文件，每次请求都会加载
- **消息分割** -- 长回复自动在换行处分割，适配不同平台长度限制（Telegram 4096 / Discord 2000 / Slack 4000 / 飞书 4000）

## 工具列表

| 工具                    | 描述                                                                                 |
| ----------------------- | ------------------------------------------------------------------------------------ |
| `bash`                  | 执行 Shell 命令，可配置超时                                                          |
| `read_file`             | 读取文件，带行号，支持偏移/限制                                                      |
| `write_file`            | 创建或覆盖文件（自动创建目录）                                                       |
| `edit_file`             | 查找替换编辑，带唯一性验证                                                           |
| `glob`                  | 按模式查找文件（`**/*.rs`、`src/**/*.ts`）                                           |
| `grep`                  | 正则搜索文件内容                                                                     |
| `read_memory`           | 读取持久化 AGENTS.md 记忆（`global` / `bot` / `chat`）                               |
| `write_memory`          | 写入持久化 AGENTS.md 记忆                                                            |
| `web_search`            | 通过 DuckDuckGo 搜索（返回标题、URL、摘要）                                          |
| `web_fetch`             | 抓取 URL 并返回纯文本（去 HTML，最大 20KB）                                          |
| `send_message`          | 会话中发送消息；支持 Telegram/Discord/Slack/Weixin 附件发送（`attachment_path` + 可选 `caption`） |
| `schedule_task`         | 创建循环（cron）或一次性定时任务                                                     |
| `list_scheduled_tasks`  | 列出聊天的所有活跃/暂停任务                                                          |
| `pause_scheduled_task`  | 暂停定时任务                                                                         |
| `resume_scheduled_task` | 恢复已暂停的任务                                                                     |
| `cancel_scheduled_task` | 永久取消任务                                                                         |
| `get_task_history`      | 查看定时任务的执行历史                                                               |
| `export_chat`           | 导出聊天记录为 markdown                                                              |
| `sub_agent`             | 委派子任务给有限制工具集的并行代理                                                   |
| `activate_skill`        | 激活技能以加载专业指令                                                               |
| `sync_skills`           | 从外部技能仓库（如 vercel-labs/skills）同步技能并规范化本地 frontmatter              |
| `todo_read`             | 读取当前聊天的任务/计划列表                                                          |
| `todo_write`            | 创建或更新聊天的任务/计划列表                                                        |

## 记忆系统

<p align="center">
  <img src="docs/assets/readme/memory-architecture.svg" alt="MicroClaw 记忆架构图" width="92%" />
</p>

MicroClaw 通过 `AGENTS.md` 文件维护持久化记忆：

```
<data_dir>/runtime/groups/
    AGENTS.md                 # 全局记忆（所有聊天共享）
    {channel}/
        AGENTS.md             # 该渠道下 bot/账号级记忆
        {chat_id}/
            AGENTS.md         # 每聊天记忆（按渠道隔离）
```

记忆在每次请求时加载到系统提示中。模型可以通过工具读写记忆 -- 告诉它"记住我喜欢用 Python"，它就会跨会话保存。

另外，MicroClaw 也会把结构化记忆写入 SQLite（`memories` 表）：
- `write_memory` 会同时写入文件记忆与结构化记忆
- 后台 Reflector 会增量提取长期事实并去重
- 对“记住……”类显式指令走确定性快速路径（直接结构化 upsert）
- 写入前有质量闸门，过滤低信息量/不确定表达
- 结构化记忆具备置信度与软归档生命周期（不再只依赖硬删除）

当使用 `--features sqlite-vec` 构建且配置了 embedding 参数时，结构化记忆的检索和去重会使用语义 KNN；否则自动回退为关键词排序 + Jaccard 去重。

`/usage` 现在包含 **Memory Observability**（Web UI 也有可视化面板），可查看：
- 记忆池健康度（active/archived/low-confidence）
- Reflector 24h 吞吐（insert/update/skip）
- 注入覆盖率（selected/candidates）

### 聊天身份映射（channel + chat id）

MicroClaw 现在会保存“按渠道隔离”的聊天身份：

- `internal chat_id`：SQLite 内部主键（用于 sessions/messages/tasks）
- `channel + external_chat_id`：来自 Telegram/Discord/Slack/飞书/Weixin/IRC/Web 的源聊天身份

这样可避免不同渠道使用相同数字 id 时发生冲突。历史数据会在启动时自动迁移补齐。

排查时建议用以下 SQL：

```sql
SELECT chat_id, channel, external_chat_id, chat_type, chat_title
FROM chats
ORDER BY last_message_time DESC
LIMIT 50;

SELECT id, chat_id, chat_channel, external_chat_id, category, content, embedding_model
FROM memories
ORDER BY id DESC
LIMIT 50;
```

## 技能系统

<p align="center">
  <img src="docs/assets/readme/skills-lifecycle.svg" alt="MicroClaw 技能生命周期图" width="92%" />
</p>

MicroClaw 支持 [Anthropic Agent Skills](https://github.com/anthropics/skills) 标准。技能是为特定任务提供专业能力的模块化包。

```
<data_dir>/skills/
    pdf/
        SKILL.md              # 必需：name、description + 指令
    docx/
        SKILL.md
```

**工作方式：**
1. 技能元数据（名称 + 描述）始终在系统提示中（每个技能约 100 token）
2. 当模型判断某技能相关时，调用 `activate_skill` 加载完整指令
3. 模型按技能指令完成任务

**内置技能：** pdf、docx、xlsx、pptx、skill-creator、apple-notes、apple-reminders、apple-calendar、weather

**新增 macOS 相关技能（示例）：**
- `apple-notes` -- 通过 `memo` 管理 Apple Notes
- `apple-reminders` -- 通过 `remindctl` 管理 Apple Reminders
- `apple-calendar` -- 通过 `icalBuddy` + `osascript` 查询/创建日历事件
- `weather` -- 通过 `wttr.in` 快速查询天气

**添加技能：** 在 `<data_dir>/skills/` 下创建子目录，放入包含 YAML frontmatter（`name` 和 `description`）和 markdown 指令的 `SKILL.md` 文件。

**命令：**
- `/stop` -- 中止当前聊天正在执行的 run（保留历史/会话数据）
- `/clear` -- 清除当前聊天上下文（会话 + 聊天历史），保留定时任务
- `/reset` -- 清除当前聊天上下文（会话 + 聊天历史）并清空定时任务状态
- `/skills` -- 列出所有可用技能
- `/reload-skills` -- 从磁盘重新加载技能
- `/archive` -- 将当前内存会话归档为 markdown
- `/usage` -- 查看 token 用量统计（当前聊天 + 全局汇总）
- `/status` -- 查看 provider/model 和当前聊天会话/任务状态
- `/providers` -- 列出已配置的 provider profile，并标出当前生效项
- `/provider` -- 查看当前 provider/model（`/provider <profile>` 可切换当前 channel 到该 profile，并持久化到配置文件；`/provider reset` 可清除）
- `/models` -- 列出当前 provider 的已配置 model（`/models api` 在支持时拉取 provider 实时模型列表）
- `/model` -- 查看当前 provider/model（`/model <name>` 可切换当前 channel 的 model override，并持久化到配置文件；`/model reset` 可清除）

命令处理规则：
- 以 `/` 开头的输入会被识别为命令。
- 支持“前置提及 + slash”形式（例如 `@bot /status`、`<@U123> /status`）。
- slash 命令不会写入 agent 会话上下文。
- 未知 slash 命令返回 `Unknown command.`。
- 需要中断正在执行的请求时用 `/stop`；仅清空上下文用 `/clear`；清空上下文并重置定时任务用 `/reset`。

## MCP

MicroClaw 支持从以下位置加载 MCP 配置并合并：

- `<data_dir>/mcp.json`
- `<data_dir>/mcp.d/*.json`（按文件名顺序覆盖前者）

推荐做法：

```sh
cp mcp.minimal.example.json <data_dir>/mcp.json
```

旁路/sidecar 集成（例如 HAPI bridge）建议单独放分片配置：

```sh
mkdir -p <data_dir>/mcp.d
cp mcp.hapi-bridge.example.json <data_dir>/mcp.d/hapi-bridge.json
```

这样可以在不改 MicroClaw 核心 agent loop 的情况下，通过外部桥接服务扩展远程终端能力。

详细操作可见：`docs/operations/hapi-bridge.md`。

如果你要接入 Weixin 原生 Rust 模式，请看：
`docs/operations/weixin.md`。

### 在 macOS 上接入 Peekaboo MCP（桌面自动化）

[Peekaboo](https://github.com/steipete/Peekaboo) 是一个 macOS 桌面自动化 MCP server。MicroClaw 可通过 `stdio` 直接接入（无需修改运行时代码）。

```sh
mkdir -p <data_dir>/mcp.d
cp mcp.peekaboo.example.json <data_dir>/mcp.d/peekaboo.json
```

`mcp.peekaboo.example.json`：

```json
{
  "mcpServers": {
    "peekaboo": {
      "transport": "stdio",
      "command": "npx",
      "args": ["-y", "peekaboo-mcp@latest"]
    }
  }
}
```

### Windows 上的类似方案

MicroClaw 也可以通过 `stdio` 接入 Windows 桌面自动化 MCP server：

```sh
mkdir -p <data_dir>/mcp.d
cp mcp.windows.desktop.example.json <data_dir>/mcp.d/windows-desktop.json
```

`mcp.windows.desktop.example.json` 包含：
- `pywinauto`（Windows 原生桌面 UI 自动化，stdio MCP）
- 可选 `playwright` MCP（Windows 浏览器自动化）

注意：部分 Windows MCP 项目只提供 `sse` transport。MicroClaw 当前仅直接支持 `stdio` 与 `streamable_http`，SSE-only 服务需先通过协议桥接后再接入。

## 计划与执行

<p align="center">
  <img src="docs/assets/readme/plan-execute.svg" alt="MicroClaw 计划执行流程图" width="92%" />
</p>

对于复杂的多步骤任务，机器人可以创建计划并跟踪进度：

```
你: 搭建一个新的 Rust 项目，配好 CI、测试和文档
Bot: [创建 todo 计划，然后逐步执行，更新进度]

1. [x] 创建项目结构
2. [x] 添加 CI 配置
3. [~] 编写单元测试
4. [ ] 添加文档
```

Todo 列表存储在 `<data_dir>/runtime/groups/{chat_id}/TODO.json`，跨会话持久化。

## 定时任务

<p align="center">
  <img src="docs/assets/readme/task-scheduler.svg" alt="MicroClaw 定时任务流程图" width="92%" />
</p>

机器人支持通过自然语言管理定时任务：

- **循环任务：** "每 30 分钟提醒我检查日志" -- 创建 cron 任务
- **一次性：** "下午 5 点提醒我给 Alice 打电话" -- 创建一次性任务

底层使用 6 字段 cron 表达式（秒 分 时 日 月 周）。调度器每 60 秒轮询到期任务，运行智能体循环处理任务提示，并将结果发送到对应聊天。

管理任务：
```
"列出我的定时任务"
"暂停任务 #3"
"恢复任务 #3"
"取消任务 #3"
```

## 本地 Web UI（跨渠道历史）

当 `web_enabled: true` 时，MicroClaw 会启动本地 Web UI（默认 `http://127.0.0.1:10961`）。

- 左侧会话列表会展示 SQLite 中所有渠道聊天（`telegram`、`discord`、`slack`、`feishu`、`irc`、`web`）
- 支持历史查看与管理（刷新 / 清理上下文 / 删除）
- 默认对非 `web` 渠道是只读（发送请在原渠道进行）
- 如果当前没有会话，Web UI 会自动生成一个 `session-YYYYMMDDHHmmss` 格式的会话键
- 在该会话发送第一条消息后，会自动持久化到 SQLite

### HTTP 请求触发（自动化 / 无头调用）

如果要让外部系统（Webhook、CI、脚本）主动触发 agent，可使用 Web API，并配置带
`operator.write` scope 的 API key。

详细说明见：[`docs/operations/http-hook-trigger.md`](docs/operations/http-hook-trigger.md)

可用端点：
- `POST /api/send`（主端点）
- `POST /api/chat`（聊天客户端风格别名）
- `POST /api/send_stream`（异步运行 + SSE 回放）
- `POST /api/chat_stream`（聊天客户端风格别名）
- `GET /` 在 WebSocket Upgrade 请求下作为 Mission Control / OpenClaw 风格 WebSocket bridge
- `POST /hooks/agent` 与 `POST /api/hooks/agent`（兼容 OpenClaw webhook 请求体）
- `POST /hooks/wake` 与 `POST /api/hooks/wake`（系统事件唤醒，支持 `now` 或 `next-heartbeat`）

Hook 鉴权与策略（`channels.web`）：
```yaml
channels:
  web:
    hooks_token: "replace-with-secret"
    hooks_default_session_key: "hook:ingress"
    hooks_allow_request_session_key: false
    hooks_allowed_session_key_prefixes: ["hook:"]
```

说明：
- `/hooks/*` 需要独立 hook token（`Authorization: Bearer <token>` 或 `x-openclaw-token`）。
- 请求体里的 `sessionKey` 默认拒绝；只有 `hooks_allow_request_session_key: true` 才允许。
- 若允许外部传 `sessionKey`，建议同时配置前缀白名单，避免任意会话路由。

请求体：
```json
{
  "session_key": "ops-bot",
  "sender_name": "automation",
  "message": "检查最近 1 小时错误预算并汇总事故。"
}
```

同步返回（`/api/send` 或 `/api/chat`）：
```json
{
  "ok": true,
  "session_key": "ops-bot",
  "chat_id": 123,
  "response": "..."
}
```

异步返回（`/api/send_stream` 或 `/api/chat_stream`）：
```json
{
  "ok": true,
  "run_id": "6f4c2b1d-...",
  "session_key": "ops-bot",
  "chat_id": 123
}
```

SSE 消费示例：
```sh
curl -N "http://127.0.0.1:10961/api/stream?run_id=<RUN_ID>" \
  -H "Authorization: Bearer $MICROCLAW_API_KEY"
```

Mission Control / OpenClaw 风格 WebSocket bridge：

1. 连接 `ws://127.0.0.1:10961/`
2. 等待 `connect.challenge`
3. 发送 `connect` 帧，并在 `params.auth.token` 中带上 operator API key
4. 可调用 `chat.send`、`sessions_send`、`sessions_kill`、`sessions_spawn`、`session_set*` 等方法
5. 消费实时 `chat` 事件（`delta` / `final` / `error`）

当前 bridge 方法：

- `health`
- `status`
- `chat.send`
- `chat.history`
- `session_delete`
- `sessions_send`
- `sessions_kill`
- `sessions_spawn`
- `session_setThinking`
- `session_setVerbose`
- `session_setReasoning`
- `session_setLabel`
- `agents.list`
- `models.list`
- `config.get`
- `node.list`

连接示例：

```json
{
  "type": "req",
  "id": "connect-1",
  "method": "connect",
  "params": {
    "minProtocol": 3,
    "maxProtocol": 3,
    "auth": { "token": "mc_..." }
  }
}
```

发送消息示例：

```json
{
  "type": "req",
  "id": "send-1",
  "method": "chat.send",
  "params": {
    "sessionKey": "ops-bot",
    "message": "请总结当前仓库",
    "idempotencyKey": "idem-1"
  }
}
```

创建会话示例：

```json
{
  "type": "req",
  "id": "spawn-1",
  "method": "sessions_spawn",
  "params": {
    "task": "请总结当前仓库",
    "label": "Ops"
  }
}
```

设置会话标签示例：

```json
{
  "type": "req",
  "id": "label-1",
  "method": "session_setLabel",
  "params": {
    "sessionKey": "ops-bot",
    "label": "Ops"
  }
}
```

行为说明：

- bridge 的 WebSocket 路径是根路径 `GET /`，不是 `/ws`。
- `sessions_send` 会立即返回 `runId`，随后持续发送 `chat` 事件，并在普通消息完成后发出终态 `final`。
- `sessions_spawn` 会创建新的异步会话，并可先持久化初始标签。
- `session_set*` 只更新当前请求提供的字段，不会覆盖其它已存储的 session 设置。
- `sessions_send` 的 control payload 当前会被确认接收，但还不会真的改变运行时控制状态。

本地 gateway 冒烟测试：

```sh
MICROCLAW_GATEWAY_TOKEN=mc_... microclaw gateway call health
MICROCLAW_GATEWAY_TOKEN=mc_... microclaw gateway call status
MICROCLAW_GATEWAY_TOKEN=mc_... microclaw gateway call session_setLabel \
  --params '{"sessionKey":"ops-bot","label":"Ops"}'
MICROCLAW_GATEWAY_TOKEN=mc_... microclaw gateway call sessions_send \
  --params '{"sessionKey":"ops-bot","message":"请给出状态摘要"}'
```

`microclaw gateway call` 会按以下优先级读取连接配置：

- `MICROCLAW_GATEWAY_URL`、`OPENCLAW_GATEWAY_URL`、`GATEWAY_URL`
- `MICROCLAW_GATEWAY_HOST`、`OPENCLAW_GATEWAY_HOST`、`GATEWAY_HOST`
- `MICROCLAW_GATEWAY_PORT`、`OPENCLAW_GATEWAY_PORT`、`GATEWAY_PORT`
- `MICROCLAW_GATEWAY_TOKEN`、`OPENCLAW_GATEWAY_TOKEN`、`GATEWAY_TOKEN`、`MICROCLAW_API_KEY`

调用示例：
```sh
curl -sS http://127.0.0.1:10961/api/chat \
  -H "Authorization: Bearer $MICROCLAW_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"session_key":"ops-bot","sender_name":"automation","message":"请给出状态摘要"}'
```

OpenClaw 风格 webhook 请求体示例：
```sh
curl -sS http://127.0.0.1:10961/hooks/agent \
  -H "Authorization: Bearer $MICROCLAW_HOOKS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message":"Summarize inbox","name":"Email","sessionKey":"hook:email:msg-123"}'
```

Wake 示例：
```sh
curl -sS http://127.0.0.1:10961/hooks/wake \
  -H "Authorization: Bearer $MICROCLAW_HOOKS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"text":"New email received","mode":"now"}'
```

## 发布

一条命令同时发布安装脚本模式（GitHub Release 资产）和 Homebrew 模式：

```sh
./deploy.sh
```

Nixpkgs 上游/更新流程参考：
- `docs/releases/nixpkgs-upstream-guide.md`

## 配置

> **新功能：** 现在支持交互式问答配置（`microclaw config`），并且在 `start` 时若缺少必需配置会自动进入配置流程。

### 1. 创建渠道机器人凭据

至少启用一个渠道，或使用 Web UI（默认开启）。

Telegram（可选）：
1. 打开 Telegram，搜索 [@BotFather](https://t.me/BotFather)
2. 发送 `/newbot`
3. 输入机器人的显示名称（例如 `My MicroClaw`）
4. 输入用户名（必须以 `bot` 结尾，例如 `my_microclaw_bot`）
5. BotFather 会回复一个 token，类似 `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`，保存为 `telegram_bot_token`

推荐的 BotFather 设置（可选但有用）：
- `/setdescription` -- 设置机器人简介，显示在机器人资料页
- `/setcommands` -- 注册命令，用户可以在菜单中看到：
  ```
  reset - 清除当前会话
  status - 查看运行/会话状态
  model - 查看当前 provider/model
  skills - 查看可用技能列表
  usage - 查看用量统计
  ```
- `/setprivacy` -- 设置为 `Disable`，这样机器人可以看到群里所有消息（而不仅仅是 @提及）

Discord（可选）：
1. 打开 [Discord Developer Portal](https://discord.com/developers/applications)
2. 创建应用并添加 Bot
3. 复制 Bot token，保存为 `discord_bot_token`
4. 邀请 Bot 进入服务器，并授予发送消息、读取历史、被提及响应等权限
5. 可选：配置 `discord_allowed_channels` 限制可回复频道

Slack（可选，Socket Mode）：
1. 在 [api.slack.com/apps](https://api.slack.com/apps) 创建应用
2. 启用 Socket Mode，获取 `app_token`（以 `xapp-` 开头）
3. 添加 `bot_token` 权限并安装到工作区，获取 `bot_token`（以 `xoxb-` 开头）
4. 订阅 `message` 和 `app_mention` 事件
5. 在配置文件的 `channels.slack` 下配置

飞书/Lark（可选）：
1. 在[飞书开放平台](https://open.feishu.cn/app)创建应用（国际版使用 [Lark Developer](https://open.larksuite.com/app)）
2. 在应用凭证页获取 `app_id` 和 `app_secret`
3. 开启 `im:message` 和 `im.message.receive_v1` 事件订阅
4. 选择连接方式：WebSocket 长连接（默认，无需公网地址）或 Webhook
5. 在配置文件的 `channels.feishu` 下配置；国际版设置 `domain: "lark"`

IRC（可选）：
1. 准备 IRC 服务器地址、端口和机器人昵称
2. 在配置文件 `channels.irc` 下配置（`server`、`nick`、`channels` 必填）
3. 可选：设置 `tls: "true"` 启用 TLS，并按需配置 `tls_server_name`
4. 可选：设置 `mention_required: "false"`，让机器人在频道中无需提及也可回复

### 2. 获取 LLM API Key

选择一个 provider 并创建 API key：
- Anthropic: [console.anthropic.com](https://console.anthropic.com/)
- OpenAI: [platform.openai.com](https://platform.openai.com/)
- 或任意 OpenAI 兼容 provider（OpenRouter、DeepSeek 等）
- 对于 `openai-codex`，可使用 OAuth（`codex login`）或 API key（用于 OpenAI 兼容代理端点）

### 3. 配置（推荐：交互式问答）

```sh
microclaw config
```

<!-- setup 向导截图占位，后续替换为真实图片 -->
![Setup 向导（占位）](screenshots/setup-wizard.png)

`config` 流程提供：
- 一问一答式配置，所有字段都带默认值（可直接回车确认）
- provider/model 选择（编号选择 + 自定义覆盖）
- 更好的 Ollama 体验：自动探测本地模型 + 本地默认地址
- 安全写入 `microclaw.config.yaml`（自动备份）
- 自动创建 `data_dir` 和 `working_dir`

如果你更喜欢全屏 TUI，也可以继续用：

```sh
microclaw setup
```

向导内置 provider 预设：
- `openai`
- `openai-codex`（ChatGPT/Codex 订阅 OAuth，先运行 `codex login`）
- `openrouter`
- `anthropic`
- `ollama`
- `google`
- `alibaba`
- `deepseek`
- `moonshot`
- `mistral`
- `azure`
- `bedrock`
- `zhipu`
- `minimax`
- `cohere`
- `tencent`
- `xai`
- `huggingface`
- `together`
- `custom`（手动填写 provider/model/base URL）

对于 Ollama：`llm_base_url` 默认是 `http://127.0.0.1:11434/v1`，`api_key` 可留空，交互式配置会尝试自动发现本地已安装模型。

对于 `openai-codex`：你可以先运行 `codex login`，MicroClaw 会读取 `~/.codex/auth.json`（或 `$CODEX_HOME/auth.json`）里的 OAuth 凭据。也可以在使用 OpenAI 兼容中转端点时配置 `api_key`。默认 base URL 是 `https://chatgpt.com/backend-api`。

如果你更喜欢手工配置，也可以直接写 `microclaw.config.yaml`：

```
telegram_bot_token: "123456:ABC-DEF1234..."
bot_username: "my_bot"
llm_provider: "anthropic"
api_key: "sk-ant-..."
model: "claude-sonnet-4-20250514"
# 可选
# llm_base_url: "https://..."
data_dir: "~/.microclaw"
working_dir: "~/.microclaw/working_dir"
working_dir_isolation: "chat" # 可选；默认 chat
sandbox:
  mode: "off" # 可选；默认关闭。设为 "all" 可让 bash 在 docker 沙箱执行
max_document_size_mb: 100
memory_token_budget: 1500
timezone: "UTC"
# 可选语义记忆配置（需使用 --features sqlite-vec 构建）
# embedding_provider: "openai"   # openai | ollama
# embedding_api_key: "sk-..."
# embedding_base_url: "https://api.openai.com/v1"
# embedding_model: "text-embedding-3-small"
# embedding_dim: 1536
```

### 4. 运行

```sh
microclaw start
```

### 5. 作为常驻 gateway 服务运行（可选）

```sh
microclaw gateway install
microclaw gateway status
microclaw gateway status --json
```

服务生命周期管理：

```sh
microclaw gateway install --force
microclaw gateway start
microclaw gateway stop
microclaw gateway restart
microclaw gateway logs 200
microclaw gateway uninstall
```

说明：
- macOS 使用 `launchd` 用户级服务
- Linux 使用 `systemd --user`
- Windows 使用由 `microclaw.exe` 直接托管的原生 Windows Service。运行 `microclaw gateway install` 前，请先准备好 `microclaw.config.yaml`，并在管理员终端中执行 gateway 服务命令
- 运行日志写入 `<data_dir>/runtime/logs/`
- 日志按小时分片：`microclaw-YYYY-MM-DD-HH.log`
- 超过 30 天的日志会自动删除

## 配置项

所有配置都在 `microclaw.config.yaml` 中。

| 配置键                                         | 必需 | 默认值                     | 描述                                                                                                         |
| ---------------------------------------------- | ---- | -------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `telegram_bot_token`                           | 否*  | --                         | BotFather 的 Telegram bot token                                                                              |
| `discord_bot_token`                            | 否*  | --                         | Discord Bot token（来自 Discord Developer Portal）                                                           |
| `discord_allowed_channels`                     | 否   | `[]`                       | Discord 允许响应的频道 ID 列表；为空表示不限制                                                               |
| `api_key`                                      | 是*  | --                         | LLM API key（`ollama` 可留空；`openai-codex` 支持 OAuth 或 `api_key`）                                       |
| `bot_username`                                 | 否   | --                         | Telegram Bot 用户名（不带 @，仅 Telegram 群聊 @ 提及时需要）                                                 |
| `llm_provider`                                 | 否   | `anthropic`                | 提供方预设 ID（或自定义 ID）。`anthropic` 走原生 Anthropic API，其他走 OpenAI 兼容 API                       |
| `model`                                        | 否   | 随 provider 默认           | 模型名                                                                                                       |
| `channels.telegram.accounts.<id>.model`        | 否   | 未设置                     | Telegram 某个 bot 账号的模型覆盖（按 bot 生效）                                                              |
| `channels.discord.accounts.<id>.model`         | 否   | 未设置                     | Discord 某个 bot 账号的模型覆盖（按 bot 生效）                                                               |
| `channels.slack.accounts.<id>.model`           | 否   | 未设置                     | Slack 某个 bot 账号的模型覆盖（按 bot 生效）                                                                 |
| `channels.feishu.accounts.<id>.model`          | 否   | 未设置                     | 飞书/Lark 某个 bot 账号的模型覆盖（按 bot 生效）                                                             |
| `channels.irc.model`                           | 否   | 未设置                     | IRC bot 的模型覆盖                                                                                           |
| `allow_group_slash_without_mention`            | 否   | `false`                    | 为 `true` 时，群/频道中的 slash 命令可不提及机器人直接执行                                                   |
| `model_prices`                                 | 否   | `[]`                       | 可选模型价格表（每百万 token 的美元单价），用于 `/usage` 成本估算                                            |
| `llm_base_url`                                 | 否   | provider 预设默认值        | 自定义 API 基础地址                                                                                          |
| `data_dir`                                     | 否   | `~/.microclaw`             | 数据根目录（运行时数据在 `data_dir/runtime`，技能在 `data_dir/skills`）                                      |
| `working_dir`                                  | 否   | `~/.microclaw/working_dir` | 工具默认工作目录；`bash/read_file/write_file/edit_file/glob/grep` 的相对路径都以此为基准                     |
| `working_dir_isolation`                        | 否   | `chat`                     | 工具工作目录隔离模式：`shared` 使用 `working_dir/shared`，`chat` 使用 `working_dir/chat/<channel>/<chat_id>` |
| `high_risk_tool_user_confirmation_required`    | 否   | `true`                     | 高风险工具（例如 `bash`）执行前是否必须等待用户明确确认                                                      |
| `sandbox.mode`                                 | 否   | `off`                      | `bash` 工具的容器沙箱模式：`off` 在宿主执行；`all` 通过 docker 容器执行                                      |
| `sandbox.mount_allowlist_path`                 | 否   | 未设置                     | 可选外部挂载白名单文件（每行一个允许根路径）                                                                 |
| `max_tokens`                                   | 否   | `8192`                     | 每次模型回复的最大 token                                                                                     |
| `max_tool_iterations`                          | 否   | `100`                      | 每条消息的最大工具循环次数                                                                                   |
| `max_document_size_mb`                         | 否   | `100`                      | Telegram 入站文档允许的最大大小（MB）；超过会拒绝并提示                                                      |
| `memory_token_budget`                          | 否   | `1500`                     | 注入结构化记忆时使用的估算 token 预算                                                                        |
| `max_history_messages`                         | 否   | `50`                       | 作为上下文发送的历史消息数                                                                                   |
| `control_chat_ids`                             | 否   | `[]`                       | 可跨聊天执行操作的 chat_id 列表（send_message/定时/导出/全局记忆/todo）                                      |
| `max_session_messages`                         | 否   | `40`                       | 触发上下文压缩的消息数阈值                                                                                   |
| `compact_keep_recent`                          | 否   | `20`                       | 压缩时保留的最近消息数                                                                                       |
| `embedding_provider`                           | 否   | 未设置                     | 语义记忆 embedding provider（`openai` 或 `ollama`）；需要 `--features sqlite-vec` 构建                       |
| `embedding_api_key`                            | 否   | 未设置                     | embedding provider API key（`ollama` 可留空）                                                                |
| `embedding_base_url`                           | 否   | provider 默认              | embedding provider base URL 覆盖                                                                             |
| `embedding_model`                              | 否   | provider 默认              | embedding 模型 ID                                                                                            |
| `embedding_dim`                                | 否   | provider 默认              | sqlite-vec 索引使用的向量维度                                                                                |
| `channels.irc.server`                          | 否*  | 未设置                     | IRC 服务器地址（域名/IP）                                                                                    |
| `channels.irc.port`                            | 否   | `"6667"`                   | IRC 端口                                                                                                     |
| `channels.irc.nick`                            | 否*  | 未设置                     | IRC 机器人昵称                                                                                               |
| `channels.irc.username`                        | 否   | 未设置                     | IRC 用户名（默认同 nick）                                                                                    |
| `channels.irc.real_name`                       | 否   | `"MicroClaw"`              | IRC real name（USER 命令字段）                                                                               |
| `channels.irc.channels`                        | 否*  | 未设置                     | 逗号分隔的频道列表（例如 `#general,#ops`）                                                                   |
| `channels.irc.password`                        | 否   | 未设置                     | 可选 IRC 服务器密码                                                                                          |
| `channels.irc.mention_required`                | 否   | `"true"`                   | 频道中是否要求提及才回复                                                                                     |
| `channels.irc.tls`                             | 否   | `"false"`                  | 是否启用 IRC TLS                                                                                             |
| `channels.irc.tls_server_name`                 | 否   | 未设置                     | 可选 TLS SNI/服务名覆盖                                                                                      |
| `channels.irc.tls_danger_accept_invalid_certs` | 否   | `"false"`                  | 是否接受无效证书（仅测试）                                                                                   |

路径兼容策略：
- 如果用户已经在配置里设置了 `data_dir` / `skills_dir` / `working_dir`，会继续沿用原有路径。
- 如果未配置，则默认使用 `data_dir=~/.microclaw`、`skills_dir=<data_dir>/skills`、`working_dir=~/.microclaw/working_dir`。

`*` 需要至少启用一个渠道配置；`web_enabled` 默认是开启的。

## Docker 沙箱

用于让 `bash` 工具在 Docker 容器执行，而不是在宿主执行。

快速配置：

```sh
microclaw setup --enable-sandbox
microclaw doctor sandbox
```

或手工配置：

```yaml
sandbox:
  mode: "all"
  backend: "auto"
  image: "ubuntu:25.10"
  container_prefix: "microclaw-sandbox"
  no_network: true
  require_runtime: false
  # 可选外部白名单文件
  # mount_allowlist_path: "~/.microclaw/sandbox-mount-allowlist.txt"
```

测试步骤：

```sh
docker info
docker run --rm ubuntu:25.10 echo ok
microclaw start
```

然后让 agent 执行：
- `cat /etc/os-release`
- `pwd`

说明：
- `sandbox.mode: "off"`（默认）时，`bash` 在宿主执行。
- `mode: "all"` 但 Docker 不可用时：
  - `require_runtime: false`：降级宿主执行并告警。
  - `require_runtime: true`：直接报错，不降级。
- 可选加固：
  - `~/.microclaw/sandbox-mount-allowlist.txt`：沙箱挂载路径白名单。
  - `~/.microclaw/sandbox-path-allowlist.txt`：文件工具路径白名单。

工作目录约定：
- `bash` 会在当前 chat 工作目录下的 `tmp/` 子目录执行。
- 优先使用相对路径或当前 chat 工作目录下的路径，不要使用绝对 `/tmp/...`。
- 如果出现 `command not found`，仍需在宿主安装该依赖，或改用已包含该命令的沙箱镜像。

### 支持的 `llm_provider` 值

`openai`、`openai-codex`、`openrouter`、`anthropic`、`ollama`、`google`、`alibaba`、`deepseek`、`moonshot`、`mistral`、`azure`、`bedrock`、`zhipu`、`minimax`、`cohere`、`tencent`、`xai`、`huggingface`、`together`、`custom`。

## 平台行为

- Telegram 私聊：每条消息都会回复
- Telegram 群聊：仅在被 `@bot_username` 提及时回复；但仍会存储所有消息用于上下文
- Discord DM：每条消息都会回复
- Discord 服务器频道：被 @ 提及时回复；可通过 `discord_allowed_channels` 限定频道
- Slack DM：每条消息都会回复
- Slack 频道：被 @ 提及时回复；可通过 `allowed_channels` 限定
- 飞书/Lark 单聊（p2p）：每条消息都会回复
- 飞书/Lark 群聊：被 @ 提及时回复；可通过 `allowed_chats` 限定
- 飞书/Lark emoji 反应：模型可自由选择仅反应（`reaction-only: 👍`）、反应+文本（`reaction: 👍` 后跟文本）或纯文本；单 token 反应在 API 失败时会自动回退文本。
- IRC 私聊：每条消息都会回复
- IRC 频道：默认被提及时回复；可通过 `channels.irc.mention_required` 配置
- 群/频道中的 slash 命令默认也需要提及；可通过 `allow_group_slash_without_mention: true` 放开

**追赶行为（Telegram 群）：** 被 @ 时，机器人会加载该群上次回复以来的所有消息（而不是仅最近 N 条），使群聊交互更具上下文。

## 多聊天权限模型

工具调用会按当前聊天做权限校验：

- 非控制聊天只能操作自己的 `chat_id`
- 控制聊天（`control_chat_ids`）可跨聊天操作
- `write_memory` 的 `scope: "global"` 仅控制聊天可写

已接入权限校验的工具包括 `send_message`、定时任务相关工具、`export_chat`、`todo_*` 以及 chat scope 的记忆操作。

## 使用示例

**网页搜索：**
```
你: 搜索一下最新的 Rust 版本发行说明
Bot: [搜索 DuckDuckGo，返回带链接的结果]
```

**定时任务：**
```
你: 每天早上 9 点查看东京天气并发给我
Bot: 任务 #1 已创建。下次运行：2025-06-15T09:00:00+00:00

[第二天早上 9 点，机器人自动发送天气摘要]
```

**编程助手：**
```
你: 找出这个项目中所有的 TODO 注释并修复它们
Bot: [grep 搜索 TODO，读取文件，编辑修复，报告完成情况]
```

**记忆：**
```
你: 记住生产数据库在端口 5433
Bot: 已保存到聊天记忆。

[三天后]
你: 生产数据库在哪个端口？
Bot: 端口 5433。
```

**技能：**
```
你: 帮我把这个文档转成 PDF
Bot: [激活 pdf 技能，按照专业指令完成转换]
```

## 新增平台适配器（Adding a New Platform Adapter）

MicroClaw 的核心智能体循环是渠道无关的。新增平台时，重点是实现适配器层：

1. 将平台入站事件映射到统一输入（`chat_id`、sender、chat type、content blocks）。
2. 复用共享的 `process_with_agent` 流程，不要新增平台专属 agent loop。
3. 实现平台出站发送（文本与附件），并处理平台长度限制。
4. 定义群组/频道场景下的触发规则（例如 @ 提及才回复）。
5. 保持会话键稳定，确保会话恢复、上下文压缩、记忆机制可复用。
6. 复用现有权限与安全边界（`control_chat_ids`、工具约束、path guard）。
7. 按 `TEST.md` 的模式补平台集成测试（私聊/DM、群聊/频道提及、`/reset`、长度限制、失败场景）。


## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=microclaw/microclaw&type=Date)](https://star-history.com/#microclaw/microclaw&Date)

## Contributors

感谢所有为这个项目做出贡献的开发者。

[![Contributors](https://contrib.rocks/image?repo=microclaw/microclaw)](https://github.com/microclaw/microclaw/graphs/contributors)


## 可观测性 (Langfuse)

MicroClaw 支持基于 OpenTelemetry (OTLP) 的可观测能力，并与 [Langfuse](https://langfuse.com/) 深度集成。你可以追踪完整的 `agent_run`，查看 `llm_generation` / `tool_execution` 子链路，并监控 Token 消耗。

### 5 分钟快速上手（第一次使用推荐）

1. **部署 Langfuse**
   - **云服务**：`https://cloud.langfuse.com`
   - **自托管**：按 Langfuse 官方文档部署，并确认 UI 可访问（例如 `http://127.0.0.1:3000`）
2. **创建 Langfuse 项目**，拿到：
   - `langfuse_public_key`（`pk-lf-...`）
   - `langfuse_secret_key`（`sk-lf-...`）
3. **编辑 MicroClaw 配置** `microclaw.config.yaml`
4. **重启 MicroClaw**
5. **发送一条测试消息**（Web/Telegram/Discord 任一渠道），再去 Langfuse 查看 Traces

### 推荐配置

```yaml
observability:
  service_name: "microclaw-agent"
  otlp_tracing_enabled: true
  langfuse_host: "https://cloud.langfuse.com" # 自托管可改为 "http://127.0.0.1:3000"
  langfuse_public_key: "pk-lf-..."
  langfuse_secret_key: "sk-lf-..."
  otlp_tracing_max_queue_size: 8192
  otlp_tracing_max_export_batch_size: 512
  otlp_tracing_scheduled_delay_ms: 5000
```

### 如何确认接入成功

- 使用调试日志启动：

```sh
RUST_LOG=info,microclaw_observability=debug,opentelemetry_sdk=info microclaw start
```

- 重点看日志：
  - `otlp trace exporter initialized`
  - `trace span submitted to otel sdk`
- 在 Langfuse 中确认：
  - trace 名称：`agent_run`
  - 子 span：`llm_generation`、`tool_execution`
  - 有真实模型输出时，token usage 字段应非 0

### 常见踩坑与排障

- **`langfuse_host` 填错**
  - 只填主机根地址，例如 `http://127.0.0.1:3000`
  - 不要填 UI 地址 `/project/<id>/traces`
  - 不要手动拼 `/api/public/otel/v1/traces`
- **代理拦截本地 Langfuse 请求**
  - 如果日志里看到 proxy intercept 本地地址，请设置：

```sh
export NO_PROXY=127.0.0.1,localhost,<你的-langfuse-host>
export no_proxy=127.0.0.1,localhost,<你的-langfuse-host>
```

- **Docker 网络误区**
  - 容器内的 `127.0.0.1` 不是宿主机
  - MicroClaw 在容器里运行时，请改用容器可达域名（如 `http://langfuse-web:3000`）
- **改完配置后看不到数据**
  - 修改配置后必须重启 MicroClaw
  - 发送新请求再到 Langfuse 查看
- **OpenTelemetry 定时导出日志太多**
  - 将 SDK 日志级别提高到 `opentelemetry_sdk=info`
- **历史 trace 的 usage 异常**
  - 历史数据不会回填，请用升级后的新请求验证

## 许可证

MIT
