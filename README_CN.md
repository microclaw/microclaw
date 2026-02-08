# MicroClaw

[English](README.md) | [中文](README_CN.md)

[![Website](https://img.shields.io/badge/Website-microclaw.ai-blue)](https://microclaw.ai)
[![Discord](https://img.shields.io/discord/1469628852983697482?logo=discord&label=Discord&color=5865F2)](https://discord.gg/pvmezwkAk5)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **注意：** 本项目正在积极开发中，功能可能会变化，欢迎贡献！

<p align="center">
  <img src="screenshots/screenshot1.png" width="45%" />
  &nbsp;&nbsp;
  <img src="screenshots/screenshot2.png" width="45%" />
</p>

一个住在 Telegram 聊天里的 AI 智能助手，灵感来自 [nanoclaw](https://github.com/gavrielc/nanoclaw/)，参考了 nanoclaw 的部分思路。MicroClaw 将 Claude 连接到 Telegram，支持完整的工具执行：运行 Shell 命令、读写编辑文件、搜索代码库、浏览网页、定时任务、持久化记忆等。

## 工作原理

```
Telegram 消息
    |
    v
 存入 SQLite --> 加载聊天历史 + 记忆
                    |
                    v
              Claude API（带工具）
                    |
               stop_reason?
              /            \
         end_turn        tool_use
            |               |
            v               v
       发送回复        执行工具
                         |
                         v
                   将结果反馈给
                   Claude（循环）
```

每条消息触发一个 **智能体循环**：Claude 可以调用工具、检查结果、再调用更多工具，经过多步推理后再回复。默认每次请求最多 25 次迭代。

## 博客文章

关于架构设计和使用体验的深入介绍：**[Building MicroClaw: An Agentic AI Assistant in Rust That Lives in Your Telegram Chats](BLOG.md)**

## 功能特性

- **智能体工具调用** -- bash 命令、文件读写编辑、glob 搜索、正则 grep、持久化记忆
- **会话恢复** -- 完整对话状态（包括工具交互）持久化保存；Claude 跨调用记住工具调用
- **上下文压缩** -- 会话过长时自动总结旧消息，保持在上下文限制内
- **子代理** -- 将独立子任务委派给有限制工具集的并行代理
- **技能系统** -- 可扩展的技能系统（兼容 [Anthropic Skills](https://github.com/anthropics/skills) 标准）；技能从 `data/skills/` 自动发现，按需激活
- **计划与执行** -- todo 工具，将复杂任务拆解为步骤，逐步跟踪进度
- **网页搜索** -- 通过 DuckDuckGo 搜索和抓取网页
- **定时任务** -- 基于 cron 的循环任务和一次性定时任务，通过自然语言管理
- **会话中发消息** -- 智能体可以在最终回复前发送中间进度消息
- **群聊追赶** -- 在群里被 @ 时，机器人会读取上次回复以来的所有消息
- **持续输入指示** -- 处理期间持续显示"正在输入"状态
- **持久化记忆** -- 全局和每个聊天的 CLAUDE.md 文件，每次请求都会加载
- **消息分割** -- 长回复自动在换行处分割，适配 Telegram 4096 字符限制

## 工具列表

| 工具 | 描述 |
|------|------|
| `bash` | 执行 Shell 命令，可配置超时 |
| `read_file` | 读取文件，带行号，支持偏移/限制 |
| `write_file` | 创建或覆盖文件（自动创建目录） |
| `edit_file` | 查找替换编辑，带唯一性验证 |
| `glob` | 按模式查找文件（`**/*.rs`、`src/**/*.ts`） |
| `grep` | 正则搜索文件内容 |
| `read_memory` | 读取持久化 CLAUDE.md 记忆（全局或每聊天） |
| `write_memory` | 写入持久化 CLAUDE.md 记忆 |
| `web_search` | 通过 DuckDuckGo 搜索（返回标题、URL、摘要） |
| `web_fetch` | 抓取 URL 并返回纯文本（去 HTML，最大 20KB） |
| `send_message` | 会话中发送 Telegram 消息（进度更新、多部分回复） |
| `schedule_task` | 创建循环（cron）或一次性定时任务 |
| `list_scheduled_tasks` | 列出聊天的所有活跃/暂停任务 |
| `pause_scheduled_task` | 暂停定时任务 |
| `resume_scheduled_task` | 恢复已暂停的任务 |
| `cancel_scheduled_task` | 永久取消任务 |
| `get_task_history` | 查看定时任务的执行历史 |
| `export_chat` | 导出聊天记录为 markdown |
| `sub_agent` | 委派子任务给有限制工具集的并行代理 |
| `activate_skill` | 激活技能以加载专业指令 |
| `todo_read` | 读取当前聊天的任务/计划列表 |
| `todo_write` | 创建或更新聊天的任务/计划列表 |

## 记忆系统

MicroClaw 通过 `CLAUDE.md` 文件维护持久化记忆，灵感来自 Claude Code 的项目记忆：

```
data/runtime/groups/
    CLAUDE.md                 # 全局记忆（所有聊天共享）
    {chat_id}/
        CLAUDE.md             # 每聊天记忆
```

记忆在每次请求时加载到 Claude 的系统提示中。Claude 可以通过工具读写记忆 -- 告诉它"记住我喜欢用 Python"，它就会跨会话保存。

## 技能系统

MicroClaw 支持 [Anthropic Agent Skills](https://github.com/anthropics/skills) 标准。技能是为特定任务提供专业能力的模块化包。

```
data/skills/
    pdf/
        SKILL.md              # 必需：name、description + 指令
    docx/
        SKILL.md
```

**工作方式：**
1. 技能元数据（名称 + 描述）始终在系统提示中（每个技能约 100 token）
2. 当 Claude 判断某技能相关时，调用 `activate_skill` 加载完整指令
3. Claude 按技能指令完成任务

**内置技能：** pdf、docx、xlsx、pptx、skill-creator

**添加技能：** 在 `data/skills/` 下创建子目录，放入包含 YAML frontmatter（`name` 和 `description`）和 markdown 指令的 `SKILL.md` 文件。

**命令：**
- `/skills` -- 列出所有可用技能

## 计划与执行

对于复杂的多步骤任务，机器人可以创建计划并跟踪进度：

```
你: 搭建一个新的 Rust 项目，配好 CI、测试和文档
Bot: [创建 todo 计划，然后逐步执行，更新进度]

1. [x] 创建项目结构
2. [x] 添加 CI 配置
3. [~] 编写单元测试
4. [ ] 添加文档
```

Todo 列表存储在 `data/runtime/groups/{chat_id}/TODO.json`，跨会话持久化。

## 定时任务

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

## 安装

### 一键安装（推荐）

```sh
curl -fsSL https://microclaw.ai/install.sh | bash
```

安装脚本会按顺序尝试：
- 从最新 GitHub Release 下载匹配平台的预编译二进制
- 在 macOS 上回退到 Homebrew 安装
- 回退到 `cargo install` 源码编译安装

强制只使用 GitHub Release（不回退 Homebrew/Cargo）：
```sh
curl -fsSL https://microclaw.ai/install.sh | MICROCLAW_INSTALL_METHOD=release bash
```

### Homebrew (macOS)

```sh
brew tap everettjf/tap
brew install microclaw
```

### 从源码构建

```sh
git clone https://github.com/microclaw/microclaw.git
cd microclaw
cargo build --release
cp target/release/microclaw /usr/local/bin/
```

## 发布

一条命令同时发布安装脚本模式（GitHub Release 资产）和 Homebrew 模式：

```sh
./deploy.sh
```

## 配置

> **新功能：** 现在支持交互式配置向导（`microclaw setup`），并且在 `start` 时若缺少必需配置会自动进入向导。

### 1. 创建 Telegram 机器人

1. 打开 Telegram，搜索 [@BotFather](https://t.me/BotFather)
2. 发送 `/newbot`
3. 输入机器人的显示名称（例如 `My MicroClaw`）
4. 输入用户名（必须以 `bot` 结尾，例如 `my_microclaw_bot`）
5. BotFather 会回复一个 token，类似 `123456789:ABCdefGHIjklMNOpqrsTUVwxyz` -- 保存好

**推荐的 BotFather 设置**（可选但有用）：
- `/setdescription` -- 设置机器人简介，显示在机器人资料页
- `/setcommands` -- 注册命令，用户可以在菜单中看到：
  ```
  reset - 清除当前会话
  skills - 查看可用技能列表
  ```
- `/setprivacy` -- 设置为 `Disable`，这样机器人可以看到群里所有消息（而不仅仅是 @提及）

### 2. 获取 Anthropic API Key

1. 访问 [console.anthropic.com](https://console.anthropic.com/)
2. 注册或登录
3. 进入 **API Keys** 页面，创建新的 key
4. 复制 key（以 `sk-ant-` 开头）

### 3. 配置（推荐：向导）

```sh
microclaw setup
```

<!-- setup 向导截图占位，后续替换为真实图片 -->
![Setup 向导（占位）](screenshots/setup-wizard.png)

向导提供：
- 终端交互式 UI（字段切换、状态提示、帮助）
- provider/model 可视化列表选择（`Enter` 打开列表，`↑/↓` 选择，`Enter` 确认）
- 本地校验（必填项、时区、数据目录可写）
- 在线校验（Telegram `getMe`、LLM API 连通性）
- 安全写入 `.env`（自动备份 `.env.bak.<timestamp>`）

向导内置 provider 预设：
- `openai`
- `openrouter`
- `anthropic`
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
- `baidu`
- `tencent`
- `huawei`
- `xai`
- `huggingface`
- `together`
- `perplexity`
- `custom`（手动填写 provider/model/base URL）

如果你更喜欢手工配置，也可以直接写 `.env`：

```
TELEGRAM_BOT_TOKEN=123456:ABC-DEF1234...
BOT_USERNAME=my_bot
LLM_PROVIDER=anthropic
LLM_API_KEY=sk-ant-...
LLM_MODEL=claude-sonnet-4-20250514
# 可选
LLM_BASE_URL=
DATA_DIR=./microclaw.data
TIMEZONE=UTC
```

### 4. 运行

```sh
microclaw start
```

## 环境变量

| 变量 | 必需 | 默认值 | 描述 |
|------|------|--------|------|
| `TELEGRAM_BOT_TOKEN` | 是 | -- | BotFather 的 Telegram bot token |
| `LLM_API_KEY` | 是 | -- | LLM API key（兼容 `ANTHROPIC_API_KEY`） |
| `BOT_USERNAME` | 是 | -- | Bot 用户名（不带 @） |
| `LLM_PROVIDER` | 否 | `anthropic` | 提供方预设 ID（或自定义 ID）。`anthropic` 走原生 Anthropic API，其他走 OpenAI 兼容 API |
| `LLM_MODEL` | 否 | 随 provider 默认 | 模型名（仍兼容 `CLAUDE_MODEL`） |
| `LLM_BASE_URL` | 否 | provider 预设默认值 | 自定义 API 基础地址 |
| `DATA_DIR` | 否 | `./microclaw.data` | 数据根目录（运行时数据在 `DATA_DIR/runtime`，技能在 `DATA_DIR/skills`） |
| `MAX_TOKENS` | 否 | `8192` | 每次 Claude 回复的最大 token |
| `MAX_TOOL_ITERATIONS` | 否 | `25` | 每条消息的最大工具循环次数 |
| `MAX_HISTORY_MESSAGES` | 否 | `50` | 作为上下文发送的历史消息数 |
| `MAX_SESSION_MESSAGES` | 否 | `40` | 触发上下文压缩的消息数阈值 |
| `COMPACT_KEEP_RECENT` | 否 | `20` | 压缩时保留的最近消息数 |

## 群聊

私聊中机器人回复每条消息。群聊中只在被 `@bot_username` 提及时回复。所有群消息仍会存储用于上下文。

**追赶行为：** 在群里被 @ 时，机器人会加载该群上次回复以来的所有消息（而不是仅最近 N 条），使群聊交互更具上下文。

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

## 许可证

MIT

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=everettjf/MicroClaw&type=Date)](https://star-history.com/#everettjf/MicroClaw&Date)
