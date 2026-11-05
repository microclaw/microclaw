# MicroClaw Code 下一阶段开发规划（对比主流 Coding Agent）

状态：**0.21–0.23 已实现**（#538、#539、#540）
更新：**2026-11-04**
基线：**v0.20.0**（MicroClaw Code 首个版本）

本文对比 Claude Code、OpenAI Codex CLI、OpenCode、Kimi Code CLI（以及 Amp 的部分做法），列出 `mccode`
的差距，并给出按优先级排列的开发计划。重点是**上下文管理与压缩**，这是当前差距最大、收益也最大的部分。

> 关于竞品资料：竞品行为来自各自的官方文档、源码和公开分析文章（见文末来源）。阈值等具体数字
> 多来自第三方分析，版本之间会变化，只作为设计参考，不作为对标承诺。

---

## 1. 现状：v0.20.0 已有的能力

| 方面 | 已有 |
|---|---|
| 交互 | 全屏 TUI、`-p` / `--json`、`@file`、斜杠命令、运行中引导、Shift+Tab 切换模式 |
| 权限 | `plan` / `ask` / `auto`；运行中审批（一次 / 总是 / 本项目命令前缀 / 拒绝）；破坏性命令始终询问；`--review-commands` 模型复核命令 |
| 安全 | bubblewrap / Seatbelt / Landlock 沙箱；凭据目录隐藏；项目信任绑定文件哈希；路径保护 |
| 验证 | 自动探测检查命令，改动后运行，失败回灌，限定修复轮数 |
| 回退 | 每轮影子 git 检查点，`/undo`、`/rewind` |
| 会话 | 续接、`/fork`、`/model`、`/cost`、`/compact`、`/review` |
| 集成 | `mccode acp`（Zed）、`mccode mcp-server`、`--remote`（Server）、`mccode eval` |
| 工具 | `apply_patch`、gitignore 感知的 `glob` / `grep`、防陈旧读、后台进程 + `bash_input`、子代理 |

### 1.1 上下文管理的实际实现（问题所在）

读 `crates/microclaw-engine/src/agent_engine.rs` 与配置默认值后的结论。`mccode` 没有覆盖这些默认值：

| 项 | 当前实现 | 对编码场景的问题 |
|---|---|---|
| 压缩触发 | **按消息条数**：`max_session_messages = 40`，保留最近 `compact_keep_recent = 20` 条 | 一轮编码就可能有几十次工具调用，40 条很快触发；与真实 token 占用无关 |
| 压力触发 | 上次请求输入 token ≥ `model_context_window`（固定 200k）× 85% | 窗口大小不按模型区分（128k / 272k / 1M 模型都当成 200k） |
| 摘要输入 | 旧消息拼成文本后**截断到 20,000 字符**（保留开头） | 长会话里被丢掉的恰好是离现在最近的那部分旧历史 |
| 摘要提示词 | 一句通用的“简要总结” | 没有结构：目标、约束、已改文件、决定、失败与修复、下一步都可能丢 |
| 摘要失败 | 直接丢弃旧消息，只留最近 20 条 | 静默丢上下文 |
| 工具输出 | 单条超过 4000 字符就落盘为 artifact，正文保留头 1500 + 尾 500 | 读大文件时每次只看到片段；历史中旧的工具输出从不清理 |
| 压缩后补回 | 系统提示词每轮重建（AGENTS.md 会保留） | 待办列表、最近编辑的文件、验证状态不会主动补回 |
| 可观测 | `/cost` 只有 token 总数 | 没有 `/context` 占用明细，状态栏没有上下文百分比 |
| 缓存 | Anthropic `cache_control` 已支持 | 压缩、裁剪没有考虑缓存前缀稳定性 |

---

## 2. 竞品对比

### 2.1 上下文管理与压缩

| 能力 | Claude Code | Codex CLI | OpenCode | Kimi Code CLI | **mccode 0.20** |
|---|---|---|---|---|---|
| 触发依据 | token 占用（接近窗口上限时自动） | token：`model_auto_compact_token_limit`，上限被限制在窗口的 90% | token：超过“窗口 − 输出上限” | 需要时自动（窗口大，约 1M） | **消息条数**；外加固定 200k 的 85% |
| 先裁剪工具输出 | 有：先清旧工具输出，不够再摘要 | 输出在写入历史时截断 | 有：不调模型，保护最近约 40k token 的工具输出，可清理量超过约 20k 才动手 | — | **无** |
| 摘要结构 | 完成内容、进行中、涉及文件、下一步、用户要求 | “上下文检查点”交接：进度与决定、约束偏好、剩余步骤、关键引用 | 做了什么、当前工作、改过的文件、下一步、持久要求、技术决定 | `/compact` 可加提示 | **单句通用提示** |
| 保留原话 | 摘要 + 重新读入 CLAUDE.md / 自动记忆 | 最近用户消息原文（约 20k token）+ 摘要 | 只留摘要，再加“有下一步就继续” | — | 最近 20 条消息 |
| 用户控制 | `/compact <重点>`；CLAUDE.md 写压缩说明；可关自动压缩；`/context` 看占用 | 阈值可配；`/compact` | 可关自动压缩、可配裁剪 | `/compact <提示>` | `/compact`（无重点参数） |
| 模型自管上下文 | API 侧有 context editing、memory tool | 实验特性：token 预算 + 笔记 + `new_context` 开新窗口 | 给模型一个压缩工具，让它在任务边界自己压 | **D-Mail**：回到某个检查点，并给过去的自己留言 | 无 |
| 服务端压缩 | Anthropic API 有 compaction beta | 远程压缩；从最近压缩边界恢复 | — | — | 无 |
| 跨会话记忆 | CLAUDE.md + 自动记忆（模型自己写） | AGENTS.md | AGENTS.md | AGENTS.md | AGENTS.md（受信任项目）+ 引擎记忆（Code 未专门利用） |
| 交接 / 新线程 | `/clear`、子代理隔离上下文 | `new_context`（实验） | — | `/fork` | `/fork` |

（Amp 的做法也值得参考：不自动压缩，靠 **Handoff**——给定目标，由辅助模型抽取相关信息开一个新线程；
再加线程引用，按需拉取其他线程的内容。）

### 2.2 其他能力

| 能力 | Claude Code | Codex CLI | OpenCode | Kimi CLI | mccode |
|---|---|---|---|---|---|
| 子代理 / 并行 | 自定义子代理、并行 | 有限 | 多 agent（build / plan / 自定义） | 有 agent 工具 | 一个通用只读子代理 |
| Hooks | Pre/PostToolUse 等，可拦截 | 有限 | 插件 | — | 引擎有 hooks，**Code 未开放项目级配置** |
| 自定义命令 / Skills / 插件 | 有，并有市场 | prompts | 命令、插件 | — | 引擎有 Skills / MCP，**Code 无自定义斜杠命令** |
| 代码智能 | 依赖 grep / 子代理 | grep | **LSP 诊断附在读写结果上** | — | **无 LSP** |
| 沙箱 | macOS / Linux | macOS / Linux / **Windows** | 无（靠权限） | — | macOS / Linux，**Windows 无** |
| 编辑器 | VS Code、JetBrains | VS Code 扩展 | 客户端 / 服务端架构，多前端 | **Zed（ACP）** | Zed（ACP）；VS Code 无原生扩展 |
| 云端 / 后台任务 | 后台任务、Web 版 | Codex Cloud | 服务端模式 | — | `--remote` 到自己的 Server |
| GitHub | Action、PR 评审 | `/review`、云端 PR | — | — | `/review` 只看本地 |
| 图片输入 | 有 | 有 | 有 | 有 | **无** |
| 会话分享 / 导出 | 有 | 有 | 分享链接 | — | 无 |

**我们的优势**，保持并加强：开放的多模型（含 Ollama / 本地）、同一引擎可以作为 Server 和 SDK 嵌入、
默认 OS 沙箱、内建验证 + 修复回合、项目信任绑定文件哈希、Rust 单二进制。

---

## 3. 规划

优先级：**P0** 下一个版本必须做；**P1** 紧随其后；**P2** 视反馈再做。
每项都写明改哪里、怎么验收。

### P0：上下文引擎重写（目标版本 0.21）

#### C1. 按 token 计预算，替代按消息条数

- 加一张按模型区分的上下文窗口与最大输出表（基于 provider 矩阵，用户配置可覆盖）。
  Code 默认关闭条数触发（`max_session_messages` 只对聊天渠道生效）。
- token 估算：用上一次请求的 `usage.input_tokens` 做基准，加上新消息的估算（字节数 / 4，再用历史比率校准）。
  不引入 tokenizer 依赖。
- 阈值：`有效窗口 = 窗口 − 预留输出 − 安全余量`；自动压缩阈值默认 80%，可配置，并限制最高 90%
  （参考 Codex 的教训：阈值太高容易压缩循环）。
- 验收：100k / 200k / 1M 三档模型的单测；一个 60 次工具调用的会话不触发条数压缩。

#### C2. 分级缩减：先裁剪，再摘要

1. **裁剪工具输出（不调模型）**：从后往前扫描，最近约 40k token 的工具输出不动；更早的
   `tool_result` 正文替换成占位，例如
   `[已清理：read_file src/parser.rs（312 行）；需要时重新读取]`。
   只有可清理量超过约 20k token 时才动手，避免每轮都改变前缀、打掉提示缓存。
2. **同一文件去重**：同一路径多次 `read_file`，只保留最新一次的完整内容。
3. **artifact 指针保留**：被清理的大输出保留 `fetch_artifact` 引用，可以找回。
4. 仍然超过阈值时，才进入 C3 的摘要。
- 验收：裁剪前后 tool_use / tool_result 必须成对（复用 `safe_compact_split` 的约束）；
  回放测试中裁剪后的请求合法。

#### C3. 结构化、增量式摘要

- 替换现在的单句提示词，改为固定章节：
  1. 用户目标与约束（原话优先）
  2. 已做出的决定及原因
  3. 改过的文件及其当前状态
  4. 遇到的错误与修复方式
  5. 当前计划 / 待办
  6. 验证状态（哪些检查通过或失败）
  7. 下一步
- **增量**：以上一次摘要为锚点，只把新增部分合进去，不再每次从头总结。
- **不再截断到 20k 字符**：历史超过摘要模型窗口时，分块摘要后再合并（map-reduce）。
- **保留原话**：最近若干条用户消息按 token 预算（约 20k）原样保留（参考 Codex），
  而不是固定保留 20 条消息。
- 摘要前缀写明“这是之前对话的交接摘要”，并要求模型在此基础上继续，不要重新开始。
- 验收：一组“跨压缩事实召回”评测（见 C12）。

#### C4. 压缩后主动补回

压缩后的第一次请求补入：
- 当前待办 / 计划；
- 最近编辑的文件列表，含 diff 统计；可选在预算内补入最近 N 个文件的当前内容；
- 最近一次验证结果；
- 当前权限模式和信任状态；
- `.microclaw/project.yaml` 里的 `compact_instructions`。

AGENTS.md 已在系统提示词里，保持不变。

#### C5. 失败安全

- 摘要失败或超时时，**不再丢弃历史**：先做 C2 裁剪；仍然超限，就用确定性摘要
  （文件列表 + 工具调用清单 + 用户原话）兜底。
- 压缩循环保护：连续两次压缩后仍超限，就停下来告诉用户，不再自动重试。
- 压缩前完整历史照常归档（`archive_conversation` 已有），`/rewind` 可以回到压缩前。

#### C6. 可观测与用户控制

- `/context`：分项显示系统提示词、工具定义、AGENTS.md、消息、工具输出、摘要各占多少 token，
  以及距离自动压缩还剩多少。
- TUI 状态栏显示上下文百分比；超过 70% 变色提示。
- `/compact <重点>`，以及 `project.yaml` 的 `compact_instructions`。
- 配置项：`auto_compact`（开关）、`auto_compact_pct`、`prune_protect_tokens`。
- `--json` 事件新增 `context_compacted`（压缩前后 token、方式、耗时）。

### P1：模型参与的上下文管理（目标 0.22）

#### C7. 向模型暴露 token 预算

在每轮系统提醒里告诉模型当前上下文用量和剩余预算，
让它知道何时该收尾、交给子代理，或主动整理（参考 Codex 的实验特性）。

#### C8. 两个上下文工具（默认关闭，评测通过后再开）

- `checkpoint_note`：模型在任务边界写一条“阶段笔记”，压缩时优先保留。
- `rewind_with_note`：参考 Kimi CLI 的 D-Mail。模型发现走错方向时（例如反复搜索无果），
  把**对话**退回到某个检查点，并给过去的自己留一句话，例如“不要再搜 X，答案在 Y”。
  文件状态不随之回退，文件回退仍由用户用 `/rewind` 决定。

#### C9. 用子代理隔离上下文

- 探索型子代理（只读）成为一等功能：大范围搜索、读大量文件的工作交给它，主线程只收结论。
- 支持并行多个探索子代理，结果合并后再回到主线程。
- 支持在 `.microclaw/agents/*.md` 定义子代理（名称、说明、工具、模型）。

#### C10. `/handoff <目标>`

参考 Amp：用辅助模型从当前会话抽取与新目标相关的信息，作为种子开一个新会话，原会话保留。
适合“这个任务做完了，基于它做下一个”。

#### C11. 项目记忆

- 受信任项目可以有 `.microclaw/memory.md`：模型把稳定的经验写进去，
  比如构建怎么跑、哪些测试很慢、某个坑怎么绕。写入要经过审批或在 diff 里展示。
- 压缩后、新会话开始时自动读入。复用引擎已有的记忆服务，但按项目隔离。

#### C12. 上下文评测集

扩展 `mccode eval`：
- **长会话用例**：需要 50 次以上工具调用才能完成的任务。
- **跨压缩召回**：早期给出的约束（例如“不要改公共 API”“用 pnpm”）在压缩后仍然被遵守。
- 指标：成功率、每个任务的 token 数、压缩次数、缓存命中率、压缩耗时。
- C1–C6 上线前后各跑一次，结果写入发版计划。

### P1：编码体验差距

| 编号 | 项 | 说明 |
|---|---|---|
| E1 | LSP 诊断 | 编辑后自动拿诊断（rust-analyzer、tsserver、pyright、gopls），附在工具结果里（参考 OpenCode）；比整套检查快，早发现错误 |
| E2 | Hooks 开放给 Code | `project.yaml` / 用户配置里的 PreToolUse / PostToolUse / AfterTurn，例如编辑后自动格式化；复用引擎 hooks |
| E3 | 自定义斜杠命令 | `.microclaw/commands/*.md`，带参数占位 |
| E4 | 图片输入 | TUI 粘贴截图或拖入路径；ACP 的图片内容块 |
| E5 | Windows 沙箱 | 用受限令牌 / AppContainer 或 Job Object 做写入限制；在那之前 Windows 默认 `ask` 并明确提示 |
| E6 | 后台任务与 worktree | `mccode -p --worktree`：在独立 git worktree 里跑任务，完成后给出分支或补丁，可以并行多个 |
| E7 | GitHub 集成 | `mccode review --pr <n>` 读 PR diff 出评审意见；提供一个 GitHub Action 示例 |
| E8 | 会话导出 | `/export` 导出 Markdown 或 JSON 记录 |

### P2：生态与分发

| 编号 | 项 | 说明 |
|---|---|---|
| D1 | VS Code | 通过 ACP 桥接或轻量扩展 |
| D2 | JetBrains | 跟进 JetBrains 的 ACP 支持 |
| D3 | 服务端压缩 | 可选接入 Anthropic compaction API、OpenAI 远程压缩；本地实现作为通用兜底 |
| D4 | 模型预设 | Kimi / DeepSeek / Qwen 等编码模型的窗口、价格、推荐参数预设 |
| D5 | 预算控制 | 每个会话 / 任务的 token 或费用上限，到达后暂停询问 |
| D6 | nixpkgs、Windows ARM | 补齐分发渠道 |

---

## 交付情况

| 版本范围 | PR | 说明 |
|---|---|---|
| 0.21：C1–C6、C12 | #538 | 按 token 计预算（含模型窗口表）、先裁剪后摘要、结构化增量摘要、补回用户原话与改动文件、失败兜底、`/context`、状态栏占用、`ContextCompacted` 事件、多轮评测用例 |
| 0.22：C7–C11、E1–E3 | #539 | 向模型暴露预算、`context_note` / `rewind_context`（默认关闭）、`explore` 只读助手与项目 agent、`/handoff`、项目记忆 `.microclaw/memory.md`、LSP 诊断、`after_edit` / `after_turn` hooks、自定义斜杠命令 |
| 0.23：E4–E8、D3、D5 | #540 | `@图片`（含 ACP）、Windows 明确降级、`--worktree` 并行任务、`review --pr`、`/export`、Anthropic 服务端 context editing（可选）、会话 token 预算 |

尚未做：D1 VS Code、D2 JetBrains、D4 模型预设、D6 nixpkgs / Windows ARM；Windows 真正的沙箱（AppContainer / 受限令牌）仍待实现。

## 4. 版本计划

| 版本 | 内容 | 验收 |
|---|---|---|
| **0.21** | C1–C6（上下文引擎重写）、C12 评测集初版 | 长会话评测成功率不低于 0.20，每个任务 token 下降 ≥ 25%；跨压缩召回 ≥ 90%；不再出现按条数压缩 |
| **0.22** | C7–C11、E1、E2、E3 | LSP 在 Rust / TS / Python 三种项目可用；hooks 与自定义命令有文档和测试 |
| **0.23** | E4–E8、D3、D5 | Windows 沙箱或明确的降级策略；worktree 并行任务；PR 评审 |
| 之后 | D1、D2、D4、D6 | 视用户反馈排序 |

## 5. 实施注意

- 上下文逻辑放在 `microclaw-engine`，Server 与 SDK 共用；Code 只做配置和展示（`/context`、状态栏）。
  聊天渠道可以保留按条数压缩作为选项，但默认也迁移到 token 预算。
- 每项改动都要保持 tool_use / tool_result 成对和中断恢复的不变式，复用现有回放测试。
- 新的配置字段放进 `config/core.rs`，带默认值；生成文档（`generated-config-defaults`）同步更新。
- 不引入重量级 tokenizer；估算误差由安全余量吸收。

## 6. 来源

- [Context engineering: memory, compaction, and tool clearing（Anthropic cookbook）](https://platform.claude.com/cookbook/tool-use-context-engineering-context-engineering-tools)
- [Inside Claude Code's Compaction System](https://decodeclaude.com/compaction-deep-dive/)
- [How Claude Code Got Better by Protecting More Context](https://hyperdev.matsuoka.com/p/how-claude-code-got-better-by-protecting)
- [ChatGPT & Codex changelog](https://developers.openai.com/codex/changelog)
- [Experimental Context Management / Compaction in Codex（社区帖）](https://community.openai.com/t/experimental-context-management-compaction-in-codex/1395578)
- [Context Compaction Deep Dive: Codex CLI, Claude Code, OpenCode](https://codex.danielvaughan.com/2026/04/14/context-compaction-deep-dive-codex-cli-claude-code-opencode/)
- [Context Compaction Research: Claude Code, Codex CLI, OpenCode, Amp（gist）](https://gist.github.com/badlogic/cd2ef65b0697c4dbe2d13fbecb0a0a5f)
- [Dissecting OpenCode — 10 Design Elements（gist）](https://gist.github.com/shibuiwilliam/1d1466b24cb5c8f0d9367f2c75c9c064)
- [OpenCode Context Management](https://datalakehousehub.com/blog/2026-03-context-management-opencode/)
- [kimi-cli AGENTS.md](https://github.com/MoonshotAI/kimi-cli/blob/main/AGENTS.md)
- [Kimi Code CLI Quick Reference](https://www.kimi.ai/academy/kimi-code-cheat-sheet)
- [Kimi Code CLI Getting started](https://www.kimi.com/code/docs/en/kimi-code-cli/guides/getting-started.html)
