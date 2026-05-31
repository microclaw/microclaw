# 出厂内置 Skills 清单与集成方案（开箱即用 · 一站式）

> 目标：让 MicroClaw **出厂即是一个一站式助手**——计算、编码、查资料、规划、写作、
> 图示、文档处理……常见需求都有对应的内置 skill，用户装上就能用，不用自己配。
> 本文是调研 + 选型 + 集成方案，并记录本次已落地的启动批次。

---

## 0. Skill 机制（30 秒理解，为什么扩展很安全）

MicroClaw 用的是 **Anthropic Agent Skills 标准**：一个 skill = 一个文件夹，里面一个
`SKILL.md`（YAML frontmatter: `name` / `description` / `compatibility` + Markdown 正文/脚本）。

- **嵌入**：`skills/built-in/` 下的所有 skill 在编译期被 `include_dir!` 打进二进制
  （`crates/microclaw-app/src/builtin_skills.rs:5`）。
- **安装**：运行时 `ensure_builtin_skills` 自动把兼容的 skill 释放到 skills 目录。
- **自动跳过**：`skill_skip_reason`（`builtin_skills.rs:117`）会按 `platforms` / `deps`
  跳过不兼容主机的 skill——所以 Apple 那几个在 Linux 服务器上本就不会装，缺依赖的也会静默跳过。
- **结论**：**新增 skill = 往 `skills/built-in/` 丢一个文件夹，自动发现、自动嵌入、自动按兼容性安装。
  纯增量，不用改任何 Rust 代码，零回归风险。**

> "出厂即用"的工程含义：**优先选零依赖，或只依赖 `python3` / `curl` / `git` 这类几乎必备命令的 skill**，
> 这样在典型 Linux 服务器上不会被跳过。

---

## 1. 现状：已内置 12 个

| 类别 | 已有 skill |
|---|---|
| 文档 | `pdf` `docx` `pptx` `xlsx` |
| 苹果生态（mac-only，服务器自动跳过） | `apple-calendar` `apple-notes` `apple-reminders` |
| 工具/平台 | `weather`(wttr.in 无需 key) `github`(gh CLI) |
| 检索/溯源 | `propagation-trace`(web 工具) |
| 元能力 | `skill-creator` `find-skills` |

**缺口**（也正是用户点名的）：**计算、编码、规划** 几乎是空白；**查东西/检索** 只有溯源一个；
创意图示、写作生产力、实用工具 也没有。下面补齐。

---

## 2. 调研：现有 skill 生态（可借鉴/可移植的来源）

- **Anthropic 官方**（`anthropics/skills`，~70k★）：文档类（pdf/docx/pptx/xlsx，我们已用同款）、
  创意设计（algorithmic-art、canvas-design）、开发技术（web app 测试、MCP server 生成）、
  企业沟通（branding、comms）。是参考实现也是可用目录。
- **社区聚合**（量大，质量参差，需筛选）：
  - `VoltAgent/awesome-agent-skills`（1000+）
  - `sickn33/antigravity-awesome-skills`（1400+，含安装器）
  - `alirezarezvani/claude-skills`（337，覆盖工程/产品/研究/财务/生产力）
  - `travisvn/awesome-claude-skills`、`ComposioHQ/awesome-claude-skills`（精选清单）

**选型原则**：① 零/轻依赖优先（出厂即用）；② 跨平台；③ 覆盖高频日常需求；
④ 许可清晰（见 §5）。**我们自己写原创 SKILL.md（指令本身），不照搬第三方内容，规避许可问题。**

---

## 3. 出厂默认 Roster（建议的一站式默认集）

> 优先级：**P0 = 零依赖或 python3/curl，出厂即用（建议原创、本批/下批落地）**；
> P1 = 依赖常见命令（git/jq/sqlite3/qrencode 等），声明依赖、缺失自动跳过；
> P2 = 重依赖或需 API key，可选。

### A. 计算与数据
| skill | 作用 | 依赖 | 优先级 |
|---|---|---|---|
| **calculator** | 精确算术/百分比/利息/统计 | python3 | P0 ✅本批 |
| unit-converter | 长度/重量/温度/货币*等换算 | python3 | P0 |
| datetime | 时区换算、日期差、倒计时、"周几" | python3 | P0 |
| csv-tools | 读取/清洗/统计 CSV | python3 | P0 |
| json-tools | 查询/转换/校验 JSON | jq | P1 |
| sql | 写并执行 SQL（本地库/查询） | sqlite3 | P1 |
| data-analysis | 表格分析/出图 | python3+pandas | P2 |

### B. 编码
| skill | 作用 | 依赖 | 优先级 |
|---|---|---|---|
| **code-review** | 查 bug/安全/简化的代码评审 | — | P0 ✅本批 |
| **regex** | 写/测/调正则，按样本验证 | python3 | P0 ✅本批 |
| debugging | 系统化排错法（复现→二分→定位） | — | P0 |
| shell-scripting | 健壮 bash 写法/常用片段 | — | P0 |
| api-design | REST/错误码/版本化规范 | — | P0 |
| testing | 测试设计/边界/最小用例 | — | P0 |
| git | 常用 git 工作流/救场 | git | P1 |

### C. 查东西 / 检索（已具备 `web_search`/`web_fetch` 工具）
| skill | 作用 | 依赖 | 优先级 |
|---|---|---|---|
| research | 结构化多源调研 + 交叉验证 + 引用 | web 工具 | P0 |
| wikipedia | 快速查百科条目摘要 | curl | P1 |
| define | 词典/术语/翻译速查 | curl | P1 |
| tech-news | Hacker News/科技头条速览 | curl | P1 |
| propagation-trace | 溯源/传播链（已有） | web 工具 | ✅已有 |

### D. 规划
| skill | 作用 | 依赖 | 优先级 |
|---|---|---|---|
| **planning** | 目标拆里程碑/排期/风险 | — | P0 ✅本批 |
| brainstorming | 发散+收敛的点子生成 | — | P0 |
| decision-matrix | 多方案加权打分选型 | — | P0 |
| meeting-notes | 会议纪要/行动项提炼 | — | P0 |
| goal-setting | OKR/目标分解与跟踪 | — | P0 |

### E. 创意与图示
| skill | 作用 | 依赖 | 优先级 |
|---|---|---|---|
| mermaid | 文本生成流程图/时序图/甘特图 | — | P0 |
| color-tools | hex/rgb/hsl 换算、配色 | python3 | P0 |
| algorithmic-art | 生成艺术（Anthropic 同款思路） | python3 | P1 |
| qrcode | 生成二维码 | qrencode | P1 |

（图像生成已是内置工具 `generate_image`，无需 skill。）

### F. 写作与生产力
| skill | 作用 | 依赖 | 优先级 |
|---|---|---|---|
| writing-editor | 润色/改写/控制语气长度 | — | P0 |
| summarize | 长文/会议/文档摘要 | — | P0 |
| email-drafting | 邮件起草（多语气模板） | — | P0 |
| translate | 翻译规范（保留术语/格式） | — | P0 |

---

## 4. 本次已落地的启动批次（4 个，全部 P0、零/轻依赖、立即可用）

| skill | 类别 | 依赖 | 说明 |
|---|---|---|---|
| `calculator` | 计算 | python3 | 用 Python 做精确计算，避免"心算错一位" |
| `planning` | 规划 | 无 | 把模糊目标拆成里程碑+下一步+风险 |
| `code-review` | 编码 | 无 | 按 正确性>边界>安全>错误处理>简化 评审 |
| `regex` | 编码 | python3 | 写正则并用真实样本验证，给出"匹配 vs 拒绝" |

均为**原创 SKILL.md**，遵循现有格式（`name`/`description`/`compatibility` frontmatter），
已放入 `skills/built-in/`，下次编译自动嵌入、运行时自动安装。

---

## 5. 集成方式与许可注意

- **加 skill 的标准动作**：在 `skills/built-in/<name>/` 放一个 `SKILL.md`（必要时带脚本/资源）。
  无需改 Rust 代码。
- **声明兼容性**：需要外部命令时在 `compatibility` 写清楚（如 "Requires jq"），不满足会自动跳过——
  这正是"出厂即用"的保障：用户机器缺什么就静默少装什么，不报错。
- **许可（重要）**：
  - 我们**自写原创 SKILL.md**（skill 的价值在指令，不在代码），从源头规避许可问题。
  - 若要**移植** Anthropic 官方或社区 skill，必须遵守其各自许可并保留署名；社区 skill 许可参差，
    需逐个核对，不可无脑打包。
  - 内置脚本应避免引入需付费 API key 的硬依赖（放 P2，并在文档标注"需配置 key"）。

---

## 6. 分批实施计划

| 批次 | 内容 | 风险 | 状态 |
|---|---|---|---|
| **Batch 1** | calculator / planning / code-review / regex（P0） | 极低（纯增量） | ✅ 完成 |
| **Batch 2** | 计算数据：unit-converter / datetime / csv-tools / json-tools | 低 | ✅ 完成 |
| **Batch 3** | 编码：debugging / shell-scripting / api-design / testing / git | 低 | ✅ 完成 |
| **Batch 4** | 检索 + 规划：research / wikipedia / define / brainstorming / decision-matrix / meeting-notes / goal-setting | 低 | ✅ 完成 |
| **Batch 5** | 创意/写作：mermaid / color-tools / writing-editor / summarize / email-drafting / translate | 低 | ✅ 完成 |
| Batch 6（可选） | P1/P2 重依赖：sql / qrcode / algorithmic-art / data-analysis | 中（依赖检测） | 待评估 |

> **已落地 26 个内置 skill**（含原有 12 个，共 38 个）。`test_ensure_builtin_skills_includes_*`
> 断言全部新 skill 正确嵌入并安装，作为回归保护。所有新 skill 采用字符串 `compatibility`
> 约定（与现有 weather/github 一致）→ 始终安装；带外部命令的（git/jq/curl）在缺失时由 skill
> 正文内的兜底逻辑处理，不会因依赖检测被误跳过。

> 每批都是"丢文件夹"级别的增量，可独立合入、独立回滚。建议按 Batch 顺序推进，
> 每批合入后跑一次构建确认 `include_dir!` 正常嵌入即可。

---

## 7. 与其它方案的关系

- 这批 skill 让 bot **能力一站式**；配合 `docs/being-more-human.md` 的**专科 Sub-Agent 团队**，
  主代理可以把 skill 化的能力交给对应专家在后台并发执行，再像同事一样汇报——
  "能干"和"像人"在这里合流。

---

## 参考来源

- Anthropic 官方 Agent Skills 仓库 — <https://github.com/anthropics/skills>
- Equipping agents for the real world with Agent Skills — <https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills>
- Agent Skills 规范 — <https://github.com/anthropics/skills/blob/main/spec/agent-skills-spec.md>
- VoltAgent/awesome-agent-skills（1000+） — <https://github.com/VoltAgent/awesome-agent-skills>
- alirezarezvani/claude-skills（337） — <https://github.com/alirezarezvani/claude-skills>
- travisvn/awesome-claude-skills — <https://github.com/travisvn/awesome-claude-skills>
- ComposioHQ/awesome-claude-skills — <https://github.com/ComposioHQ/awesome-claude-skills>
