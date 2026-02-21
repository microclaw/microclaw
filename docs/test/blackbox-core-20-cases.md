# Blackbox Core Test Cases (20)

本文档用于手工黑盒回归测试 MicroClaw 核心能力。每个用例都给出可直接执行的步骤、发送消息和验收标准。

## 测试前准备

1. 服务已启动，Web 可访问（示例：`http://127.0.0.1:8787`）。
2. 具备 Web 登录权限（建议使用可读写 API 权限账号）。
3. 每个用例使用独立 `session_key`，避免互相污染。
4. 如需验证 MCP 相关用例，确保 `mcp.json` 或 `mcp.d/*.json` 已配置并可用。
5. 建议准备记录表：`执行人 / 执行时间 / 结果(通过|失败) / 截图链接 / 备注`。

## 通用检查接口

- `GET /api/metrics`
- `GET /api/metrics/summary`
- `GET /api/metrics/history?minutes=60`

---

## P0（发布阻断级，必须先跑）

### TC01 基础对话链路

- `session_key`: `tc01_basic`
- 步骤:
1. 新建会话并发送消息。
- 发送消息:
`请用一句话回复“基础链路OK”。`
- 预期:
1. 返回成功。
2. 回复中包含“基础链路OK”。
- 记录:
1. 结果：
2. 备注：

### TC02 多轮上下文保持

- `session_key`: `tc02_multi_turn`
- 步骤:
1. 在同一会话连续发送 3 条消息。
- 发送消息:
`我叫张三。`
`记住我的名字。`
`我叫什么？`
- 预期:
1. 第三条回复能正确说出“张三”。
2. 无上下文错乱。
- 记录:
1. 结果：
2. 备注：

### TC07 工具调用成功（写入+读取）

- `session_key`: `tc07_tools_ok`
- 步骤:
1. 请求 agent 写入并读取文件。
- 发送消息:
`请用工具在当前工作目录写入文件 tc07.txt，内容是 hello-microclaw，然后再读出来返回。`
- 预期:
1. 工具调用成功。
2. 返回内容包含 `hello-microclaw`。
- 记录:
1. 结果：
2. 备注：

### TC08 工具调用失败（参数错误）

- `session_key`: `tc08_tools_err`
- 步骤:
1. 请求 agent 故意错误调用工具。
- 发送消息:
`请调用 read_file 工具但故意不给 path 参数。`
- 预期:
1. 返回结构化错误信息。
2. 会话不中断，可继续提问。
- 记录:
1. 结果：
2. 备注：

### TC10 跨会话权限拦截

- `session_key`: `tc10_acl`
- 步骤:
1. 在普通会话请求读取他人 chat 数据。
- 发送消息:
`请读取 chat_id=999999 的聊天记忆。`
- 预期:
1. 被权限拒绝。
2. 不应返回“成功但空数据”。
- 记录:
1. 结果：
2. 备注：

### TC13 定时任务 once

- `session_key`: `tc13_schedule_once`
- 步骤:
1. 创建 1 分钟后执行的一次性任务。
2. 等待触发并观察执行结果。
- 发送消息:
`请创建一个1分钟后执行的一次性任务，内容是“到点提醒：喝水”。`
- 预期:
1. 任务成功创建。
2. 到点触发并产生日志/消息。
- 记录:
1. 结果：
2. 备注：

### TC15 DLQ 与重放

- `session_key`: `tc15_dlq`
- 步骤:
1. 创建一个必然失败的任务。
2. 查看 DLQ。
3. 重放最近一条。
- 发送消息:
`请创建一次性任务，执行 bash: cat /not_exists_abc_xyz`
`请列出DLQ。`
`请重放最新一条失败任务。`
- 预期:
1. 失败记录进入 DLQ。
2. replay 后状态变化为已重放/已入队。
- 记录:
1. 结果：
2. 备注：

### TC16 MCP 基础调用

- `session_key`: `tc16_mcp_basic`
- 前置:
1. MCP 文件系统工具可用。
- 步骤:
1. 让 agent 调用 MCP 列目录。
- 发送消息:
`请调用 MCP 文件系统工具列出当前目录文件名。`
- 预期:
1. 成功返回目录列表。
2. 回复中有 MCP 工具调用痕迹。
- 记录:
1. 结果：
2. 备注：

### TC19 Metrics Snapshot 与 Summary 合约

- `session_key`: `tc19_metrics_contract`
- 步骤:
1. 执行若干工具/MCP请求后，访问 metrics 接口。
2. 检查字段完整性。
- 检查项:
1. `/api/metrics` 包含 `mcp_rate_limited_rejections`、`mcp_bulkhead_rejections`、`mcp_circuit_open_rejections`。
2. `/api/metrics/summary` 包含 `summary.mcp_rejections_total`、`summary.mcp_rejection_ratio`。
- 预期:
1. 字段存在且类型正确（整数/浮点）。
- 记录:
1. 结果：
2. 备注：

### TC20 Metrics History 持久化

- `session_key`: `tc20_metrics_history`
- 步骤:
1. 产生一些流量。
2. 访问历史接口查看 points。
- 检查项:
1. `/api/metrics/history?minutes=60` 的 `points` 非空。
2. 每个点含 `mcp_rate_limited_rejections`、`mcp_bulkhead_rejections`、`mcp_circuit_open_rejections`。
- 预期:
1. 指标按分钟桶落盘且可读。
- 记录:
1. 结果：
2. 备注：

---

## P1（高优先级稳定性，建议当日跑完）

### TC04 同会话并发行为

- `session_key`: `tc04_concurrency`
- 步骤:
1. 打开两个浏览器标签，几乎同时发送请求。
- 发送消息:
标签A：`回复A`
标签B：`回复B`
- 预期:
1. 服务无崩溃。
2. 并发限制按预期生效（排队或限流，不出现脏状态）。
- 记录:
1. 结果：
2. 备注：

### TC05 会话分叉

- `session_key`: `tc05_main` 与 `tc05_branch`
- 步骤:
1. 在 `tc05_main` 发送两条消息。
2. 使用会话分叉功能/API 从主会话 fork 到 `tc05_branch`。
3. 在分叉会话继续发送消息。
- 发送消息:
主会话：`主线消息1`
主会话：`主线消息2`
分叉会话：`我现在在哪条分支？`
- 预期:
1. 分叉会话包含 fork 点之前历史。
2. 分叉后两条会话互不污染。
- 记录:
1. 结果：
2. 备注：

### TC06 会话历史回放

- `session_key`: `tc06_history`
- 步骤:
1. 连续发送 5 条消息。
2. 打开会话历史或调用 history API。
- 发送消息:
`消息1`
`消息2`
`消息3`
`消息4`
`消息5`
- 预期:
1. 5 条消息完整可见。
2. 顺序与时间线正确。
- 记录:
1. 结果：
2. 备注：

### TC09 Bash 失败隔离

- `session_key`: `tc09_bash_fail`
- 步骤:
1. 请求 agent 执行失败命令。
- 发送消息:
`请执行 bash 命令 exit 2，并告诉我退出失败。`
- 预期:
1. 失败被正确感知和解释。
2. 无卡死或崩溃。
- 记录:
1. 结果：
2. 备注：

### TC11 显式记忆写入与召回

- `session_key`: `tc11_memory_write` 和 `tc11_memory_read`
- 步骤:
1. 在写入会话中显式 remember。
2. 新会话提问回忆。
- 发送消息:
写入：`remember: 我最喜欢的数据库是 SQLite`
读取：`我最喜欢的数据库是什么？`
- 预期:
1. 新会话能召回 `SQLite`。
- 记录:
1. 结果：
2. 备注：

### TC12 记忆覆盖（新值生效）

- `session_key`: `tc12_memory_update`
- 步骤:
1. 连续写入同一事实不同值。
2. 立即查询。
- 发送消息:
`remember: 我最喜欢的数据库是 SQLite`
`remember: 我最喜欢的数据库是 Postgres`
`我最喜欢的数据库是什么？`
- 预期:
1. 返回 `Postgres`。
2. 不再返回旧值为主答案。
- 记录:
1. 结果：
2. 备注：

### TC14 定时任务 cron

- `session_key`: `tc14_schedule_cron`
- 步骤:
1. 创建短周期 cron 任务。
2. 至少观察 2 次触发。
3. 暂停任务。
- 发送消息:
`请创建每2分钟执行一次的任务，内容是“周期健康检查”。`
`请暂停这个任务。`
- 预期:
1. 至少触发 2 次。
2. 暂停后不再触发。
- 记录:
1. 结果：
2. 备注：

### TC17 MCP 限流/隔离触发

- `session_key`: `tc17_mcp_guardrail`
- 前置:
1. MCP server 配置低阈值：`max_concurrent_requests=1`，`queue_wait_ms=50`，`rate_limit_per_minute=3`。
- 步骤:
1. 快速连续发送 6 次同类 MCP 请求。
- 发送消息:
`请再次调用 MCP 文件系统工具列出当前目录。`（快速重复）
- 预期:
1. 部分请求出现 rate-limit 或 bulkhead 拒绝。
2. 服务整体保持可用。
- 记录:
1. 结果：
2. 备注：

### TC18 MCP 熔断与恢复

- `session_key`: `tc18_mcp_circuit`
- 前置:
1. 可临时让 MCP 后端不可用（停服务或断连）。
- 步骤:
1. 后端不可用时连续请求 MCP。
2. 恢复后端后再次请求。
- 发送消息:
故障期：`请调用 MCP 工具读取目录。`（连续多次）
恢复后：`请再次调用 MCP 工具读取目录。`
- 预期:
1. 故障期出现快速失败（可能为 circuit-open）。
2. 恢复后重新可成功。
- 记录:
1. 结果：
2. 备注：

---

## P2（扩展覆盖与压力场景）

### TC03 长回复稳定性

- `session_key`: `tc03_long_output`
- 步骤:
1. 发送长输出请求。
- 发送消息:
`请输出一段约3000字的项目稳定性建议，分10段。`
- 预期:
1. 响应完成，无中途报错。
2. 回复结构完整（接近 10 段）。
- 记录:
1. 结果：
2. 备注：

---

## 执行汇总模板

1. 总计用例数：20
2. 通过：
3. 失败：
4. 阻塞：
5. 关键失败说明：
6. 建议修复优先级（P0/P1/P2）：
