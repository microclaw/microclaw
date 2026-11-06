# MicroClaw 下一阶段规划（2026-11）

状态：**Active**
更新：**2026-11-05**
基线：**v0.23.0**（0.21–0.23 的 MicroClaw Code 功能一次发出，见
[`mccode-next-plan-cn.md`](./mccode-next-plan-cn.md)）

0.23.0 发版时只验证了安装与运行，三批功能没有用真实模型评测过。所以先测试、修补丁，
再做新功能。

## 阶段 0：0.23.0 收尾

| 项 | 状态 |
|---|---|
| Homebrew tap 更新到 0.23.0（含 `mccode` formula） | 完成：tap [`379bb4a`](https://github.com/microclaw/homebrew-tap/commit/379bb4a) |
| 确认 Intel macOS 交叉编译 | 完成：dry run [41982580133](https://github.com/microclaw/microclaw/actions/runs/41982580133) |
| v0.20.0 / v0.23.0 发布证据补全 | 完成（随 0.23.1 的 PR） |
| 本文作为 Active 计划，替换已交付的 `mccode-next-plan-cn.md` | 完成 |
| 吊销旧的 crates.io token | 维护者手动 |
| 回复 nilo（GHSA-xww5-ccxc-48jj 的报告者） | 维护者手动 |
| 清理长期未合并的远程分支（约 100 个） | 完成（2026-11-05）：删除 111 个远程分支，只留 `main`；删除前全部打包备份到维护者本地 |

## 阶段 1：真实模型测试 → 0.23.1

用 DeepSeek（`deepseek-flash`、`deepseek-v4-pro`）跑评测和逐项手测，
结果与修复记录在 [`v0.23.1-plan.md`](./v0.23.1-plan.md)。

状态：完成，[v0.23.1](https://github.com/microclaw/microclaw/releases/tag/v0.23.1)
已于 2026-11-05 发布（crates.io、Homebrew 同步）。

遗留：
- 评测用例太小，还不能衡量 0.21 定的“每个任务 token 降 25%”；需要更大的长会话用例，
  以及 `eval replay` 从本仓库历史生成的回归集。
- 没覆盖：Windows / Linux、Zed 本体、typescript-language-server / gopls、`--remote`。
- `review --pr` 在大 PR 上很慢（> 10 分钟），可以考虑限制工具调用轮数或先按文件分片。
- `context_note` / `rewind_context` 仍默认关闭，需要专门的用例再决定。

## 阶段 2：0.25，MicroClaw Code 体验大版本

原计划的 0.24（模型预设、VS Code、Windows ARM）和 0.25（Windows 沙箱）调整为：0.25 一次完成
[`mccode-ux-config-plan-2026-11-cn.md`](./mccode-ux-config-plan-2026-11-cn.md) 的全部内容
（TUI 改版、交互、四层配置、权限规则、hooks、导入、聊天审批、回执、按块审阅），
模型预设（原 D4）随之完成。交付情况见该文第 10 节。

## 阶段 3：并行轨道

| 项 | 说明 |
|---|---|
| VS Code（原 D1） | 先走 ACP 桥接或轻量扩展，复用 `mccode acp` |
| Windows ARM（原 D6 的一半） | 发版工作流加 `aarch64-pc-windows-msvc` |
| Windows 沙箱（原 E5） | AppContainer 或受限令牌 + Job Object；在此之前 Windows 保持默认 `ask` |
| JetBrains（原 D2） | 等 JetBrains 的 ACP 支持稳定后接入 |
| 评测集扩充 | 见阶段 1 遗留 |
| 0.25 遗留 | Ctrl+B 后台化、对话级回退、子代理角色模型、模型价格表 |

## 暂缓

- nixpkgs：维护者暂停（#491），之后重新提交。
