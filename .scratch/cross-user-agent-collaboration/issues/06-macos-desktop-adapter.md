# 06: macOS WorkBuddy Desktop Adapter

**What to build:** 使用 macOS Accessibility API 操作专用 WorkBuddy 协作会话，提供与 Windows adapter 对称的权限检查、输入、回复读取、执行证据、command journal、UI reconciliation 和安全暂停行为。

**Blocked by:** 03: Gateway–Worker 模拟协作契约; 04: 可运行的执行隔离与结果出口。

**Status:** complete

- [x] 能验证 macOS Accessibility 权限和受支持的 WorkBuddy App 版本
- [x] 能选择专用协作会话并完成输入、回复读取和状态识别
- [x] UI 操作前持久化 `command_id`、目标会话和执行意图
- [x] 重连时能通过 UI reconciliation 判断 command 是否已执行；不确定时进入 `NEEDS_ATTENTION`
- [x] 登录页、更新弹窗、人工焦点变化和控件缺失不会被自动绕过
- [x] 能回传模板定义的执行证据和结构化错误事件

**Implementation:** `gateway_worker/macos_adapter.py` provides the macOS Accessibility compatibility profile, adapter and fake backend with the same file-backed command journal, dedicated conversation checks, completion evidence, reconciliation, structured safe-stop errors, and capability-gated clipboard restoration as the Windows contract. Contract coverage is in `tests/test_macos_adapter.py`.
