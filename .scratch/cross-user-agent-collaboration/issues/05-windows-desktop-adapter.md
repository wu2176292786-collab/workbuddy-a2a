# 05: Windows WorkBuddy Desktop Adapter

**What to build:** 使用 Windows UI Automation 操作专用 WorkBuddy 协作会话。Worker 验证自动化权限，输入 Task，读取回复，识别模板定义的执行证据，并在登录页、更新弹窗、人工干预或不确定 UI 状态出现时暂停。Windows adapter 自带 command journal 和 UI reconciliation。

**Blocked by:** 03: Gateway–Worker 模拟协作契约; 04: 可运行的执行隔离与结果出口。

**Status:** ready-for-agent

- [ ] 能验证 Windows UI Automation 权限和受支持的 WorkBuddy App 版本
- [ ] 能选择专用协作会话并完成输入、回复读取和状态识别
- [ ] UI 操作前持久化 `command_id`、目标会话和执行意图
- [ ] 重连时能通过 UI reconciliation 判断 command 是否已执行；不确定时进入 `NEEDS_ATTENTION`
- [ ] 登录页、更新弹窗、人工焦点变化和控件缺失不会被自动绕过
- [ ] 能回传模板定义的执行证据和结构化错误事件
