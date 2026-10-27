# 11: 受控 PoC 验收

**What to build:** 使用测试账号和合成数据，在一台 Windows 和一台 macOS 电脑上完成真实 ClawBot 确认、双平台 WorkBuddy 执行、至少两轮协调、结果回传和双方通知，并对全部 P0 安全门槛给出独立结论。此票只负责验收，不新增实现工作。

**Blocked by:** 04: 可运行的执行隔离与结果出口; 05: Windows WorkBuddy Desktop Adapter; 06: macOS WorkBuddy Desktop Adapter; 07: 真实 ClawBot 确认与通知 Adapter; 08: 跨组件崩溃恢复与对抗性一致性; 09: Admin console、RBAC、审计与数据治理; 10: 腾讯云基础部署与可观测性。

**Status:** ready-for-agent

- [ ] 两个平台的 Worker 均能通过真实 ClawBot 通路接收确认并完成 Task
- [ ] 至少两轮协调在同一个 `task_id` 下完成，结果到达双方 WorkBuddy 和 ClawBot
- [ ] 断线、重连、过期、取消和 UI 不确定状态均符合安全状态机
- [ ] 重放、身份伪造、旧 Worker、崩溃窗口、并发竞态和提示注入测试全部通过
- [ ] 功能成功率按声明的样本量、平台分布和故障条件达到至少 90%
- [ ] 重复执行和未授权执行为零；未通过 P0 门槛时明确禁止真实账号和真实数据
