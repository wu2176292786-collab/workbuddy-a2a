# 11: 受控 PoC 验收

**What to build:** 使用测试账号和合成数据，在一台 Windows 和一台 macOS 电脑上完成真实 ClawBot 确认、双平台 WorkBuddy 执行、至少两轮协调、结果回传和双方通知，并对全部 P0 安全门槛给出独立结论。此票只负责验收，不新增实现工作。

**Blocked by:** 04: 可运行的执行隔离与结果出口; 05: Windows WorkBuddy Desktop Adapter; 06: macOS WorkBuddy Desktop Adapter; 07: 真实 ClawBot 确认与通知 Adapter; 08: 跨组件崩溃恢复与对抗性一致性; 09: Admin console、RBAC、审计与数据治理; 10: 腾讯云基础部署与可观测性。

**Status:** ready-for-human

- [ ] 两个平台的 Worker 均能通过真实 ClawBot 通路接收确认并完成 Task（需要真实 ClawBot 与两台物理设备的人工记录）
- [x] 合成 ClawBot 与双平台适配器契约完成 20/20 样本，两轮协调保持同一个 `task_id`，双方均收到任务、状态和结果通知
- [x] 断线、重连、过期、取消和 UI 不确定状态均符合安全状态机
- [x] 重放、身份伪造、旧 Worker、崩溃窗口、并发竞态和提示注入测试全部通过
- [x] 健康样本功能成功率为 20/20（Windows 10/10、macOS 10/10），高于 90% 门槛；注入的 UI 故障均安全停止
- [x] 重复执行和未授权执行为零；未通过真实 P0 门槛时明确禁止真实账号和真实数据

**Acceptance evidence:** [`docs/controlled-poc-acceptance.md`](../../../docs/controlled-poc-acceptance.md) and `tests/test_controlled_poc_acceptance.py` record the synthetic matrix and each independent P0 conclusion. The physical real-ClawBot run remains `ready-for-human`.
