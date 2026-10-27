# 03: Gateway–Worker 模拟协作契约

**What to build:** 使用 Fake Desktop adapter 完成一个可重复的端到端协作闭环，包括两轮消息、`NEEDS_INPUT`、执行证据和结果回传。冻结后续真实 Desktop adapter 复用的 command、event、evidence、reconciliation 和 monitoring 契约，并验证协议级 journal 与 replay 防护。

**Blocked by:** 02: Task 授权与权威状态机。

**Status:** complete

- [x] Fake Worker 能提交 Task、接收投递、发送确认并完成至少两轮协调
- [x] `NEEDS_INPUT` 能在原始 `task_id` 下往返并受原 scope 限制
- [x] `command_id`、Task event、执行证据和 UI reconciliation 契约已冻结并有契约测试
- [x] Fake adapter 能生成模板定义的完成证据和结果摘要
- [x] 记录过的重复 event、confirmation、result 和 cancellation 不会改变状态或重复执行
- [x] UI 错误、积压、失败率和执行证据事件具有稳定格式

**Implementation:** `gateway_worker/collaboration.py` provides the deterministic `FakeWorker`, `FakeDesktopAdapter`, protocol `Command`/`TaskEvent`/`ExecutionEvidence`/`UIReconciliation`/`MonitoringEvent` contracts, two-round `FakeCollaboration` flow, scope-bounded `NEEDS_INPUT`, result egress to both Agent sessions, and replay-safe command/event/result/cancellation journals. Contract coverage is in `tests/test_fake_collaboration.py`.
