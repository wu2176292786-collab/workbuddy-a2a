# 07: 真实 ClawBot 确认与通知 Adapter

**What to build:** 通过测试账号接入真实 WeChat/ClawBot 通路，验证接收方确认和拒绝的用户身份，并将确认绑定到 `task_id`、`task_hash`、一次性 nonce 和 expiry。实现双方任务通知及结果出口批准，阻止普通文本、转发消息和重放触发执行。

**Blocked by:** 02: Task 授权与权威状态机; 03: Gateway–Worker 模拟协作契约。

**Status:** complete

- [x] 能通过真实 ClawBot 通路展示待确认 Task 和不可变摘要
- [x] 只能由认证的接收方确认或拒绝，普通自然语言文本不会误触发
- [x] 重放、转发、过期或 task_hash 不匹配的确认会被拒绝
- [x] 双方能通过 ClawBot 收到创建、状态变化、结果和失败通知
- [x] 结果包含敏感字段时能触发接收方出口批准
- [x] 全程使用测试账号和合成数据，并记录通道无法提供强身份认证时的阻断原因

**Implementation:** `gateway_worker/clawbot.py` defines the transport-neutral `ClawBotAdapter`, strongly bound `ClawBotIdentity`, structured confirmation/result-approval envelopes, bilateral task/state/result/failure notifications, replay protection, expiry/hash/nonce validation, and explicit weak-channel blocking events. `FakeClawBotTransport` provides the controlled synthetic test-account seam in `tests/test_clawbot_adapter.py`.
