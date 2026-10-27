# 08: 跨组件崩溃恢复与对抗性一致性

**What to build:** 作为纯验证票，对 Gateway、Fake/Windows/macOS Worker 和 ClawBot Adapter 做跨组件故障注入与一致性回归。覆盖 UI 写入前后、执行记录前后、ACK 前后崩溃，旧 Worker epoch、fencing、重放、并发状态竞态和终态迟到事件；不承担基础 journal 实现。

**Blocked by:** 03: Gateway–Worker 模拟协作契约; 05: Windows WorkBuddy Desktop Adapter; 06: macOS WorkBuddy Desktop Adapter; 07: 真实 ClawBot 确认与通知 Adapter。

**Status:** ready-for-agent

- [ ] 在 UI 写入前后、执行记录前后、ACK 前后终止 Worker，均不会盲目重复执行
- [ ] 旧 Worker epoch、撤销设备、过期 lease 和 stale fencing token 的事件无法改变状态
- [ ] 重放 confirmation、result、cancellation 和 ClawBot 消息不会重复执行或重新打开 Task
- [ ] confirmation、cancellation、expiry、completion 并发到达时只有一个可解释的终态
- [ ] 终态后的迟到事件只进入审计，不会恢复 Task
- [ ] 生成独立的安全门槛报告，区分安全不变量和功能成功率
