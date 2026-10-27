# 02: Task 授权与权威状态机

**What to build:** 为版本化 Task template 建立不可变授权协议和 Gateway 权威状态机。Gateway 对规范化的 sender、recipient、template、input、scope、permissions 和 expiry 计算 `task_hash`，使用一次性 confirmation nonce 和数据库 CAS 状态迁移处理确认、拒绝、过期、取消和终态，并校验 Worker fencing。

**Blocked by:** 01: Team 与 Worker 配对。

**Status:** ready-for-agent

- [ ] Task template、scope、permission、expiry 和输入可规范化并生成稳定 `task_hash`
- [ ] 确认 envelope 绑定 `task_id`、`task_hash`、一次性 nonce、expiry 和认证接收方身份
- [ ] 输入、template、permission、recipient、scope 或 expiry 变化会使旧确认失效
- [ ] Gateway 是唯一状态权威，状态迁移使用 expected `state_version` 和 CAS
- [ ] 终态包括 `REJECTED`、`COMPLETED`、`FAILED`、`CANCELLED` 和 `EXPIRED`，迟到事件不会重新打开 Task
- [ ] 每个 Task lease 校验 `worker_id`、`worker_epoch` 和 fencing token
