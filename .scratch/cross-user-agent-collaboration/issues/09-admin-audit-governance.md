# 09: Admin console、RBAC、审计与数据治理

**What to build:** 提供管理员 MFA/RBAC 和最小 Admin console，管理 Team、User、Agent、Worker、Task template 和设备撤销；实现 30 天审计、任务内容短期保留、导出/删除审计、敏感字段脱敏和资源限制配置。

**Blocked by:** 01: Team 与 Worker 配对; 02: Task 授权与权威状态机; 03: Gateway–Worker 模拟协作契约。

**Status:** ready-for-agent

- [ ] 管理员 MFA/RBAC 能限制成员、设备、template 和审计操作
- [ ] 能创建、暂停和移除 Team 成员与 Agent，并批准或撤销 Worker
- [ ] 能查看 Task、Worker 和管理员操作的 30 天审计事件
- [ ] Task payload/result 有独立短期保留策略，导出和删除均被审计
- [ ] 日志、通知和审计视图会脱敏密码、Token、密钥和敏感字段
- [ ] 能配置活动 Task、轮数、字节数、事件频率和队列深度限制
