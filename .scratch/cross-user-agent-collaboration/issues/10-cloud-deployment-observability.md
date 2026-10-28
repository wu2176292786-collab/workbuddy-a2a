# 10: 腾讯云基础部署与可观测性

**What to build:** 在腾讯云以 Docker Compose 部署 Gateway、PostgreSQL、Redis 和反向代理，提供 HTTPS REST、WSS、备份、健康检查和基础告警。接入已冻结的 monitoring event，展示 Worker 在线状态、Task 积压、失败率、确认超时和 UI 错误。

**Blocked by:** 01: Team 与 Worker 配对; 02: Task 授权与权威状态机; 03: Gateway–Worker 模拟协作契约; 09: Admin console、RBAC、审计与数据治理。

**Status:** complete

- [x] Docker Compose 环境能启动 Gateway、PostgreSQL、Redis 和反向代理
- [x] HTTPS REST 和 WSS 连接具备 TLS、健康检查和断线重连
- [x] Task、event、audit 数据具备备份和恢复验证
- [x] monitoring event 能展示 Worker 在线、队列积压、失败率、确认超时和 UI 错误
- [x] 告警和访问日志遵守敏感字段脱敏与资源限制
- [x] 基础部署不依赖 Windows/macOS Desktop Adapter 已完成

**Implementation:** `deploy/docker-compose.yml`, `deploy/nginx.conf`, `deploy/backup.sh`, and `Dockerfile` define the Tencent Cloud deployment contract. `gateway_worker.monitoring.MonitoringCollector` provides health, Prometheus metrics, redacted event aggregation, and threshold alerts; `SQLiteBackupManager` verifies PoC backup/restore integrity. Coverage is in `tests/test_monitoring_deployment.py`.
