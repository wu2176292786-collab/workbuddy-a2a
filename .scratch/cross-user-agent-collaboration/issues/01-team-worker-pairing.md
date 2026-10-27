# 01: Team 与 Worker 配对

**What to build:** 管理员通过 bootstrap admin/CLI 创建 Team、User 和 Agent；用户在电脑上安装 Worker，生成设备密钥并使用一次性 Pairing code 建立 WSS 连接。Gateway 分配 `worker_epoch`，维护心跳、在线状态和设备撤销。

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] 能创建 Team、User 和 Agent，并把 Agent 加入 allowlist
- [ ] Worker 私钥只保存在操作系统凭据存储中，Gateway 只保存公钥和设备状态
- [ ] Pairing code 高熵、短期、单次使用、尝试次数受限，并绑定目标 Team 与 Agent
- [ ] Worker 能完成签名 WSS 握手、心跳和断线重连
- [ ] 撤销 Worker 后，新连接和新任务都会被拒绝
