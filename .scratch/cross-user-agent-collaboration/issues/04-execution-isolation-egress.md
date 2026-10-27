# 04: 可运行的执行隔离与结果出口

**What to build:** 提供可运行的测试账号或受限 WorkBuddy workspace，使协作 Task 只能访问模板 allowlist 中的工具和资源。实现结果 egress 策略，对敏感字段阻断或要求接收方批准；剪贴板、截图和 OCR 默认关闭。

**Blocked by:** 03: Gateway–Worker 模拟协作契约。

**Status:** complete

- [x] 测试账号或受限 workspace 与普通 WorkBuddy 会话、文件和工具隔离
- [x] Task template 的工具、资源、输出字段和结果接收方由机器规则强制执行
- [x] 提示注入不能访问普通会话、任意文件或未授权工具
- [x] 敏感结果字段会被阻断或进入接收方批准流程
- [x] 默认关闭截图/OCR 和剪贴板回退，显式启用时有独立能力记录
- [x] 隔离失败时 Task 进入 `NEEDS_ATTENTION`，不会依赖自然语言提示自我约束

**Implementation:** `gateway_worker/isolation.py` provides versioned template allowlists, `RestrictedWorkspace` conversation/tool/resource enforcement, explicit fallback capability grants, and `ResultEgressPolicy` sensitive-field filtering or recipient approval. `FakeCollaboration` enforces the boundary before adapter execution and moves isolation failures to `NEEDS_ATTENTION`; result completion routes through the egress policy. Contract coverage is in `tests/test_execution_isolation.py`.
