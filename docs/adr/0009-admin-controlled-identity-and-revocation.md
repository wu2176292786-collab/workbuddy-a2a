# Keep identity and revocation under administrator control

The Gateway provides a minimal Admin console. Administrators create and suspend Users and Agents, approve Pairing, manage Task templates, inspect audit events, and revoke Workers. Internal `user_id`, `agent_id`, and `worker_id` values remain separate from WeChat and WorkBuddy account names. Revoking a Worker immediately invalidates its key and sessions, blocks new Tasks, and does not automatically reassign its current Task.

## Consequences

The PoC requires a small administrative workflow before a Worker can participate. This adds setup steps but prevents self-enrollment, ambiguous ownership, and silent reassignment after a device compromise.
