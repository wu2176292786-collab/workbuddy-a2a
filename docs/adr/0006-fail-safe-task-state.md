# Fail safe when UI state or authorization is uncertain

Workers must use idempotency records before UI injection, expire undelivered Tasks after 24 hours, pause on unexpected human or UI state, route additional information through the original `task_id`, and enter `NEEDS_ATTENTION` when completion cannot be proven. Revoking a Worker blocks new work and requests cooperative cancellation of the current Task; the final state is reported only after a safe stop point or an explicit human decision.

## Consequences

The state machine includes operational states that need human resolution. A Worker must never infer success from a timeout or retry an uncertain UI action automatically.
