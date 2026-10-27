# Pair Workers with one active device per Agent

Workers are enrolled with a one-time pairing code followed by administrator approval, and the PoC permits one active Worker per Agent. This gives the Gateway a revocable device identity without collecting WorkBuddy credentials and avoids duplicate UI execution while the task protocol is still being validated. Tasks may remain queued while a Worker is offline, but expire after a defined TTL (24 hours for the PoC).

## Considered Options

- Long-lived bearer tokens copied into Worker configuration: rejected because they are harder to rotate and revoke safely.
- Multiple active Workers per Agent: deferred because simultaneous UI execution can duplicate tasks and complicate ownership.

## Consequences

Replacing a computer requires pairing a new Worker and revoking the old device. The Worker must emit a machine-readable confirmation envelope containing the Task ID; free-form approval text is not sufficient for routing state.
