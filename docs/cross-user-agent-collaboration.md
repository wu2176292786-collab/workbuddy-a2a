# Cross-user Agent collaboration PoC

> **Security status:** This design is restricted to controlled demonstrations with test accounts and synthetic data until the P0 authorization, isolation, crash-recovery, and Worker-fencing gates in the security amendment are implemented and tested. TLS alone does not satisfy those gates.

## Goal

Allow one person's WorkBuddy Agent to delegate a bounded Task to another person's WorkBuddy Agent, obtain a first-round confirmation through the recipient's WeChat/ClawBot path, coordinate over multiple rounds, and return a result to both people.

## Architecture

```text
User A WeChat → ClawBot → WorkBuddy A → Worker A ─┐
                                                  ├─ WSS/TLS ─ Gateway
User B WeChat ← ClawBot ← WorkBuddy B ← Worker B ─┘
```

WorkBuddy does not log in to the Gateway. Each computer runs one device-bound Worker. The Worker maintains an outbound WSS connection to the Gateway and automates the already-authenticated WorkBuddy desktop App. The Gateway routes Tasks by `agent_id`, persists Task and audit state, and enforces the Team allowlist.

## Enrollment

1. An administrator creates the Team member and Agent records.
2. The user installs the Worker and starts pairing.
3. The Worker generates a device keypair and stores the private key in the OS credential store.
4. The user submits a one-time, single-use pairing code bound to the intended Team and Agent; the administrator approves it.
5. The Gateway binds `worker_id` to `agent_id`, assigns a monotonic `worker_epoch`, and returns a short-lived session credential.
6. The Worker connects to `wss://gateway.example.com/v1/worker/ws`, sends a signed handshake with a fresh nonce and timestamp, and starts heartbeats.

Pairing codes have high entropy, a short lifetime, a bounded attempt count, and are invalidated after use. Every subsequent Worker event is checked against the current public key, `worker_epoch`, session, lease, and fencing token; authentication at WebSocket connect time alone is insufficient.

The PoC permits one Active Worker per Agent. Replacing a computer means pairing a new Worker and revoking the old one.

## Task flow

1. WorkBuddy A creates a Task using an administrator-approved Task template.
2. The Gateway normalizes the sender, recipient, template version, input, immutable scope, permission set, and expiry into a canonical form and computes an immutable `task_hash`.
3. Worker A sends the Task envelope to the Gateway. Sender and Team identity are derived from the authenticated Worker session; self-reported envelope identities are ignored.
4. The Gateway validates the target Agent, template, protocol version, size limits, authorization scope, and current Worker fencing state.
5. Worker B receives the Task, checks its durable command journal, and writes it into the dedicated collaboration conversation in WorkBuddy B only when the command has not already been proven to have run.
6. The recipient confirms or rejects using a machine-readable confirmation envelope containing `task_id`, `task_hash`, a one-time `confirmation_nonce`, and `expires_at`.
7. The Gateway consumes the confirmation once with a conditional state update. Any input, template, permission, recipient, or scope change creates a new hash and requires a new confirmation.
8. After acceptance, Workers exchange Task events through the Gateway. Additional information stays under the original `task_id` and remains inside the immutable scope and round/byte/time budgets.
9. Worker B reports template-defined execution evidence or enters `NEEDS_ATTENTION` when completion cannot be established.
10. The Gateway validates the evidence, applies the result egress policy, routes the approved result to Worker A, and records the lifecycle events. Both WorkBuddy sessions notify their users through ClawBot.

## Message envelope

```json
{
  "protocol_version": "1",
  "message_id": "msg_01J...",
  "task_id": "tsk_01J...",
  "task_hash": "sha256:...",
  "team_id": "team_demo",
  "from_agent": "agent_alice",
  "to_agent": "agent_bob",
  "type": "delegate",
  "title": "Summarize the customer research",
  "input": {"topic": "..."},
  "requires_confirmation": true,
  "scope": {"template": "research_summary", "version": "1", "tools": [], "resources": []},
  "expires_at": "2026-10-27T12:00:00Z",
  "context_policy": "minimal",
  "created_at": "2026-10-26T12:00:00Z"
}
```

The confirmation envelope additionally carries `confirmation_nonce`, `task_hash`, and the recipient's authenticated channel identity. A nonce is single-use. A plain message containing only a `task_id` is not a valid approval. A natural-language response from a WorkBuddy UI is not cryptographic proof of user intent; the production gate therefore requires a signed or otherwise authenticated confirmation channel bound to the recipient and nonce. Until that channel exists, confirmation is suitable only for controlled demonstrations.

Messages are delivered at least once and deduplicated by `task_id + message_id`. The Gateway stores durable Task and audit state in PostgreSQL; Redis holds presence, leases, and short-lived queue data.

## State model

```text
CREATED → WAITING_RECIPIENT_CONFIRM → ACCEPTED → RUNNING
                                      ↘ REJECTED
RUNNING → NEEDS_INPUT → RUNNING
RUNNING → CANCEL_REQUESTED → CANCELLED | RUNNING
RUNNING → COMPLETED | FAILED | NEEDS_ATTENTION
WAITING_RECIPIENT_CONFIRM → EXPIRED
```

The Gateway is the sole state authority. Every transition carries an expected `state_version` and uses a database compare-and-set update. `REJECTED`, `COMPLETED`, `FAILED`, `CANCELLED`, and `EXPIRED` are terminal. Late events are retained as audit evidence but cannot reopen a terminal Task. `NEEDS_ATTENTION` can resume only through an explicit operator action; if scope or authorization changes, a new confirmation is required. Undelivered Tasks expire after 24 hours. Unexpected UI state, human interference, login screens, update dialogs, or uncertain completion always produce `NEEDS_ATTENTION`.

Each Task also has an immutable scope, maximum round count, maximum bytes, maximum execution duration, and absolute expiry. A new tool, resource, recipient, or output field outside that scope requires re-approval.

## Desktop Worker

The Worker targets the WorkBuddy desktop App. It uses Windows UI Automation or macOS Accessibility APIs first. Screenshot/OCR and clipboard fallback are disabled by default and require a separate explicit capability grant. It operates a dedicated collaboration conversation under an isolated OS user, independent WorkBuddy account, or equivalent restricted workspace; a merely separate chat is not treated as a security boundary. The Worker enforces a tool and resource allowlist and cannot access ordinary conversations, arbitrary files, or unapproved tools. It never automates WorkBuddy login or stores WorkBuddy credentials.

The PoC pins one supported WorkBuddy App version per platform. Installation verifies the required OS automation permission, the collaboration conversation, and the app's logged-in state.

Before UI injection, the Worker durably records a `command_id`, target conversation, normalized execution intent, and current Worker epoch. After injection it must locate the same `command_id` or equivalent template-defined evidence before acknowledging execution. If a crash occurs in the uncertain window, reconnect recovery checks the UI; inability to prove whether the command ran enters `NEEDS_ATTENTION` and forbids blind retry.

## Security and governance

- All Worker traffic uses TLS/WSS.
- Worker private keys remain in the OS credential store; the Gateway stores public keys and device state.
- Every Task has an immutable `task_hash`; confirmation is one-time, nonce-bound, expiry-bound, and consumed with a conditional state update.
- The recipient confirmation channel must be cryptographically or locally authenticated; text that merely resembles an approval is never sufficient for real-account execution.
- Every Task lease carries `worker_id`, `worker_epoch`, and a fencing token. Old epochs and revoked sessions cannot change Task state.
- Administrators control Team membership, Agent allowlists, Pairing, Task templates, and Device revocation.
- Gateway and Worker reject incompatible `protocol_version` values.
- Logs exclude full WorkBuddy and WeChat transcripts and retain Task metadata and result summaries for 30 days.
- Task payloads and result bodies have a separately configured short retention period; the controlled-demo default is 7 days, with deletion and export actions audited.
- Admin access requires MFA and RBAC. Admin actions, data exports, deletion, and revocations are audited and sensitive fields are redacted from logs and notifications.
- The PoC supports read-only or draft-producing templates and does not perform external writes, sends, deletes, or submissions.
- Revoking a Worker invalidates its key and sessions, blocks new Tasks, and does not silently reassign an active Task.
- Results pass a template-defined egress policy; sensitive fields are blocked or require recipient-side approval before they can reach the sender.
- Gateway applies per-user, per-Agent, and per-Worker rate limits plus bounds on active Tasks, rounds, message bytes, event frequency, and queue depth.

## Deployment

The first deployment uses Docker Compose on one Tencent Cloud server: reverse proxy, Gateway, PostgreSQL, and Redis. HTTPS REST serves administration and setup; WSS carries Worker events and heartbeats. A minimal Admin console manages the Team and provides task/audit views.

## Acceptance

- One Windows and one macOS Worker complete an end-to-end delegated Task.
- Recipient confirmation is required before execution.
- At least two coordination rounds complete under one `task_id`.
- The result reaches both WorkBuddy sessions and both users are notified through ClawBot.
- Duplicate delivery never causes duplicate UI execution.
- Unauthorized Agents are rejected and audited.
- Disconnect/reconnect restores state without losing or silently repeating a Task.
- UI uncertainty never produces a false `COMPLETED` result.
- Initial target success rate is at least 90%; duplicate executions and unauthorized executions are zero-tolerance failures.

The security gate also requires adversarial tests for modified inputs after confirmation, replayed confirmations/results/cancellations, forged envelope identities, revoked and old-epoch Workers, crash points before and after UI injection and ACK, concurrent confirmation/cancellation/expiry/completion, prompt injection against the isolation boundary, sensitive result egress, and late events after terminal states. The success-rate metric is reported separately from these security invariants and includes sample size, platform split, and injected network/UI failures.
