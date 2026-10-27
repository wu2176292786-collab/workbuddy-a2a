# Cross-user Agent collaboration PoC spec

## Problem Statement

Each person can reach their own WorkBuddy Agent through WeChat and ClawBot, but one Agent cannot safely delegate a Task to another person's Agent. WorkBuddy does not provide the required multi-account, cross-user Agent communication model, and the existing setup has no shared routing, confirmation, multi-round coordination, or result-return channel.

The desired outcome is a small-team PoC in which a User delegates a bounded Task to a colleague's Agent, the recipient confirms through their existing WeChat/ClawBot path, the recipient's WorkBuddy Agent executes through a local Worker, both Agents can exchange constrained follow-up messages, and the result reaches both Users.

The current design is suitable only for a controlled demonstration until the security gates in this spec pass. Real WorkBuddy accounts, real user data, and external side effects remain blocked until authorization binding, execution isolation, crash recovery, and Worker fencing are implemented and adversarially tested.

## Solution

Add a cloud Gateway and one device-bound Worker per participating computer.

- The Gateway authenticates Workers, enforces the Team and Agent allowlist, routes Task events, persists Task state, applies limits, and records audit events.
- A Worker maintains an outbound WSS/TLS connection to the Gateway and drives the already-authenticated WorkBuddy desktop App on its computer.
- WorkBuddy credentials remain local. WorkBuddy does not log in to the Gateway.
- Agents communicate virtually through the Gateway; Workers do not create direct peer-to-peer sessions.
- The Worker uses Windows UI Automation or macOS Accessibility APIs first. Screenshot/OCR and clipboard fallback require explicit capability grants and are disabled by default.
- The recipient uses a dedicated collaboration conversation under a genuine isolated OS user, independent WorkBuddy account, or equivalent restricted workspace. A separate chat alone is not a security boundary.
- The first deployment is a single Tencent Cloud Docker Compose environment with a reverse proxy, Gateway, PostgreSQL, Redis, and a minimal Admin console.

The highest test seam is the end-to-end Task lifecycle from authenticated Worker submission through Gateway routing, recipient confirmation, constrained coordination, execution evidence, result egress, and terminal state. A fake Desktop adapter can exercise this seam deterministically. Real Windows and macOS Desktop adapters then satisfy the same Worker contract through platform-specific contract tests.

## User Stories

1. As a User, I want to ask my WorkBuddy Agent to delegate a bounded Task to a named colleague's Agent, so that I can obtain help without manually copying the request between computers.
2. As a User, I want the delegation to include only the normalized input, approved template, immutable scope, permissions, recipient, and expiry, so that unnecessary conversation history is not shared.
3. As a User, I want the Gateway to reject an unknown or unauthorized target Agent, so that only the Team allowlist can receive delegated Tasks.
4. As a recipient User, I want to see a clear Task summary and sender identity before execution, so that I know what I am approving.
5. As a recipient User, I want to accept or reject a Task through my authenticated confirmation channel, so that approval is tied to my identity and the exact Task contents.
6. As a recipient User, I want a modified input, template, permission, recipient, scope, or expiry to invalidate the old approval, so that a previous approval cannot authorize new work.
7. As a recipient User, I want accepted Tasks to start automatically within the approved scope, so that I do not need to repeat the approval for every ordinary coordination turn.
8. As either User, I want both Agents to exchange constrained follow-up messages under one Task ID, so that clarification does not create an untracked side channel.
9. As a receiving Agent, I want to request missing information with a `NEEDS_INPUT` state, so that the original sender can provide it without expanding authorization silently.
10. As a User, I want maximum rounds, bytes, execution time, and absolute expiry to limit a long-running Task, so that a first approval cannot become unlimited work.
11. As a User, I want the Gateway to route a Task to a temporarily offline Worker and expire it after the configured TTL, so that an old request cannot execute unexpectedly days later.
12. As a User, I want to cancel a Task before execution, so that work can be withdrawn before it starts.
13. As a User, I want a running Task to support cooperative cancellation with an explicit safe-stop result, so that the system does not claim an uncertain stop.
14. As a User, I want an unexpected WorkBuddy window, login prompt, update dialog, or human interaction to pause the Task, so that automation never overwrites uncertain UI state.
15. As a User, I want a Worker crash before or after UI injection to recover safely, so that the same command is not blindly entered twice.
16. As a User, I want an uncertain UI command to enter `NEEDS_ATTENTION`, so that an operator can resolve it without the system inventing success.
17. As a User, I want a completed result to include template-defined execution evidence, so that completion is based on verifiable output rather than an Agent's claim.
18. As a recipient User, I want a result egress policy to block sensitive fields or request my approval, so that my Agent cannot automatically disclose protected data to the sender.
19. As a User, I want a text result summary returned to both WorkBuddy sessions and surfaced through ClawBot, so that both parties know the outcome.
20. As an Administrator, I want to create and suspend Team members and Agents, so that participation is controlled centrally.
21. As an Administrator, I want to approve Pairing and revoke a Worker device, so that a lost or compromised computer can be removed immediately.
22. As an Administrator, I want Worker replacement to create a new monotonic Worker epoch, so that an old device cannot continue controlling Tasks after the replacement.
23. As an Administrator, I want to publish a small set of versioned Task templates, so that allowed inputs, tools, outputs, and confirmation rules are explicit.
24. As an Administrator, I want to view Task and Worker lifecycle audit events for 30 days, so that failures, approvals, revocations, and state changes can be investigated.
25. As an Administrator, I want admin actions, exports, deletions, and revocations to require MFA/RBAC and to be audited, so that control-plane changes are accountable.
26. As a User, I want task payloads and result bodies to have a separate short retention period, so that the 30-day audit window does not imply indefinite content retention.
27. As a Worker, I want to authenticate with a device key held in the operating-system credential store, so that the Gateway never receives a WorkBuddy password.
28. As a Worker, I want every event to be checked against the current public key, session, Worker epoch, lease, and fencing token, so that an old or revoked connection cannot mutate Task state.
29. As a Gateway, I want sender, recipient, and Team identity to come from the authenticated Worker session, so that forged envelope fields cannot change authorization.
30. As a Gateway, I want state transitions to use an expected state version and database compare-and-set, so that confirmation, cancellation, expiry, and completion races resolve to one explainable state.
31. As a Gateway, I want late events after a terminal state to be retained as audit evidence without reopening the Task, so that retries cannot resurrect completed or cancelled work.
32. As a Worker, I want to operate a dedicated collaboration conversation and a pinned supported WorkBuddy App version, so that UI selectors and completion checks are testable.
33. As a Worker, I want installation to verify OS automation permissions and the logged-in WorkBuddy state, so that the Worker fails during setup rather than during an active Task.
34. As an Administrator, I want pairing codes to be high-entropy, short-lived, single-use, attempt-limited, and bound to the intended Team and Agent, so that enrollment resists replay and misbinding.
35. As a Gateway, I want per-user, per-Agent, and per-Worker rate limits plus bounds on active Tasks, rounds, bytes, event frequency, and queue depth, so that resource exhaustion is controlled.
36. As a Security operator, I want to replay confirmations, results, and cancellation events, so that I can prove they do not cause duplicate execution or invalid state changes.
37. As a Security operator, I want to kill a Worker before and after UI injection and before and after ACK, so that crash recovery is tested at the side-effect boundary.
38. As a Security operator, I want to run prompt-injection inputs against the isolated WorkBuddy workspace, so that ordinary conversations, arbitrary files, and unapproved tools remain inaccessible.
39. As a Security operator, I want to test sensitive result egress and forged identities, so that the Gateway ignores self-reported `from_agent` and `team_id` and blocks unauthorized disclosure.
40. As a Team member, I want the system to state clearly that the PoC uses test accounts and synthetic data until all P0 gates pass, so that a demonstration is not mistaken for production readiness.

## Implementation Decisions

- **Identity model**: `User`, `Agent`, and `Worker` are separate identities. Internal IDs are independent of WeChat IDs, WorkBuddy names, and device names. A Team owns the allowlist.
- **Enrollment**: the Worker generates its keypair locally; the private key stays in the OS credential store. Pairing uses a high-entropy, short-lived, single-use code bound to a Team and Agent, followed by administrator approval. Re-pairing increments `worker_epoch`.
- **Worker transport**: administration and setup use HTTPS REST; Worker events and heartbeats use outbound WSS/TLS. No inbound Worker port is required.
- **Gateway authority**: the Gateway owns Task state. Every event carries an expected `state_version`; only conditional database updates may advance the state. Worker events are requests/evidence, not authoritative state changes.
- **Task binding**: the Gateway canonicalizes sender, recipient, template version, normalized input, immutable scope, permissions, and expiry into `task_hash`. Confirmation includes `task_id`, `task_hash`, a one-time nonce, expiry, and authenticated recipient identity. A plain natural-language approval is insufficient for real-account execution.
- **Authenticated confirmation**: the production gate requires a signed or otherwise authenticated confirmation channel bound to the recipient and nonce. If ClawBot/WorkBuddy can expose only ordinary UI text, the system remains test-only.
- **Task constraints**: each Task has a versioned template, immutable scope, allowed tools/resources, output fields, maximum rounds, maximum bytes, maximum execution time, and absolute expiry. Scope expansion or a new tool, resource, recipient, or output field requires a new confirmation.
- **State machine**: states include `CREATED`, `WAITING_RECIPIENT_CONFIRM`, `ACCEPTED`, `RUNNING`, `NEEDS_INPUT`, `NEEDS_ATTENTION`, `CANCEL_REQUESTED`, `REJECTED`, `COMPLETED`, `FAILED`, `CANCELLED`, and `EXPIRED`. `REJECTED`, `COMPLETED`, `FAILED`, `CANCELLED`, and `EXPIRED` are terminal. `NEEDS_ATTENTION` resumes only through an explicit operator action; changed scope requires re-approval.
- **Delivery**: delivery is at least once. `task_id + message_id` deduplication handles recorded duplicates, while a durable Worker command journal and reconnect UI reconciliation handle crashes around UI side effects. If execution cannot be proven, the Worker enters `NEEDS_ATTENTION` and never blind-retries.
- **Fencing**: every Task lease and Worker event includes the current `worker_id`, `worker_epoch`, lease, and fencing token. Revoked or superseded Workers are disconnected and their later events cannot mutate state.
- **Execution isolation**: a dedicated chat is not considered isolation. The supported execution boundary is an isolated OS user, independent WorkBuddy account, or equivalent restricted workspace, plus machine-enforced tool/resource allowlists and a result egress policy. Ordinary conversations, arbitrary files, and unapproved tools are inaccessible.
- **Desktop adapter**: Windows uses UI Automation and macOS uses Accessibility APIs first. Screenshot/OCR and clipboard fallback are disabled by default and require explicit capabilities. The adapter uses a dedicated collaboration conversation and a pinned supported WorkBuddy App version; it never automates WorkBuddy login.
- **Execution evidence**: each Task template defines evidence required for `COMPLETED`, such as a matching command identifier, valid output schema, absence of unresolved input/tool calls, and a consistent result hash. Agent text claiming completion is not evidence.
- **Persistence**: PostgreSQL stores durable Team, identity, Worker, Task, Task event, template, and audit state. Redis stores presence, leases, and short-lived queue data. Full WorkBuddy/WeChat transcripts are not stored.
- **Data governance**: audit metadata is retained for 30 days. Task payloads and result bodies have a separately configured short retention period, with deletion and export actions audited. Sensitive fields are redacted from logs and notifications.
- **Administration**: a minimal Admin console supports MFA/RBAC, Team and Agent lifecycle, Pairing approval, Worker revocation, template management, Task inspection, and audit access.
- **Deployment**: the PoC runs Gateway, PostgreSQL, Redis, and a reverse proxy in Docker Compose on one Tencent Cloud server. The design keeps `tenant_id/team_id` boundaries even though the first deployment serves one customer Team.
- **Initial templates**: the first templates are read-only/draft-producing “research summary” and “structured information extraction”. External sends, writes, deletes, submissions, arbitrary file access, and file transfer are excluded.

## Testing Decisions

- Tests assert external behavior at the highest seam: the Gateway + Worker Task lifecycle. They do not assert internal classes, database implementation details, or UI selector choices.
- A fake Desktop adapter drives deterministic end-to-end tests for Task creation, canonical hashing, confirmation, multi-round coordination, egress, state races, expiry, cancellation, fencing, and audit behavior.
- A Worker contract suite verifies the durable command journal, idempotency, reconnect reconciliation, `NEEDS_ATTENTION`, lease/fencing checks, resource limits, and protocol-version rejection.
- Windows and macOS Desktop adapters each have contract tests for permission checks, dedicated conversation selection, input injection, reply extraction, completion evidence, unexpected dialogs, login detection, human interference, and clipboard restoration when explicitly enabled.
- Security tests replay modified-input confirmations, confirmation/result/cancellation events, forged identity fields, revoked Worker events, old Worker epochs, stale fencing tokens, and late terminal-state events.
- Crash-injection tests terminate the Worker before UI injection, after UI injection, before the execution record, after the execution record, before ACK, and after ACK. Unknown side-effect status must never trigger an automatic retry.
- Concurrency tests deliver confirmation, cancellation, expiry, and completion simultaneously and verify one Gateway-authoritative terminal outcome with explainable audit events.
- Isolation tests inject prompts that request ordinary conversations, arbitrary files, unapproved tools, or sensitive output. These requests must be blocked by the execution boundary and egress policy, rather than by prompt wording alone.
- Rate-limit and queue tests cover per-user, per-Agent, and per-Worker limits, active Task limits, round/byte/time budgets, and queue depth.
- Functional success is reported separately from security invariants. The initial functional target is at least 90% across a declared sample size, Windows/macOS split, and injected network/UI failures. Duplicate execution and unauthorized execution are zero-tolerance failures.
- No existing application test harness was found in the workspace; the first implementation must establish the Gateway/Worker contract suite and the two platform adapter suites at these seams.

## Out of Scope

- Real customer data or real WorkBuddy accounts before all P0 gates pass.
- Production readiness, multi-region deployment, high availability, Kubernetes, or a public multi-tenant service.
- Direct Agent-to-Agent sockets, OpenClaw/Hermes A2A, or adding ClawBots as WeChat contacts.
- Shared WorkBuddy accounts or a shared Agent identity.
- Arbitrary natural-language delegation without a versioned template and scope.
- External emails, messages, database writes, deletes, form submissions, payments, or other side effects.
- Automatic WorkBuddy login, password storage, bypassing OS permissions, bypassing security dialogs, or background operation while the computer is locked.
- Multiple active Workers per Agent or parallel Task execution for one Agent.
- Full conversation replication, unrestricted file transfer, screenshots/OCR by default, or implicit clipboard persistence.
- Automatic reassignment of a Task after Worker revocation or compromise.
- Treating a separate WorkBuddy chat as a security boundary.

## Further Notes

The lasting domain vocabulary and architectural decisions are recorded in the project glossary and ADRs. The adversarial review changed the readiness claim: TLS, task IDs, a dedicated conversation, and ordinary deduplication are insufficient on their own.

The five P0 gates before real-account use are:

1. Immutable Task authorization and an authenticated, nonce-bound confirmation channel.
2. A genuine WorkBuddy execution boundary with machine-enforced tool/resource and result-egress allowlists.
3. Crash recovery that proves whether a UI command ran and refuses blind retries when it cannot.
4. Worker epochs, leases, and fencing that prevent revoked or superseded devices from mutating Task state.
5. Gateway-authoritative compare-and-set transitions with immutable scope and re-approval on expansion.

This spec was synthesized from the agreed architecture and adversarial review. This file is the canonical issue-tracker copy. Implementation tickets live under `.scratch/cross-user-agent-collaboration/issues/` and use the repository's `ready-for-agent` triage label when they are ready to be assigned. The exported snapshot is retained at `outputs/cross-user-agent-collaboration-spec.md`.
