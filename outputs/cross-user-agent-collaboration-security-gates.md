# Cross-user Agent collaboration security gate report

Date: 2026-10-28

This report covers the controlled demonstration seam using synthetic Teams,
Agents, Workers, UI backends, and ClawBot transport. It separates safety
invariants from functional test success. It does not certify real WeChat,
Windows UI Automation, macOS Accessibility, or production account identity.

## Security invariants

| Invariant | Evidence | Result |
| --- | --- | --- |
| Crash before UI injection does not duplicate input | File-backed Windows command journal remains `prepared`; reconnect resumes once | PASS |
| Crash after UI injection does not blind-retry | Journal remains `injected`; reconciliation returns `uncertain`; adapter raises `NEEDS_ATTENTION` | PASS |
| Execution record/ACK recovery is idempotent | Completed journal evidence is returned on reconnect without a second UI injection | PASS |
| macOS Accessibility crash recovery is symmetric | macOS fake Accessibility backend reaches the same uncertain stop point | PASS |
| Old Worker epoch and revoked device are fenced | Gateway rejects old lease identity and stale fencing capability | PASS |
| Expired lease cannot mutate state | Gateway rejects a valid identity after lease expiry | PASS |
| Confirmation/result/cancellation replay is harmless | Protocol and ClawBot journals return the recorded result and preserve the state version | PASS |
| Hash, nonce, expiry, recipient, and channel identity are bound | Modified, forwarded, weak-channel, expired, or mismatched envelopes are rejected | PASS |
| CAS races have one authoritative outcome | A stale completion/failure request cannot replace the first terminal transition | PASS |
| Late terminal events cannot reopen a Task | Gateway records `late_event_rejected` and keeps the terminal state | PASS |

## Functional verification

The full local suite contains 48 tests and passes with
`PYTHONWARNINGS=error::ResourceWarning python3 -m unittest discover -v`.
Compilation and `git diff --check` also pass. The test result is a controlled
synthetic sample and is not a production success-rate estimate.

## Remaining gate scope

Real WeChat/ClawBot identity, real Windows UIA, real macOS Accessibility, OS
profile isolation, network interruption between external ACKs, and production
multi-process database contention still require platform-specific acceptance
with test accounts. The controlled adapter blocks weak channel identity rather
than treating ordinary ClawBot text as proof of user intent.
