# Controlled PoC acceptance record

This record separates reproducible synthetic contract evidence from the
physical acceptance that requires a human operator with one Windows computer,
one macOS computer, and authenticated ClawBot test channels.

## Synthetic acceptance run

Command:

```sh
PYTHONWARNINGS=error::ResourceWarning python3 -m unittest discover -v
```

The dedicated matrix is `tests/test_controlled_poc_acceptance.py`:

| Evidence | Result |
| --- | --- |
| Healthy sample | 20/20 tasks completed (10 Windows adapter, 10 macOS adapter) |
| Coordination | Every sample kept one `task_id` through two rounds and returned execution evidence for rounds 1 and 2 |
| Confirmation and notification | Strongly authenticated synthetic ClawBot envelopes; task, state, and result notifications reached both channels |
| Injected UI failures | Windows update dialog and macOS login state both entered `NEEDS_ATTENTION` with zero execution count and no retry |
| Functional target | 100% healthy synthetic sample, above the 90% target |

The synthetic transport is `FakeClawBotTransport`, and the platform backends
are deterministic UIA/Accessibility seams. This proves the shared contract;
it is not evidence that a real ClawBot account or a physical WorkBuddy App
session has been connected.

## Independent P0 conclusions

1. **Immutable authorization and authenticated confirmation:** **PASS for the
   synthetic contract; NOT CLEARED for real-account use.** The ClawBot tests
   bind a strong channel identity to `task_id`, `task_hash`, nonce, expiry, and
   replay protection. A real connector run is still required.
2. **Execution isolation and result egress:** **PASS for the controlled
   harness.** Restricted workspaces, template allowlists, prompt-injection
   rejection, and sensitive-field egress checks are covered. Physical profile
   isolation is not demonstrated here.
3. **Crash recovery at the UI side-effect boundary:** **PASS.** Windows and
   macOS crash/reconnect tests preserve the command journal and enter
   `NEEDS_ATTENTION` when completion cannot be proven; no blind retry occurs.
4. **Worker epoch, lease, and fencing:** **PASS.** Revoked/superseded Workers,
   stale leases, and old fencing tokens are rejected by the adversarial suite.
5. **Gateway compare-and-set authority:** **PASS.** Replay and concurrent
   transition tests leave one authoritative terminal state and retain late
   events as audit evidence.

## Release decision

The controlled synthetic PoC gate passes: the healthy sample is 20/20 and the
injected UI fault cases fail closed. The real-account gate remains **BLOCKED**
until a human records the physical Windows/macOS run and the real ClawBot
confirmation/notification run. Until that evidence is attached, use only test
accounts, synthetic data, and tasks without external side effects.
