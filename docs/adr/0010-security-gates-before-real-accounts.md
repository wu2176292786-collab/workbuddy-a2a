# Gate real accounts on authorization, isolation, and crash safety

The collaboration design remains a controlled demonstration until five P0 properties are implemented and adversarially tested: (1) an immutable `task_hash` and one-time, nonce-bound confirmation tied to an authenticated recipient channel; plain natural-language text from a WorkBuddy UI is insufficient for real-account approval; (2) a real execution boundary using an isolated OS user, WorkBuddy account, or restricted workspace plus machine-enforced tool/resource and result-egress allowlists; (3) crash recovery that proves whether a UI command ran and enters `NEEDS_ATTENTION` instead of blindly retrying when it cannot; (4) Worker generations, leases, and fencing tokens that prevent revoked or superseded devices from changing Task state; and (5) Gateway-authoritative compare-and-set state transitions with immutable scope and re-approval on expansion.

## Considered Options

- Treat TLS, a dedicated chat, and `task_id` deduplication as sufficient: rejected because they do not bind approval to content, isolate data and tools, or cover side effects that occur before an ACK.
- Allow real WorkBuddy accounts while hardening incrementally: rejected because the UI automation and data boundary remain unsafe during the crash and prompt-injection windows.

## Consequences

The PoC must use test accounts, synthetic data, no external writes, and explicit fault-injection tests until the gate passes. Security invariants are reported separately from the 90% functional success target.
