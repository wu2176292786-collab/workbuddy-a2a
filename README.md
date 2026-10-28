# workbuddy-a2a

This repository contains the domain model, architecture decisions, and delivery plan for the cross-user WorkBuddy Agent collaboration PoC.

## Development documentation

- [Domain context and glossary](CONTEXT.md)
- [Collaboration architecture](docs/cross-user-agent-collaboration.md)
- [Architecture decision records](docs/adr/)
- [Implementation specification](.scratch/cross-user-agent-collaboration/spec.md)
- [Implementation tickets](.scratch/cross-user-agent-collaboration/issues/)
- [Exported design and specification snapshots](outputs/)

Repository conventions are documented in [AGENTS.md](AGENTS.md), [domain guidance](docs/agents/domain.md), [issue tracker guidance](docs/agents/issue-tracker.md), and [triage labels](docs/agents/triage-labels.md).

## Scope and readiness

The current material describes a controlled demonstration. Real WorkBuddy accounts, real user data, and external side effects remain blocked until the five P0 security gates in [ADR 0010](docs/adr/0010-security-gates-before-real-accounts.md) are implemented and adversarially tested.

## Local development

Install the package and its runtime dependencies with `python3 -m pip install -e .`, then run the Gateway/Worker pairing contract suite:

```sh
python3 -m unittest discover -v
```

The deterministic Gateway–Worker collaboration contract is available through
`gateway_worker.collaboration.FakeCollaboration`. It covers two-round delivery,
scope-bounded `NEEDS_INPUT`, command journaling and UI reconciliation,
template-defined execution evidence, result summaries, and replay-safe
monitoring events without opening a real WorkBuddy session.

Execution isolation is provided by `gateway_worker.isolation`: versioned
`TaskTemplate` allowlists, a dedicated `RestrictedWorkspace`, explicit
screenshot/OCR and clipboard grants, and a machine-enforced
`ResultEgressPolicy` for sensitive output fields.

The Windows adapter contract is exposed by
`gateway_worker.windows_adapter.WindowsDesktopAdapter`. It uses an injectable
UI Automation backend, a file-backed command journal, dedicated conversation
checks, structured UI error events, and reconnect reconciliation.

The macOS counterpart is exposed by
`gateway_worker.macos_adapter.MacOSDesktopAdapter` with the same journal,
reconciliation, completion-evidence, safe-stop, and capability-gated
clipboard contract over an Accessibility backend.

`gateway_worker.clawbot.ClawBotAdapter` provides the confirmation and
notification boundary: only strongly authenticated, machine-readable
envelopes bound to the recipient Agent can confirm a Task, while replayed,
forwarded, plain-text, expired, or mismatched messages are blocked.

`gateway_worker.admin.AdminService` provides the controlled-demo Admin
console boundary with MFA/RBAC, Team-scoped member/Agent/Worker/template
management, 30-day audit retention, short-lived task-content deletion,
redacted export, and configurable resource limits.

Deployment assets live under `deploy/`: Docker Compose services for Gateway,
PostgreSQL, Redis, and an Nginx TLS/WSS reverse proxy, plus health/ready
checks, Prometheus-compatible metrics, and checksum/integrity-checked backup
scripts.

The bootstrap CLI creates the initial Team, User, and Agent. Generate a one-time pairing code with the returned IDs:

```sh
python3 -m gateway_worker.cli bootstrap --db gateway.db \
  --team-name "Example Team" --user-name Alice --agent-name "Alice's Agent"
python3 -m gateway_worker.cli pairing-code --db gateway.db \
  --team-id TEAM_ID --agent-id AGENT_ID
```

The Gateway must be run with a TLS certificate and key for a WSS Worker connection. The Worker private key is held by the platform credential-store adapter; the Gateway persists only the public key and device state.
