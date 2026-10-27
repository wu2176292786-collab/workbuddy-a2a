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

The bootstrap CLI creates the initial Team, User, and Agent. Generate a one-time pairing code with the returned IDs:

```sh
python3 -m gateway_worker.cli bootstrap --db gateway.db \
  --team-name "Example Team" --user-name Alice --agent-name "Alice's Agent"
python3 -m gateway_worker.cli pairing-code --db gateway.db \
  --team-id TEAM_ID --agent-id AGENT_ID
```

The Gateway must be run with a TLS certificate and key for a WSS Worker connection. The Worker private key is held by the platform credential-store adapter; the Gateway persists only the public key and device state.
