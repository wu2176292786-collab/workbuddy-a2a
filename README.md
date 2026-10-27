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
