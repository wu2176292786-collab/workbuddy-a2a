# Use at-least-once delivery and side-effect-free PoC tasks

The PoC uses at-least-once message delivery with `task_id` and `message_id` idempotency, a dedicated Worker-controlled WorkBuddy window, text-only result summaries, and tasks without external side effects. Recipient rejection and sender cancellation are supported before execution; a running task receives a cooperative cancellation request whose actual stop state must be reported. These boundaries make retries and UI automation observable without risking duplicate external actions.

## Considered Options

- Exactly-once delivery: rejected because reconnects and UI automation cannot provide that guarantee.
- Arbitrary external actions in the PoC: deferred because duplicate execution and cancellation semantics are not yet safe.
- Sharing the normal human WorkBuddy window: rejected because concurrent human input can corrupt task state.

## Consequences

The first task templates should be read-only or produce drafts and text summaries. File transfer, external writes, and forced process termination require later authorization and protocol work.
