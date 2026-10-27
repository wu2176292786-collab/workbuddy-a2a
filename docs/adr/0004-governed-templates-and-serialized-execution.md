# Govern the team with templates and serialized execution

The PoC uses administrator-managed membership and device lifecycle, a small allowlist of approved Task templates, one active Task per Agent, and explicit protocol versions. Audit events retain Task and Worker lifecycle metadata for 30 days while excluding full WorkBuddy or WeChat transcripts. This keeps the first deployment understandable and limits UI automation to a serialized, reviewable execution model.

## Consequences

The Gateway must queue work per Agent and expose a clear reason when a template, protocol version, member, or device is rejected. Adding parallel execution, self-service membership, arbitrary prompts, or automatic Worker upgrades is deferred until operational evidence supports it.
