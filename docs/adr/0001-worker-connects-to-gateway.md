# Local Worker connects to the Gateway

The local Worker, rather than WorkBuddy itself, authenticates to the Tencent Cloud Gateway and maintains the cross-user connection. The Worker then drives the already-authenticated WorkBuddy session through UI automation. This keeps WorkBuddy credentials and local conversation state on the user's computer, gives the gateway a stable device identity that can be revoked independently, and works even when WorkBuddy has no multi-account Agent API.

## Considered Options

- Have WorkBuddy log in directly to the Gateway: rejected because it assumes an integration surface that is not available and would couple the design to WorkBuddy account/session internals.
- Have the Gateway log in to each user's WorkBuddy: rejected because it would require collecting WorkBuddy credentials and would move private UI state into the cloud.

## Consequences

Each computer needs a registered, always-on Worker and a running, unlocked WorkBuddy session. The Gateway routes messages by Agent identity, while the Worker-to-Gateway connection is authenticated by a device credential; Agent identity and device identity are separate and can be revoked independently.
