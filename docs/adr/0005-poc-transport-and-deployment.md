# Use WSS with a small persistent Gateway deployment

The PoC exposes HTTPS REST endpoints for administration and setup, an outbound WSS connection for each Worker, PostgreSQL for durable Task and audit state, and Redis for online presence, leases, and short-lived queue data. The first deployment runs these services with a reverse proxy in Docker Compose on a Tencent Cloud server. Worker private keys stay in the operating system credential store; the Gateway keeps public keys and device state.

## Considered Options

- MQTT as the primary Worker transport: deferred because WSS is easier to inspect and implement for the small PoC.
- Redis-only Task storage: rejected because reconnect and audit recovery require durable state.
- Kubernetes or a multi-instance service from day one: deferred because the expected team size does not justify the operational cost during feasibility validation.
