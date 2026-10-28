# Tencent Cloud deployment contract

Copy `secrets/postgres_password` and TLS files into `certs/` before starting:

```sh
docker compose -f deploy/docker-compose.yml up -d --build
curl -fsS https://gateway.example.com/readyz
curl -fsS https://gateway.example.com/metrics
```

The reverse proxy terminates HTTPS and forwards `/v1/worker/ws` as WSS with
the WebSocket upgrade headers. Access logs use a fixed sanitized format and do
not include request bodies or tokens. `backup.sh` creates PostgreSQL, Redis,
and mounted SQLite backups plus checksums; restore validation must run the
database integrity checks before a recovered service is exposed.
