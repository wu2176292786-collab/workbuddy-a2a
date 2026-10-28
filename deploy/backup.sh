#!/usr/bin/env sh
set -eu

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="${BACKUP_DIR:-./backups}/${STAMP}"
mkdir -p "$DEST"

# Production PostgreSQL/Redis backup. The current controlled PoC also keeps a
# SQLite file in the gateway volume; back it up when that volume is mounted.
docker compose exec -T postgres pg_dump -U workbuddy -d workbuddy > "$DEST/postgres.sql"
docker compose exec -T redis redis-cli --rdb - > "$DEST/redis.rdb"
if [ -f "${GATEWAY_DB:-./gateway.db}" ]; then
  sqlite3 "${GATEWAY_DB:-./gateway.db}" ".backup '$DEST/gateway.db'"
  sqlite3 "$DEST/gateway.db" "PRAGMA integrity_check;" > "$DEST/gateway.integrity"
fi
sha256sum "$DEST"/* > "$DEST/SHA256SUMS"
echo "backup=$DEST"
