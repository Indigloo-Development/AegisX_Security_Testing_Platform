#!/usr/bin/env bash
set -euo pipefail
: "${POSTGRES_CONTAINER:=aegisx-db-1}"
: "${POSTGRES_USER:=aegisx}"
: "${POSTGRES_DB:=aegisx}"
OUT="${1:-./backup/aegisx_$(date +%Y%m%d_%H%M%S).sql}"
mkdir -p "$(dirname "$OUT")"
docker exec -t "$POSTGRES_CONTAINER" pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" > "$OUT"
echo "Backup written to $OUT"
