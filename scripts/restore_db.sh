#!/usr/bin/env bash
set -euo pipefail
: "${POSTGRES_CONTAINER:=aegisx-db-1}"
: "${POSTGRES_USER:=aegisx}"
: "${POSTGRES_DB:=aegisx}"
FILE="${1:?usage: restore_db.sh backup.sql}"
cat "$FILE" | docker exec -i "$POSTGRES_CONTAINER" psql -U "$POSTGRES_USER" "$POSTGRES_DB"
