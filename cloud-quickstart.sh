#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  cp .env.cloud.example .env
  echo "Created .env.cloud.example as .env. Edit DATABASE_URL, REDIS_URL, CORS_ORIGINS and NEXT_PUBLIC_API_URL first."
  exit 2
fi

./scripts/aegisx install
./scripts/aegisx start
