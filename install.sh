#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "=== AegisX Easy Installer ==="

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This installer targets Linux."; exit 1
fi

command -v python3 >/dev/null || { echo "Missing python3"; exit 1; }
command -v node >/dev/null || { echo "Missing node"; exit 1; }
command -v npm >/dev/null || { echo "Missing npm"; exit 1; }

if [[ ! -f .env ]]; then
  cp .env.standalone.example .env
  echo "Created .env for standalone SQLite + memory-queue mode."
fi

./scripts/aegisx install
./scripts/aegisx doctor

echo
printf '%s\n' 'Installed. Start everything with:'
printf '%s\n' '  ./scripts/aegisx start'
printf '%s\n' 'Then open: http://127.0.0.1:3000'
