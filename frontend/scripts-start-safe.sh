#!/usr/bin/env bash
set -euo pipefail
exec python3 "$(dirname "$0")/launcher.py" dev -p 3000
