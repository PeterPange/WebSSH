#!/usr/bin/env bash
set -euo pipefail

# Load optional deployment settings without requiring an extra npm package.
if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

if ! command -v node >/dev/null 2>&1; then
  echo 'Startup failed: Node.js was not found. Install Node.js 18+ or deploy with Docker: docker compose up -d --build' >&2
  exit 127
fi

exec node server.js
