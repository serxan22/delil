#!/usr/bin/env bash
# Runs every example against a live server and fails if any of them fails.
#   DELIL_API_KEY=dlk_... [DELIL_URL=http://localhost:8080] scripts/run-examples.sh
# The SDK must be built first: (cd sdk/typescript && npm ci && npm run build)
set -euo pipefail
: "${DELIL_API_KEY:?set DELIL_API_KEY to a key with every scope (the bootstrap key)}"
export DELIL_URL="${DELIL_URL:-http://localhost:8080}"
export WEBHOOK_SECRET="${WEBHOOK_SECRET:-whsec_ci}"
cd "$(dirname "$0")/../examples"
export NODE_NO_WARNINGS=1

for ex in node-basic webhook-audit contract-workflow; do
  echo "::group::$ex"
  (cd "$ex" && npm ci --no-audit --no-fund --silent && npm run --silent typecheck)
  case "$ex" in
    webhook-audit)
      export PORT="${PORT:-4100}" WEBHOOK_URL="http://127.0.0.1:${PORT:-4100}/webhooks/payments"
      (cd "$ex" && node src/server.ts) & server=$!
      trap 'kill $server 2>/dev/null || true' EXIT
      for _ in $(seq 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/" && break; sleep 0.2; done
      (cd "$ex" && node src/send-test-webhook.ts)
      kill "$server"; trap - EXIT ;;
    *)
      (cd "$ex" && node src/main.ts) ;;
  esac
  echo "::endgroup::"
done
echo "all examples passed"
