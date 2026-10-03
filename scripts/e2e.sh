#!/usr/bin/env bash
# End-to-end checks against the running Docker Compose stack (`make dev` or
# `docker compose up -d --wait`). Used by CI; safe to run locally, but the last
# step leaves the demo database TAMPERED (`make reset` starts over).
#
#   scripts/e2e.sh
#
# Needs: docker compose, Go, Node.js >= 22.18, curl.
set -euo pipefail
cd "$(dirname "$0")/.."
COMPOSE=${COMPOSE:-docker compose}
export DELIL_URL=${DELIL_URL:-http://127.0.0.1:${DELIL_API_PORT:-8080}}
export NODE_NO_WARNINGS=1
step() { echo; echo "==> $*"; }
fail() { echo "E2E FAILED: $*" >&2; exit 1; }

step "Bootstrap API key from the api logs"
DELIL_API_KEY=$($COMPOSE logs api 2>/dev/null | grep -o 'dlk_[a-z0-9_]*' | head -1 || true)
[ -n "$DELIL_API_KEY" ] || fail "no bootstrap API key in the api logs (was the database already bootstrapped?)"
export DELIL_API_KEY
mkdir -p bin && CGO_ENABLED=0 go build -o bin/delil ./cmd/delil && CGO_ENABLED=0 go build -o bin/delil-bench ./cmd/delil-bench
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT

step "Health and readiness"
bin/delil health
curl -fsS "$DELIL_URL/ready" >/dev/null
curl -fsS "http://127.0.0.1:${DELIL_DASHBOARD_PORT:-3000}/login" >/dev/null || fail "dashboard login page"

step "Independent verification of every demo stream, with pinned keys"
bin/delil keys export > "$work/trusted-keys.json"
bin/delil verify --trusted-keys "$work/trusted-keys.json"
bin/delil verify --remote

step "Least privilege: the runtime role cannot modify audit records"
out=$($COMPOSE exec -T postgres psql -U delil_app -d delil -v ON_ERROR_STOP=1 \
  -c "UPDATE audit_events SET action = 'x' WHERE sequence = 1" 2>&1 || true)
echo "$out" | grep -qi "permission denied" || fail "delil_app could UPDATE audit_events: $out"
out=$($COMPOSE exec -T postgres psql -U delil_app -d delil -v ON_ERROR_STOP=1 \
  -c "DELETE FROM audit_events WHERE sequence = 1" 2>&1 || true)
echo "$out" | grep -qi "permission denied" || fail "delil_app could DELETE from audit_events: $out"
echo "UPDATE and DELETE denied for delil_app"

step "Examples"
(cd sdk/typescript && npm ci --no-audit --no-fund --silent && npm run --silent build)
scripts/run-examples.sh

step "SDK integration tests"
(cd sdk/typescript && DELIL_TEST_URL="$DELIL_URL" DELIL_TEST_API_KEY="$DELIL_API_KEY" npm run --silent test:integration)

step "Load: 2,000 events over HTTP, verified locally and on the server"
bin/delil-bench -url "$DELIL_URL" -events 2000 -concurrency 4 -batch 25 -streams 2

step "Evidence package round trip"
bin/delil export --stream payments --output "$work/payments.zip"
bin/delil verify-export "$work/payments.zip" --trusted-keys "$work/trusted-keys.json"

step "Tamper detection (leaves the demo database tampered)"
scripts/tamper-demo.sh

echo; echo "E2E PASSED"
