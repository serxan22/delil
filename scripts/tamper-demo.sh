#!/usr/bin/env bash
# Demonstrates tamper evidence on the local Compose stack:
#   1. verifies the "payments" stream,
#   2. edits one stored event directly in PostgreSQL as a superuser would,
#      bypassing the append-only triggers,
#   3. verifies again and shows exactly where and how the chain broke.
# The demo database is left tampered; `make reset` starts over.
set -euo pipefail
COMPOSE=${COMPOSE:-docker compose}
API=${DELIL_URL:-http://127.0.0.1:8080}
: "${DELIL_API_KEY:?export DELIL_API_KEY (see: make credentials)}"
export DELIL_URL=$API

run_cli() { go run ./cmd/delil "$@"; }

echo "== 1. Verify the payments stream (independently, from the CLI)"
run_cli verify stream payments || true

echo
echo "== 2. Tamper: change a refund amount directly in the database"
$COMPOSE exec -T postgres psql -U delil -d delil -v ON_ERROR_STOP=1 <<'SQL'
SET session_replication_role = replica;  -- disables triggers: superusers can always do this
UPDATE audit_events
   SET content = replace(content, '"refunded":1200', '"refunded":12')
 WHERE action = 'refund.issued';
SQL

echo
echo "== 3. Verify again"
if run_cli verify stream payments; then
  echo "unexpected: verification passed" && exit 1
fi
echo
echo "Tampering detected. Reset the demo with: make reset && make dev"
