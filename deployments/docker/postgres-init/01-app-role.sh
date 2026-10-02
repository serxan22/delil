#!/bin/sh
# Creates the least-privilege runtime role used by the API. Table privileges
# are granted by `delil-server migrate` (DELIL_DB_APP_ROLE) after migrations:
# SELECT/INSERT on audit records, never UPDATE, DELETE or TRUNCATE.
set -eu
psql -v ON_ERROR_STOP=1 -v app_password="$DELIL_DB_APP_PASSWORD" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'EOSQL'
CREATE ROLE delil_app LOGIN PASSWORD :'app_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
SELECT format('GRANT CONNECT ON DATABASE %I TO delil_app', current_database()) \gexec
EOSQL
