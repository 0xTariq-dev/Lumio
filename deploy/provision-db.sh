#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
compose() {
  docker compose --env-file deploy/.env -f deploy/docker-compose.yml "$@"
}

# Apply the idempotent quota-table migration as the database administrator.
# Reports and submitted message bodies are never persisted in this database.
compose exec -T db sh -ec \
  'exec psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' \
  < lib/db/migrations/0001_scan_quotas.sql

# Create a least-privilege API role. The password is read from the database
# container environment and is never placed in this script or its arguments.
compose exec -T db sh -ec \
  'exec psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' <<'SQL'
\getenv app_password VERIDICT_APP_PASSWORD
SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'veridict_app') AS app_role_exists \gset
\if :app_role_exists
  ALTER ROLE veridict_app WITH LOGIN PASSWORD :'app_password';
\else
  CREATE ROLE veridict_app WITH LOGIN PASSWORD :'app_password';
\endif
GRANT CONNECT ON DATABASE veridict TO veridict_app;
GRANT USAGE ON SCHEMA public TO veridict_app;
REVOKE ALL ON TABLE veridict_scan_quotas FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE veridict_scan_quotas TO veridict_app;
SQL

echo "Quota table and least-privilege API role are ready."
