#!/bin/sh
set -eu

psql --set=ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  --set=runtime_password="$CONFIGSENTINEL_DB_RUNTIME_PASSWORD" <<'SQL'
CREATE ROLE configsentinel_runtime LOGIN PASSWORD :'runtime_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
GRANT CONNECT ON DATABASE configsentinel TO configsentinel_runtime;
GRANT USAGE ON SCHEMA public TO configsentinel_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE configsentinel_owner IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO configsentinel_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE configsentinel_owner IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO configsentinel_runtime;
SQL
