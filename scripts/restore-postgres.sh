#!/bin/sh
set -eu
: "${PGHOST:?PGHOST is required}"
: "${PGDATABASE:?PGDATABASE is required}"
: "${PGUSER:?PGUSER is required}"
: "${PGPASSWORD:?PGPASSWORD is required}"
: "${1:?archive is required}"
: "${2:?exact target database confirmation is required}"
[ "$2" = "$PGDATABASE" ] || { echo "Target confirmation does not match PGDATABASE" >&2; exit 2; }
cd "$(dirname "$1")"
archive="$(basename "$1")"
sha256sum --check "$archive.sha256"
pg_restore --clean --if-exists --no-owner --no-acl --exit-on-error --dbname="$PGDATABASE" "$archive"
printf 'Restore completed for %s\n' "$PGDATABASE"

