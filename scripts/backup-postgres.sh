#!/bin/sh
set -eu
: "${PGHOST:?PGHOST is required}"
: "${PGDATABASE:?PGDATABASE is required}"
: "${PGUSER:?PGUSER is required}"
: "${PGPASSWORD:?PGPASSWORD is required}"
: "${1:?output directory is required}"
mkdir -p -- "$1"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
archive="$1/configsentinel-$timestamp.dump"
pg_dump --format=custom --no-owner --no-acl --file="$archive"
sha256sum "$archive" > "$archive.sha256"
printf '%s\n' "$archive"

