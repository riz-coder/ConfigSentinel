# WP-CORE-01 Threat Model

## Protected assets

Tenant identities, regulatory sources and review metadata, audit records,
future device/evidence references, credentials, and exported reports.

## Trust boundaries

Browser to reverse proxy; proxy to Django; Django to PostgreSQL; future worker
and collector links; administrator access; tenant-to-tenant boundary.

## Initial controls

- Authenticated dashboard/API and membership-scoped querysets.
- Cross-tenant object IDs return not found and cannot select another tenant by
  request header.
- Legal state transitions validate source integrity and review prerequisites.
- Audit events are append-only at the model/queryset API and read-only in admin.
- Production cookies, HSTS, HTTPS redirect, host allowlist, and proxy HTTPS
  awareness are configured when debug mode is disabled.
- Database is not published by the Compose topology.
- `.env`, local databases, media, and virtual environments are Git-ignored.

## Open risks for later packages

- Forced PostgreSQL RLS now protects regulatory tenant tables, and the Compose
  topology separates schema-owner migrations from a non-owner runtime role.
- TOTP MFA and login throttling are implemented. SSO, MFA recovery governance,
  field-level authorization, malware scanning, encrypted object storage, KMS
  integration, and scheduled off-host backups remain open.
- Audit update/delete is blocked by a PostgreSQL trigger for normal operation;
  database superusers can still remove controls and must remain inaccessible to
  the application.
- Docker deployment has not been executed because Docker is unavailable on the
  current workstation.

