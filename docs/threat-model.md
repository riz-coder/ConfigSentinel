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

- PostgreSQL RLS and a non-owner runtime database role are not implemented yet.
- MFA/SSO, rate limiting, field-level authorization, malware scanning, encrypted
  object storage, KMS integration, and backup automation remain open.
- Model-level append-only protection does not stop a database owner; production
  database roles and database-level guards are required.
- Docker deployment has not been executed because Docker is unavailable on the
  current workstation.

