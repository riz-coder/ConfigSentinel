# WP-CORE-01 Threat Model

## Protected assets

Tenant identities, regulatory sources and review metadata, audit records,
future device/evidence references, credentials, and exported reports.

WP-EVID-01 additionally protects plaintext evidence, per-artifact data keys,
the wrapping key, immutable manifests, reviewer decisions, retention holds, and
custody history.

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
- Evidence is AES-256-GCM envelope-encrypted before object storage with
  tenant/artifact/version-bound AAD and dual plaintext/ciphertext hashes.
- Plaintext uploads are memory-bounded and never intentionally spooled to disk;
  downloads are opaque attachments with no-store caching.
- Upload, review, download, hold, release, and purge are tenant/role scoped and
  attributable; uploader self-review and early/held purge fail closed.
- Auditor accounts are owner-created with password validation; auditor PDF
  reports are encrypted, tenant-scoped and append-only. Uploading a report does
  not import or inflate clause states.
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
- The local evidence adapter lacks malware scanning, production KMS, S3 object
  versioning, HA, coordinated off-host backup, and proven key recovery. It must
  not receive customer evidence until those deployment controls are reviewed.

## Collector trust boundary

- Cross-tenant target substitution is blocked in service validation and forced
  PostgreSQL RLS across every collector table.
- Host spoofing fails closed unless the observed SSH fingerprint exactly matches
  the out-of-band pinned fingerprint.
- Raw credentials are excluded by design: only write-only opaque vault references
  are accepted and they are omitted from API/UI/audit output.
- Written scope is exact, time-bounded and independently approved; hard command,
  runtime and output ceilings are copied into each job.
- A database constraint prevents concurrent active jobs per device.
- No transport or command execution exists in this package, eliminating network
  side effects while signed agents and reviewed command packs are unfinished.

