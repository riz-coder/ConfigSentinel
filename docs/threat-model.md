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
- Corrective actions preserve append-only event and evidence-version history;
  ISP owners cannot close their own retests and auditors cannot assign or alter
  the ISP remediation plan.
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

## WP-NET-02 collector execution threats

- Credential disclosure: the control-plane database stores only opaque
  references; the local agent encrypts secrets with a dedicated key and never
  prints passwords.
- Machine-in-the-middle and device substitution: SSH requires an independently
  pinned SHA256 host key and fails closed on mismatch. Telnet remains an
  explicitly approved legacy exception and never receives an automatic
  downgrade.
- Command injection and device modification: jobs contain no free-form command;
  only an exact, versioned, independently approved read-only allowlist runs.
- Runaway or hostile output: per-scope command count, runtime and output-byte
  budgets are enforced, and each device has only one active job.
- Evidence tampering and tenant crossover: each command output becomes an
  authenticated-encryption snapshot with plaintext/ciphertext hashes, tenant
  ownership and append-only/RLS database controls.
- Unknown platform or command behavior: discovery mismatch, unsupported,
  denied, stale, truncated and failed results remain explicit UNKNOWN/ERROR
  outcomes and cannot be promoted to PASS.
- Host spoofing fails closed unless the observed SSH fingerprint exactly matches
  the out-of-band pinned fingerprint.
- Raw credentials are excluded by design: only write-only opaque vault references
  are accepted and they are omitted from API/UI/audit output.
- Written scope is exact, time-bounded and independently approved; hard command,
  runtime and output ceilings are copied into each job.
- A database constraint prevents concurrent active jobs per device.
- Exact command definitions are integrity-hashed and independently approved;
  free-form or modified manifests cannot pass approval.
- SSH remains the default with a pinned host key. Telnet requires a written risk
  exception and different approver, and is never an automatic fallback.
- No transport or command execution exists in the Django control plane,
  eliminating network side effects while signed outbound-agent execution,
  vault resolution and real-firmware parser fixtures are unfinished.

# WP-ASSET tenant inventory boundary

Asset identifiers, ownership and dependency data are tenant-filtered in the UI
and API and protected by PostgreSQL RLS. Foreign-tenant owners, sites, services
and dependency endpoints fail validation. CSV batches validate fully before
insertion so a malformed row cannot leave a partially trusted inventory.

