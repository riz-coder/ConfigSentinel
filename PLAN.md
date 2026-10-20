# ConfigSentinel Delivery Plan

## Current work package

`WP-EVID-01` — encrypted, content-addressed evidence vault with review,
retention/legal-hold guards, and custody history.

## In scope

- Encrypt every artifact before storage using approved AES-256-GCM envelope
  encryption and tenant/artifact-bound authenticated metadata.
- Add opaque local object-store adapter and production KMS/S3-compatible
  interfaces; never store plaintext documents in the database.
- Link uploads only to approved exact obligation mappings and evidence versions.
- Add hash verification, immutable manifests, reviewer separation, explicit
  evidence states, expiry/staleness, retention and legal-hold guards.
- Add append-only custody events, role-aware API/UI, migrations, forced RLS,
  negative tests, ADR/threat-model updates, and operator documentation.

## Explicitly out of scope

- Malware content disarm, OCR, AI/document interpretation, or document previews.
- Device collectors, technical test execution, compliance aggregation/scoring,
  auditor-room sharing, report exports, and automatic remediation.
- Production KMS/S3 credentials or a claim that local filesystem storage is a
  production evidence backend.
- Legal retention defaults not present in an approved evidence requirement.

## Acceptance tests

1. Upload requires an approved same-tenant mapping and stores ciphertext only;
   missing keys, oversized/unsupported files, or cross-tenant IDs fail closed.
2. Round-trip decryption verifies tenant-bound AEAD plus plaintext/ciphertext
   hashes; any metadata/blob tamper fails without returning bytes.
3. Uploader cannot review their artifact; accepted/rejected review is explicit,
   attributable, immutable, and never inferred from upload.
4. Expired accepted evidence reports `STALE`, never accepted/current.
5. Retention prevents early purge and active holds prevent purge at any age;
   custody/manifests survive permitted ciphertext purge.
6. Cross-tenant reads/downloads/reviews are denied and audited where attempted;
   PostgreSQL forced RLS protects every evidence table.
7. API/OpenAPI, UI, migrations, SQLite/PostgreSQL tests, docs, and production
   checks pass.

## Dependencies

- Python 3.11+ for local Windows development.
- PostgreSQL 17 for security-boundary validation; SQLite remains a convenience
  for Windows UI development but cannot validate RLS/database triggers.
- Docker Engine/Compose for container validation and VPS deployment (currently
  unavailable on this Windows workstation).
- Authenticated Git remote before publishing.

## Legal blockers

- The authenticated complete CTDISR 2025 Gazette and later directives are not
  present. Regulations remain `SOURCE_PENDING` unless independently supplied
  and approved by authorized reviewers.
- No regulatory deadlines, applicability rules, or legal text will be inferred
  from the blueprint or secondary sources.

## Security threats addressed in this package

- Plaintext leakage, path traversal, object swapping, nonce/key reuse, blob or
  manifest tampering, oversized/hostile uploads, IDOR, self-review, premature
  deletion, hold bypass, stale-evidence inflation, and sensitive logging.

## Completion record

### Implemented

- AES-256-GCM envelope encryption with a unique data key and nonce per artifact,
  tenant/artifact-bound authenticated metadata, wrapped keys, and plaintext and
  ciphertext hashes. Plaintext is never written to the object store.
- Tenant-scoped evidence manifests linked only to approved exact obligation and
  control mappings, plus an allowlisted upload contract and opaque downloads.
- Independent review, effective staleness, retention/legal holds, governed
  ciphertext purge, and append-only custody events.
- API/OpenAPI routes, neutral evidence UI, PostgreSQL forced RLS and immutable
  triggers, scheduled staleness command, operations guide, and encryption ADR.

### Test evidence

- `.venv\\Scripts\\python.exe manage.py test apps.evidence --verbosity 1` — all
  14 evidence-vault tests passed on SQLite.
- `.venv\\Scripts\\python.exe manage.py test --verbosity 1` — all 52 tests
  passed; 4 PostgreSQL-only security tests were explicitly skipped locally.
- Migration drift, Django system/deployment checks, Compose/CI YAML parsing,
  dependency consistency, and Git whitespace checks passed.
- GitHub Actions run `39373074878` passed, including PostgreSQL RLS and
  immutable-trigger boundary tests.

### Not implemented / known risks

- Local filesystem storage and an environment-provided wrapping key are for
  development/on-prem validation, not a production KMS/S3 deployment. Key
  rotation, HA object storage, and backup/restore drills remain required.
- Malware scanning, OCR, previews, AI interpretation, device collection,
  compliance aggregation, and report exports are not implemented.
- Official authenticated regulatory source text remains unavailable, so no
  legal compliance claim or regulatory `COMPLIANT` result is produced.

### Next bounded work package

`WP-COLLECT-01`: design and scaffold the authorized read-only collector trust
boundary (scope grants, host-key verification, command allowlists, budgets, and
per-device locks) without connecting to or changing production devices.
