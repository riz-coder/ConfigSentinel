# ConfigSentinel Delivery Plan

## Current work package

`WP-REG-01` — signed regulatory-pack intake, nested legal ontology, dual review,
version comparison, and honest coverage gates.

## In scope

- Add canonical JSON regulatory-pack schema and bounded manifest validation.
- Verify detached Ed25519 signatures using configured trusted public keys.
- Import versioned regulations, nested subclauses, and obligations atomically.
- Preserve source coordinates, hashes, import provenance, and prior versions.
- Add independent legal/compliance review decisions with two-person approval.
- Add version diff and coverage-gate services/API/UI.
- Prevent import, approval, or API paths from inflating unverified legal status.
- Add migrations, tenant permissions, negative-path tests, docs, and audit events.

## Explicitly out of scope

- Production device collection or network commands.
- Evidence uploads and object-store retention workflows.
- Full CTDISR clause transcription or legal interpretation.
- Compliance scoring, regulator submission, AI processing, and billing.
- Claims of PTA certification or customer compliance.

## Acceptance tests

1. Invalid, oversized, malformed, duplicate, or wrongly signed packs fail with
   no partial database writes.
2. Imported content is `SOURCE_PENDING` until source integrity and two distinct
   authorized reviewer decisions are present.
3. One person cannot satisfy both legal and compliance approvals.
4. Coverage gate reports every missing source/review/clause/control/test/evidence
   condition without converting unknowns into passes.
5. Version comparison is deterministic and preserves historic versions.
6. Cross-tenant import/review access is denied and audited.
7. SQLite and PostgreSQL CI suites, migrations, and production checks pass.

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

- Malicious/oversized JSON, signature spoofing, duplicate paths, partial imports,
  reviewer self-approval, cross-tenant review, source-status inflation, historic
  mutation, and misleading coverage claims.

## Completion record

### Implemented

- Canonical, schema-bounded JSON regulatory-pack intake with detached Ed25519
  verification against tenant-scoped trusted public keys.
- Atomic version, regulation, nested subclause, obligation, provenance, and
  source-coordinate import; malformed or unauthenticated packs create nothing.
- Separate legal-reviewer and compliance-lead decisions with distinct-person
  enforcement, immutable decision records, and audited status transitions.
- Deterministic version comparison and conservative coverage gates for source,
  review, regulation, obligation, control, test, and evidence completeness.
- Tenant-scoped REST endpoints and a browser regulatory center for import,
  review, coverage visibility, signing-key management, and version inspection.
- Forced PostgreSQL RLS for every new direct and inherited tenant table, plus
  admin status guards and publisher/operator documentation.

### Test evidence

- `.venv\\Scripts\\python.exe manage.py test --verbosity 1` — 29 tests passed on
  SQLite, with 3 PostgreSQL-only boundary tests explicitly skipped locally.
- `.venv\\Scripts\\python.exe manage.py makemigrations --check --dry-run` — no
  changes detected.
- Production-shaped `manage.py check --deploy` with debug disabled, strong
  secret, allowed host, trusted origin, and HTTPS settings — no issues.
- PowerShell backup/restore scripts parsed successfully; Compose and CI YAML
  parsed successfully; Python dependency check reported no broken requirements.

### Not implemented / known risks

- PostgreSQL RLS validation is delegated to CI because local Docker/PostgreSQL
  tools are unavailable; GitHub run evidence is recorded after publication.
- Signed manifest trust does not replace legal review or source-document
  authentication. Key rotation/revocation ceremony needs operator signoff.
- A rejected version is terminal and corrections require a new signed version.
- No authenticated Gazette was supplied; the local database contains no newly
  verified clause and no regulatory coverage claim is made.

### Next bounded work package

`WP-REG-02`: immutable evidence specifications and control/test mapping workflow,
without device collection or compliance scoring. Legal text remains blocked
until an authenticated Gazette is supplied.
