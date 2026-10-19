# ConfigSentinel Delivery Plan

## Current work package

`WP-REG-02` — versioned control, test, and evidence-requirement mappings with
maker-checker approval and immutable history.

## In scope

- Add tenant-scoped, versioned control definitions, test procedures, and
  evidence requirements without storing evidence artifacts yet.
- Map a verified obligation to an exact control/test/evidence version.
- Require submission plus independent legal and compliance approvals for every
  mapping; the author cannot approve their own mapping.
- Make finalized mappings and review decisions append-only and auditable.
- Update coverage gates to count only approved exact mappings.
- Add migrations, forced RLS, role-aware API/UI, negative tests, and docs.

## Explicitly out of scope

- Evidence artifact upload, encrypted object storage, retention enforcement, or
  legal holds (`WP-EVID`).
- Control implementation/assessment, device collection, rules, and scoring.
- Full CTDISR transcription, applicability decisions, and legal interpretation.
- Regulatory submission, auditor certification, AI processing, and billing.

## Acceptance tests

1. Only verified obligations can receive a submitted mapping.
2. Mapping references must belong to one tenant and an internally consistent
   control → test → evidence chain.
3. The author cannot approve; legal and compliance approvals require distinct,
   authorized people and both are required for finalization.
4. Approved mappings/reviews cannot be edited or deleted; corrections create a
   new version/mapping while old audit history remains.
5. Coverage remains incomplete for draft/rejected/partially reviewed mappings.
6. Cross-tenant reads/writes/reviews are denied and audited where attempted.
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

- Cross-tenant mapping, IDOR, inconsistent references, self-approval, role
  escalation, historic mutation, duplicate active mapping, and false coverage.

## Completion record

### Implemented

- Tenant-scoped, uniquely versioned control definitions, test procedures, and
  evidence requirements linked as an exact validated chain.
- Verified-obligation mapping submission with author separation, independent
  legal/compliance decisions, finalization, and audit events.
- Conservative coverage calculation that ignores draft, rejected, partially
  reviewed, legacy free-text, and legally unverified mappings.
- Append-only finalized mappings/reviews and referenced catalogue protection at
  the Django boundary and with PostgreSQL triggers.
- Role-aware REST endpoints and browser workflow for authoring, reviewing, and
  inspecting mappings without implying evidence acceptance.
- Forced PostgreSQL RLS for all new direct and inherited tenant tables, an ADR,
  and an explicit current mapping-coverage statement.

### Test evidence

- `.venv\\Scripts\\python.exe manage.py test --verbosity 1` — 37 tests passed on
  SQLite, with 4 PostgreSQL-only boundary tests explicitly skipped locally.
- `.venv\\Scripts\\python.exe manage.py makemigrations --check --dry-run` — no
  changes detected.
- Production-shaped `manage.py check --deploy` with debug disabled, strong
  secret, allowed host, trusted origin, and HTTPS settings — no issues.
- PowerShell backup/restore scripts parsed successfully; Compose and CI YAML
  parsed successfully; Python dependency check reported no broken requirements.

### Not implemented / known risks

- PostgreSQL RLS/trigger validation is delegated to CI because local
  Docker/PostgreSQL tools are unavailable.
- This package specifies expected evidence but does not upload, encrypt, retain,
  validate, or accept an actual artifact.
- It does not assess applicability, control implementation, test execution,
  operating effectiveness, audit opinion, or customer compliance.
- No authenticated Gazette was supplied; no production clause mapping has been
  populated and no regulatory coverage claim is made.

### Next bounded work package

`WP-EVID-01`: encrypted, content-addressed evidence vault abstraction with
tamper checks, review states, retention/legal-hold guards, and custody events.
Legal text remains blocked until an authenticated Gazette is supplied.
