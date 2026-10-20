# ConfigSentinel Delivery Plan

## Current work package

`WP-CORE-03` — privacy-safe product presentation and neutral customer-facing
framework terminology.

## In scope

- Replace authority-specific customer-facing branding with neutral assurance
  and framework terminology.
- Make the displayed product name configurable for private deployments.
- Neutralize the seeded placeholder source title, including existing databases.
- Add regression tests preventing authority-specific text in rendered pages.
- Document the confidentiality boundary between private runtime data and the
  currently public source repository.

## Explicitly out of scope

- Repository visibility/history rewrite or deletion of project documentation.
- Evidence ingestion, device access, clause assessment, or scoring.
- Changes to legal source identifiers stored from authenticated imports.
- Claims that UI wording alone makes a public repository confidential.

## Acceptance tests

1. Rendered login/dashboard/framework/MFA pages contain no `PTA` or `CTDISR`.
2. Branding can be changed with configuration without code edits.
3. Existing exact placeholder titles are migrated to neutral wording without
   altering authenticated imported legal sources.
4. Internal legal/audit semantics and source integrity gates remain unchanged.
5. Tests, migration checks, and production checks pass.

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

- Accidental authority affiliation, sensitive project-purpose disclosure in the
  UI, destructive rewriting of genuine source metadata, and false privacy claims.

## Completion record

### Implemented

- Configurable `Assurance Workspace` product branding for browser pages, API
  schema, and authenticator issuer without authority-specific affiliation.
- Neutral framework/source terminology on dashboard, source center, mappings,
  login, and MFA pages.
- A narrow data migration that renames only the known empty placeholder source;
  authenticated imported source metadata remains unchanged.
- Neutral seed output and regression assertions preventing `PTA` or `CTDISR`
  from appearing in rendered customer pages.

### Test evidence

- `.venv\\Scripts\\python.exe manage.py test --verbosity 1` — 38 tests passed on
  SQLite, with 4 PostgreSQL-only boundary tests explicitly skipped locally.
- `.venv\\Scripts\\python.exe manage.py makemigrations --check --dry-run` — no
  changes detected.
- Production-shaped `manage.py check --deploy` with debug disabled, strong
  secret, allowed host, trusted origin, and HTTPS settings — no issues.
- PowerShell backup/restore scripts parsed successfully; Compose and CI YAML
  parsed successfully; Python dependency check reported no broken requirements.

### Not implemented / known risks

- The GitHub repository is currently public and contains project blueprint,
  documentation, and immutable Git history with authority-specific context.
  Neutral runtime branding does not make that repository confidential.
- Changing repository visibility or rewriting published history requires an
  explicit owner decision and separate credential/secret exposure review.
- The full document/device assessment workflow remains unimplemented; current
  capabilities are the security, legal-source, and mapping foundation only.

### Next bounded work package

`WP-EVID-01`: encrypted, content-addressed evidence vault abstraction with
tamper checks, review states, retention/legal-hold guards, and custody events.
Legal text remains blocked until an authenticated Gazette is supplied.
