# ConfigSentinel Delivery Plan

## Current work package

`WP-CORE-02` — authentication hardening and PostgreSQL-enforced tenant/audit
boundaries for Windows development and later single-VPS deployment.

## In scope

- Add TOTP MFA enrollment/verification and require it for privileged roles.
- Add login throttling/lockout and authentication audit events.
- Establish request-scoped tenant context and PostgreSQL row-level security.
- Add PostgreSQL database-level append-only guards for audit events.
- Document separate owner/runtime database roles and least-privilege grants.
- Add PostgreSQL backup, restore, and verification scripts for VPS operations.
- Exercise migrations and isolation in CI against PostgreSQL as well as SQLite.
- Update UI, API contract, tests, threat model, and operator documentation.

## Explicitly out of scope

- Production device collection or network commands.
- Evidence uploads and object-store retention workflows.
- Full CTDISR clause transcription or legal interpretation.
- Compliance scoring, regulator submission, AI processing, and billing.
- Claims of PTA certification or customer compliance.

## Acceptance tests

1. Privileged members cannot use tenant pages until TOTP is enrolled and verified.
2. Repeated failed logins are throttled without disclosing account existence.
3. PostgreSQL rejects cross-tenant reads/writes even if an application query
   accidentally omits its tenant filter.
4. PostgreSQL rejects update/delete attempts against audit events for the
   runtime role.
5. Tenant context is validated against active membership before it reaches SQL.
6. Backup and restore scripts fail safely and document encrypted off-host use.
7. Django checks, migrations, SQLite tests, and PostgreSQL CI tests pass.

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

- Authentication brute force, privileged sessions without MFA, session fixation,
  cross-tenant SQL access, stale tenant context on pooled connections, audit
  deletion/tampering, over-privileged runtime database access, and unverified
  backups.

## Completion record

### Implemented

- Django/DRF modular monolith, Windows virtual environment workflow, migrations,
  tenant memberships and role-aware regulatory APIs.
- Append-only audit model and read-only administration surface.
- Regulatory source/version/regulation integrity guards and idempotent command
  for 84 explicit `SOURCE_PENDING` slots.
- Authenticated dashboard, health check, OpenAPI endpoint, Docker/Compose/Caddy
  deployment shape, CI workflow, ADR, threat model, and operator README.

### Test evidence

- `.venv\\Scripts\\python.exe manage.py test --verbosity 1` — 14 tests passed.
- `.venv\\Scripts\\python.exe manage.py makemigrations --check --dry-run` — no
  changes detected.
- Production-shaped `manage.py check --deploy` with debug disabled, strong
  secret, allowed host, trusted origin, and HTTPS settings — no issues.
- Health endpoint smoke test — HTTP 200 with `{"status": "ok"}`.

### Not implemented / known risks

- Docker execution was not tested because Docker is not installed locally.
- PostgreSQL RLS/non-owner runtime role, MFA/SSO, Celery/broker, encrypted object
  storage, backups, and evidence workflows remain future packages.
- Model-level audit immutability does not protect against a database owner.
- No authenticated Gazette was supplied; no clause is asserted as verified.

### Next bounded work package

`WP-CORE-02`: PostgreSQL-enforced tenant isolation, authentication hardening/MFA,
database roles, audit database guards, and deployment/backup validation.
