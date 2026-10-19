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

- TOTP enrollment and verification gate for authenticated tenant/application
  access, including QR enrollment and tenant/API denial before verification.
- Five-attempt login throttling with a 30-minute cooldown and redacted platform
  authentication audit events.
- Transaction-local tenant context plus forced PostgreSQL RLS on regulatory
  source/version/regulation data.
- Default-deny audit reads/updates, database append-only trigger, and existing
  application-model immutability.
- Separate schema-owner migration service and non-superuser runtime database
  role in the Compose topology.
- Windows/Linux checksum-generating backup and verified/destructive-restore
  scripts, database security documentation, and PostgreSQL CI validation.

### Test evidence

- `.venv\\Scripts\\python.exe manage.py test --verbosity 1` — 20 tests passed on
  SQLite, with the 2 PostgreSQL-only boundary tests explicitly skipped locally.
- GitHub Actions run `39243944720` — SQLite and PostgreSQL 17 jobs passed;
  PostgreSQL exercised forced-RLS cross-tenant read/write denial and database
  audit guards under a non-superuser owner role.
- `.venv\\Scripts\\python.exe manage.py makemigrations --check --dry-run` — no
  changes detected.
- Production-shaped `manage.py check --deploy` with debug disabled, strong
  secret, allowed host, trusted origin, and HTTPS settings — no issues.
- PowerShell backup/restore scripts parsed successfully; Compose and CI YAML
  parsed successfully; Python dependency check reported no broken requirements.

### Not implemented / known risks

- Full Compose deployment and a real backup/restore drill were not executed
  because Docker/PostgreSQL client tools are unavailable on this workstation.
- Database superusers can alter RLS/triggers and must never be application roles.
- SSO, governed MFA recovery codes, field-level sensitivity grants, encrypted
  object storage, scheduled off-host backups, Celery, and evidence workflows
  remain future packages.
- No authenticated Gazette was supplied; no clause is asserted as verified.

### Next bounded work package

`WP-REG-01`: supervised regulatory source import, source hashing, dual-review
workflow, nested clause hierarchy, version diffs, and coverage gates. Legal text
remains blocked until an authenticated Gazette is supplied.
