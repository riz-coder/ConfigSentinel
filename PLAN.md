# ConfigSentinel Delivery Plan

## Current work package

`WP-CORE-01` — production-shaped foundation for Windows development and later
single-VPS deployment, with the minimum regulatory source workflow required to
enforce honest legal states.

## In scope

- Initialize a Git-ready repository and documented Python development workflow.
- Bootstrap Django/DRF with environment-based settings and PostgreSQL support.
- Add tenant, membership, role, and tenant-bound access foundations.
- Add append-only audit event foundations.
- Add regulatory source/version/regulation models with legal source states.
- Expose a small role-aware API and server-rendered dashboard.
- Provide Docker Compose development and production-shaped deployment files.
- Add automated tests for authentication, cross-tenant isolation, immutable
  audit records, and regulatory state guards.
- Document setup, deployment assumptions, security decisions, and acceptance
  results.

## Explicitly out of scope

- Production device collection or network commands.
- Evidence uploads and object-store retention workflows.
- Full CTDISR clause transcription or legal interpretation.
- Compliance scoring, regulator submission, AI processing, and billing.
- Claims of PTA certification or customer compliance.

## Acceptance tests

1. A user cannot access another tenant's records through API object IDs.
2. Unauthenticated API and dashboard requests are rejected safely.
3. Audit events cannot be updated or deleted through the application model.
4. A regulation cannot use `VERIFIED` unless its parent source version is
   approved and has source integrity metadata.
5. `SOURCE_PENDING` remains distinct from technical and compliance outcomes.
6. Django system checks and the complete automated test suite pass locally.
7. Production settings reject missing secrets and unsafe host configuration.

## Dependencies

- Python 3.11+ for local Windows development.
- PostgreSQL for staging/production; SQLite is permitted only for local tests
  and first-run development.
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

- Cross-tenant object access and insecure direct object references.
- Accidental use of development settings in production.
- Secret leakage through committed environment files or logs.
- Mutation/removal of finalized audit history.
- Status inflation from unverified legal sources.
- Direct internet exposure of database, broker, or cache services.

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
