# ConfigSentinel Delivery Plan

## Current work package

`WP-COLLECT-01` — authorized read-only collector trust-boundary foundation.

## In scope

- Add tenant-scoped devices, external secret references, collector agents,
  written scope grants, pinned SSH host-key fingerprints, and collection jobs.
- Model an explicit command-profile approval boundary without shipping or
  executing any vendor command until separate operator/network review.
- Enforce active authorization windows, device/agent state, per-device locks,
  host-key pinning, command/time/output budgets, and fail-safe job states.
- Add role-aware API/UI, PostgreSQL forced RLS and immutable authorization/job
  history, audit events, negative tests, OpenAPI coverage, and operator docs.

## Explicitly out of scope

- Network connections, discovery/scanning, SSH/API execution, vendor commands,
  parsers, normalized facts, rules, findings, or live credentials.
- Production agent binaries, mTLS issuance, queues/workers, VPN deployment,
  signed job transport, raw-output storage, and automatic scheduling.
- Any configuration write, remediation command, reset/reload, exploit, or
  destructive probe.

## Acceptance tests

1. A job cannot be created without an active approved scope grant, exact device,
   pinned host key, active agent and approved command profile.
2. Credentials are opaque secret-manager references only and are never returned
   by API/UI, audit metadata, logs, fixtures, or job payload previews.
3. Device locks prevent concurrent active jobs; time, command and output budgets
   are mandatory positive bounded values and cannot be expanded by an agent.
4. Host-key mismatch, expired/revoked scope, unsupported profile, missing result,
   timeout or agent failure produces `UNKNOWN`/`ERROR`, never `PASS`.
5. Authorization/profile approvals are attributable and immutable; cross-tenant
   reads and foreign-object submissions are denied and audited.
6. No code path opens a socket or runs a subprocess/vendor command in this WP.
7. API/OpenAPI, UI, migrations, SQLite/PostgreSQL tests, docs and deployment
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

- Unauthorized targeting, tenant IDOR, credential disclosure, host-key spoofing,
  command substitution, replay, concurrent device access, unbounded collection,
  stale authorization, agent impersonation, and false-pass status inflation.

## Completion record

### Implemented

- Tenant-scoped devices, external secret references, collector identities,
  command-profile identities, written scope grants and collection job records.
- Independent scope approval, exact device/agent matching, authorization windows,
  pinned host-key checks, hard budgets and one-active-job-per-device constraint.
- Safe API/OpenAPI endpoints and collector setup UI; secret references are
  write-only and omitted from customer/admin read-back.
- Forced PostgreSQL RLS, immutable authorization/job guards, audit events,
  threat-model/ADR updates and operator instructions.

### Test evidence

- `.venv\\Scripts\\python.exe manage.py test apps.collector --verbosity 2` — all
  8 collector-boundary tests passed on SQLite.
- `.venv\\Scripts\\python.exe manage.py test --verbosity 1` — all 61 tests
  passed; 5 PostgreSQL-only security tests were explicitly skipped locally.
- Migration drift and Django system checks passed. Production and CI checks are
  recorded before package completion.

### Not implemented / known risks

- No socket, SSH/API transport, subprocess, agent binary or vendor command is
  included; the application cannot yet collect from a real device.
- Agent activation and command-profile approval remain deliberately blocked
  until signed enrollment and explicit network-operator review are implemented.
- Production secrets-manager resolution, mTLS, signed jobs, replay defense,
  distributed locks, queues and encrypted raw snapshots remain required.
- Official authenticated regulatory source text remains unavailable, so no
  legal compliance claim or regulatory `COMPLIANT` result is produced.

### Next bounded work package

`WP-COLLECT-02`: signed outbound-agent enrollment and replay-resistant job
transport, still without vendor commands. Actual command packs require separate
network-operator signoff and real firmware regression fixtures.
