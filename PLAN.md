# ConfigSentinel Delivery Plan

## Current work package

`WP-REG-02` — source PDF intake, reviewed clause register, clause-evidence
workflow and operational dashboard.

### Current bounded change: evidence intelligence safety gate

- Pause all Gemini/public-LLM calls behind an explicit, default-off feature flag.
- Keep the existing local keyword checks as preliminary triage only; they must
  not accept evidence or issue a legal compliance conclusion.
- Define the next evidence-intelligence design around file authenticity,
  structured requirement decomposition, dates/recurrence, approvals/signatures,
  cross-document consistency, image/OCR inspection and human review.
- Acceptance: a configured API key still causes no outbound call while the flag
  is disabled, and the result identifies the local preliminary engine.
- Security threat: keyword stuffing must not convert an unsupported document
  into accepted evidence or a verified compliance result.

Implementation status: local structured proof checks now require action-linked
roles/items and separately flag recurrence, approval/signature, unreadable or
image-only evidence, and suspicious repetition. Gemini remains disabled.
Withdrawal now purges the encrypted blob and wrapped key material, removes the
file from active UI/context, retains a minimal audit tombstone, and recalculates
the preliminary finding from the remaining active evidence.
Local RapidOCR processing now extracts visible text from JPG/JPEG/PNG files and
image-only DOCX evidence without sending evidence to an external service. OCR
output remains untrusted supporting material and cannot authenticate a photo,
signature, attendance event, date or operating effectiveness.
Clauses that explicitly require a policy/procedure/plan/programme/framework/SOP
now receive a separate document assessment: candidate-document presence,
document-control fields, and source-derived content-topic coverage. All matches
remain preliminary and unverified; no policy is accepted from filename or
keyword presence alone.

## In scope

- Add an encrypted official-source PDF intake path, a human-reviewed clause
  register, and source/document hash provenance.
- Add simple ISP clause-evidence submission against exact reviewed clause IDs,
  independent acceptance/rejection, and honest clause readiness states.
- Replace the normal-user manifest/signature screen with guided PDF-to-clause
  workflow; retain signed manifest import as an advanced administrator route.
- Add a dashboard with status counts and charts; no legal certification or
  document AI inference.

## Explicitly out of scope

- OCR/LLM-based legal extraction, automatic legal interpretation, and an
  automatic `COMPLIANT` or legal certification outcome.
- Device collection, parser/rule packs, automatic remediation, notices, report
  exports, production KMS/S3 credentials, or production retention defaults.

## Acceptance tests

1. Official source upload stores ciphertext only and records a hash, uploader,
   source metadata, and `SOURCE_PENDING` status until review.
2. Each clause is an exact user-entered source coordinate with page and review
   state; the app never invents or silently extracts legal text from a PDF.
3. ISP evidence attaches to an exact clause and stays `UNDER_REVIEW` until an
   independent reviewer accepts/rejects it; foreign-tenant IDs fail closed.
4. Dashboard displays only `READY`, `GAP`, `INSUFFICIENT_EVIDENCE`,
   `LEGAL_UNVERIFIED`, and `N_A`; it never calls an ISP legally compliant.
5. API/OpenAPI, UI, migration, RLS, encryption/tamper, permission and negative
   tests pass.

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
- Migration drift, Django system/deployment checks, dependency and YAML checks
  passed. GitHub Actions run `39375549090` passed, including PostgreSQL RLS and
  immutable authorization-boundary tests.

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
