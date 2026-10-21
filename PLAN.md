# ConfigSentinel Delivery Plan

## Current work package

`WP-EVID/AUD-01` — independent clause evidence review and audit dossier.

### Current bounded change: auditor review and report preview

- Add append-only, tenant-scoped clause assessment decisions by an independent
  auditor: `ACCEPT`, `REJECT`, or `REQUEST_UPDATE`.
- Keep the preliminary machine result, evidence-file status, legal-source
  status, and auditor assessment visibly separate.
- Require an auditor note and recorded gaps; prevent evidence uploaders from
  reviewing their own clause evidence set.
- Force `LEGAL_UNVERIFIED` while the source or mapping is not verified; an
  auditor decision must never turn a pending source into legal compliance.
- Add an auditor-room UI, role-aware API/OpenAPI surface, and a print-friendly
  clause-by-clause report preview with immutable decision history.
- Acceptance: tenant isolation, role enforcement, separation of duties,
  append-only history, fail-closed legal state, report contents, and negative
  paths have automated tests.
- Security threats: cross-tenant object references, uploader self-review,
  overwritten verdict history, status inflation, and sensitive evidence bytes
  leaking into report or audit logs.

Implementation status: complete in the local development build. The auditor
room supports integrity-backed file accept/reject decisions, append-only clause
assessment versions, evidence-change warnings, role separation, a print report,
CSV export, API serializers/endpoints, audit events, migrations and PostgreSQL
RLS/immutability guards. Reports contain evidence metadata and hashes, never
decrypted evidence content.

Test evidence: `manage.py test` passed 80 tests; 5 PostgreSQL-only boundary
tests were skipped by the local SQLite environment. The focused regulatory
suite passed 44 tests and the new auditor workflow passed 5 tests. Migration
drift and Django system checks passed. Deployment check reports the expected six
local-development warnings for DEBUG, HSTS, HTTPS redirect, cookie flags and
the development secret; production Compose/environment settings remain the VPS
deployment gate.

Regulatory source status: uploaded clauses remain `SOURCE_PENDING`; therefore
auditor assessments correctly remain `LEGAL_UNVERIFIED` until the user-supplied
official source and exact mappings complete WP-REG dual review.

### Current extension: auditor onboarding, signed report and dashboard roll-up

- Allow tenant owners to create a dedicated auditor login from the application;
  passwords are validated and never returned or written to audit metadata.
- Allow auditors to upload an encrypted PDF containing their signed/on-site
  report. Uploading a report does not silently change clause decisions; exact
  clause assessments remain attributable records in the auditor room.
- Add a separate dashboard chart for the latest human auditor states: `READY`,
  `GAP`, `INSUFFICIENT_EVIDENCE`, `LEGAL_UNVERIFIED`, stale and not reviewed.
- Acceptance: owner-only account creation, auditor-only report upload, tenant
  isolation, encrypted PDF storage, download authorization, dashboard roll-up,
  audit events, migrations, API contract, UI, docs and negative tests.

Extension status: implemented. Targeted auditor tests passed 8/8 and the full
suite passed 83 tests with 5 PostgreSQL-only tests skipped on local SQLite.
Local migrations and Django system checks passed. The source pack remains
`SOURCE_PENDING`, so the human chart currently distinguishes auditor review
from legal verification and does not present a regulator-certified result.

### Previous work package

`WP-REG-02` — source PDF intake, reviewed clause register, clause-evidence
workflow and operational dashboard.

### Current bounded change: WP-REG completion gate

- Complete authoritative source metadata capture (authority URL, gazette/SRO
  identifier, version and effective date).
- Allow authorized users to register exact clause-derived obligations and
  evidence expectations without AI invention.
- Add visible readiness blockers and separate legal/compliance approval actions.
- Prevent either approval while source provenance, page/text coordinates,
  subclauses or obligation coverage are incomplete.
- Acceptance: two distinct authorized reviewers can verify a ready pack; an
  incomplete PDF extraction remains `SOURCE_PENDING` with actionable blockers.

### Completed bounded change: evidence intelligence safety gate

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
Operational screenshots/logs are classified separately as supporting evidence.
They may corroborate a narrow operational activity but never replace a required
controlled policy, plan, BIA, SOP or procedure.
Each preliminary finding now includes an evidence-coverage percentage with a
visible non-legal disclaimer. If a required controlled document is missing,
supporting screenshots/logs are capped at 10% coverage rather than inflating
the result.
Preliminary evidence status bands: below 50% is `NON_COMPLIANT`, 50–99% is
`PARTIAL`, and 100% evidence remains `PARTIAL` pending verified legal mapping
and independent review. A `COMPLIANT` state is only possible after those gates.

## In scope

- Add an encrypted official-source PDF intake path, a human-reviewed clause
  register, and source/document hash provenance.
- Capture authority URL, gazette/SRO identifier and effective date, and expose
  fail-closed readiness blockers before dual review.
- Register human-authored clause obligations and evidence specifications, then
  require independent legal and compliance decisions.
- Add simple ISP clause-evidence submission against exact reviewed clause IDs,
  independent acceptance/rejection, and honest clause readiness states.
- Replace the normal-user manifest/signature screen with guided PDF-to-clause
  workflow; retain signed manifest import as an advanced administrator route.
- Add a dashboard with status counts and charts; no legal certification or
  document AI inference.

## Explicitly out of scope

- AI-generated legal obligations, automatic legal interpretation, and an
  automatic legal certification outcome. Unedited PDF text extraction is only
  a review aid and remains `SOURCE_PENDING`.
- Device collection, parser/rule packs, automatic remediation, notices, report
  exports, production KMS/S3 credentials, or production retention defaults.

## Acceptance tests

1. Official source upload stores ciphertext only and records a hash, uploader,
   source metadata, and `SOURCE_PENDING` status until review.
2. Each extracted clause retains its PDF page and unedited source text, remains
   pending, and receives only human-authored obligation/evidence mappings.
3. ISP evidence attaches to an exact clause and stays `UNDER_REVIEW` until an
   independent reviewer accepts/rejects it; foreign-tenant IDs fail closed.
4. Dual approval fails closed until provenance, source coordinates and
   obligation coverage are complete; reviewer identities are distinct.
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
