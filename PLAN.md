# ConfigSentinel Delivery Plan

## Current work package

`WP-NET-05` — application-dispatched local collector jobs.

- Let an authorized operator dispatch a queued job from the UI without exposing
  a terminal command or blocking the Django request on network I/O.
- Launch the existing fixed management-command worker as a detached subprocess
  with `shell=False`, an exact job UUID and no user-controlled command text.
- Retain all agent/scope/profile/device gates inside the worker and audit the
  dispatch. Production remote-agent scheduling remains a later mTLS/queue WP.
- Provide write-only in-app credential provisioning into the local encrypted
  agent store; auto-create a protected local key only for this local deployment,
  while production remains dependent on a managed secret/key service.

### Previous work package

`WP-NET-04` — Cisco NX-OS collection-profile foundation.

- Add a separate integrity-hashed Nexus NX-OS read-only command manifest,
  platform discovery and Netmiko transport selection; never run the IOS profile
  against a device registered/discovered as NX-OS.
- Retain independent command-profile approval and explicit UNKNOWN results for
  unsupported feature-dependent commands.
- Keep customer-added commands out of running jobs until a bounded validation,
  versioning and two-person approval workflow is implemented.

### Previous work package

`WP-NET-03` — Cisco IOS/IOS-XE parsing and technical assessment baseline.

- Decrypt and integrity-check completed Cisco command snapshots locally, parse
  only bounded structured facts, and link every finding to its command evidence.
- Evaluate versioned deterministic configuration/security rules with explicit
  PASS/FAIL/WARNING/UNKNOWN/NOT_APPLICABLE/ERROR results.
- Generate a tenant-scoped device report covering identity, command coverage,
  configuration/security gaps, operations and topology observations.
- Keep Cisco advisory correlation UNKNOWN until a reviewed official advisory
  feed and exact release/platform matching are implemented.

Implementation status: complete for the bounded deterministic Cisco baseline.
Successful collection invokes a versioned rule pack and produces a tenant report
with evidence-linked technical results. Initial checks cover management-plane,
AAA, logging, NTP, SNMP and snapshot integrity. Raw configuration is not
rendered. Interface/VLAN/STP/routing/topology parsers, official PSIRT ingestion
and real-firmware validation remain follow-on Cisco work.

### Previous work package

`WP-CORE-03` — tenant owner-controlled user lifecycle.

- Exactly one active tenant owner controls user creation, access disablement,
  temporary password resets and explicit ownership transfer.
- Preserve attributable history by disabling memberships instead of deleting
  referenced user rows; prevent owner self-disable and last-owner removal.
- Require the current owner's password for ownership transfer and record every
  lifecycle action in the append-only tenant audit log.
- Provide a tenant-scoped owner-only UI and tests for authorization, password
  validation, session invalidation behavior and separation of duties.

Implementation status: complete for the bounded owner lifecycle. The owner-only
Users screen creates non-owner memberships, resets temporary passwords, disables
access without deleting attributable history, and transfers the single active
owner role only after current-password verification. Every mutation is audited.
Focused tenancy tests passed 8/8; the full local suite passed 121 tests with 6
PostgreSQL-only tests skipped.

### Previous work package

`WP-NET-02` — local/on-prem outbound collector execution slice.

### Current bounded change: safe Cisco IOS/IOS-XE live collection

- Add an agent-local encrypted secret store populated through a no-echo CLI;
  raw usernames/passwords never enter Django forms, API responses, logs or Git.
- Execute only an independently approved exact command manifest over SSH or an
  explicitly approved Telnet exception; never accept free-form commands or
  silently downgrade transport.
- Perform SSH host-key preflight, deterministic `show version` platform/model/
  release discovery, per-device locking and command/runtime/output budgets.
- Record per-command states and hash-addressed encrypted raw snapshots without
  rendering full configuration in the UI.
- Fail unsupported, denied, timed-out, truncated or unparseable collection as
  `UNKNOWN`/`ERROR`; do not emit technical PASS or legal compliance states.

Acceptance tests: secret-store authentication/tamper failure, no secret output,
host-key mismatch, Telnet approval, exact allowlist enforcement, platform
mismatch, timeout/output budgets, encrypted snapshot lineage, state transitions,
tenant isolation, UI/API contracts and mocked transport execution. No test may
connect to a real or private network endpoint.

Security threats: credential exfiltration, command injection, malicious device
output, host spoofing, clear-text Telnet, runaway output, concurrent scans,
cross-tenant job claims and sensitive configuration leakage. Cryptography,
commands and real-device enablement require explicit operator/code review.

Known boundary: this slice runs as a separate local/on-prem management-command
agent against the same deployment database. Remote signed/mTLS job delivery,
Celery/Redis scheduling, production secrets manager and real-firmware lab
certification remain required before commercial deployment.

Implementation status: complete for the bounded local-agent slice. Device
registration installs the reviewed Cisco candidate manifest, while execution
still requires independent profile, agent and scope approval. The collector
resolves an encrypted local credential, pins the SSH host key, validates the
actual IOS/IOS-XE identity, enforces approved budgets, runs only manifest
commands, and stores one encrypted/hash-linked snapshot per successful command.
Command and snapshot metadata are tenant-scoped through API/RLS and immutable
after terminal capture. Targeted collector tests passed 18/18; the full local
SQLite suite passed 116 tests with 6 PostgreSQL-only tests skipped. No real
device was contacted, so actual supported firmware remains an operator/lab
signoff blocker. No parser verdict, topology graph, device technical PASS or
legal compliance decision is produced by this package.

### Previous work package

`WP-NET-01` — reviewed Cisco collection-plan foundation.

### Current bounded change: safe device assessment planning

- Link a collector device to one active tenant asset and record SSH or explicit
  legacy Telnet transport without storing raw credentials in the control plane.
- Represent every Cisco IOS/IOS-XE command as an exact, versioned command row;
  reject free-form or configuration-mode commands and require independent
  operator approval before a profile can be queued.
- Separate discovery, configuration, security, topology and operational command
  purposes; expose the exact planned command list and CDP/LLDP topology intent.
- Keep live network execution blocked until the outbound signed agent, vault
  resolver, encrypted snapshots, parser fixtures and job claim protocol exist.
- Treat all candidate device-to-regulation links as `SOURCE_PENDING`; technical
  output cannot create a legal compliance result.

Acceptance tests: tenant isolation, asset binding, SSH host-key enforcement,
Telnet exception validation, exact allowlist rejection, two-person profile
approval, command-budget enforcement, no secret read-back, API/UI contracts and
audit events. Security threats: credential leakage, command injection, silent
SSH-to-Telnet downgrade, cross-tenant asset access, unreviewed command execution,
concurrent device jobs, excessive output and legal-status inflation.

Dependencies/blockers: production secrets manager, outbound mTLS collector,
network-engineer review against actual supported Cisco firmware, anonymized
real-device fixtures and dual-reviewed official clause mappings. These remain
required before live collection or sold compliance claims.

Implementation status: collection planning is complete for this bounded slice.
The UI/API support asset-linked SSH devices, independently approved Telnet
exceptions, opaque vault references and an integrity-hashed 22-command Cisco
IOS/IOS-XE draft/approval workflow covering configuration, security, operations
and CDP/LLDP topology intent. PostgreSQL RLS protects command rows and approved
rows are database-immutable. Focused collector tests passed 13/13 and the full
suite passed 111 tests with 6 PostgreSQL-only tests skipped on local SQLite. No live
network connection, parser result, rule verdict or legal clause claim is
implemented in this package.

The customer UI does not expose manual vendor-profile installation. The next
agent package must discover actual vendor/model/OS/release/capabilities first,
then derive the reviewed least-command collection plan for configuration,
security, operations, topology and approved control needs.

### Previous work package

`WP-ASSET-01` — tenant asset, site and critical-service foundation.

### Current bounded change: asset/CII system of record

- Establish tenant-scoped sites, critical services, assets and explicit asset
  dependencies with accountable owner/custodian and lifecycle metadata.
- Provide guarded manual and CSV/XLSX/XLS onboarding, duplicate rejection and
  cross-tenant validation; incomplete scope remains visible and never passes.
- Add role-aware UI/API, dashboard readiness indicators, append-only audit
  events, PostgreSQL RLS, migrations, docs and regression tests.
- Explicitly exclude device polling, legal CII determination and automatic
  compliance conclusions from this package.

Implementation status: complete in the local build. Sites, critical services,
assets and dependency records are tenant scoped with accountable ownership,
criticality, classification and lifecycle. Manual and atomic CSV onboarding,
role-aware API/UI, audit events, dashboard gaps and PostgreSQL RLS are included.
CSV, XLSX and legacy XLS files accept common encodings and delimiters, while
the standard template fixes the required column contract; tenant people and
scope references must resolve unambiguously before atomic import proceeds.
The UI now provides fixed-column CSV/XLSX templates with three example rows;
the columns cover every minimum attribute category transcribed from Regulation
11(3) of the uploaded source copy while retaining `SOURCE_PENDING` status.
Unknown acquisition/review dates no longer block a batch import, and repeated
row failures are compacted into readable row ranges. Business owner/custodian
names and roles are preserved without requiring matching login accounts; the
authenticated importer remains the accountable system actor. Focused inventory tests
now also cover permission-gated editing, traceable archival and criticality UI
indicators; focused inventory tests passed 14/14. The earlier full suite passed 101 tests with 6
PostgreSQL-only tests skipped on local SQLite. CII remains a customer scope
candidate and never changes legal or compliance state.

### Previous work package

`WP-CAPA-01` — controlled corrective-action and retest workflow.

### Current bounded change: corrective action lifecycle

- Create an action draft from a human auditor rejection or update request; no
  machine preliminary finding creates a remediation obligation automatically.
- Allow ISP owner/compliance lead to assign an accountable owner, plan and due
  date, add immutable progress history and attach new encrypted evidence
  versions to the related clause.
- Allow only a tenant auditor to close or reopen an action after it reaches
  `READY_FOR_RETEST`; action closure never changes legal-source state.
- Add action dashboard counters for open, overdue, retest-ready and closed
  actions, plus role-aware UI/API and audit history.
- Acceptance: transitions, role separation, tenant isolation, evidence lineage,
  immutable events, overdue calculation, RLS, UI, API, docs and regression
  tests pass.

Implementation status: complete in the local build. Auditor reject/request-update
assessments create one traceable action draft; authorized users can backfill
older gap decisions once. ISP owner/compliance users assign an owner, due date
and remediation plan, add encrypted evidence versions/progress, and submit for
retest. An independent auditor alone can close or reopen it. Closing a CAPA
does not alter source verification or make a legal-compliance claim.

### Previous work package

`WP-AUD-02` — confirmed import of clause decisions from an auditor PDF.

### Current bounded change: auditor PDF decision import

- Extract only explicit clause number, auditor status and remarks from a
  text-readable uploaded PDF using local deterministic parsing.
- Store extracted rows as drafts; unmatched, duplicate or ambiguous rows remain
  blocked until the auditor corrects them in a preview screen.
- Require explicit auditor confirmation before creating immutable clause
  assessment versions and updating dashboard roll-ups.
- Preserve the original auditor wording/status and report hash in each decision
  snapshot. Never send the report to an external model.
- Force `LEGAL_UNVERIFIED` while source/mapping gates are pending, even where
  the uploaded report says compliant.
- Acceptance: permissions, tenant isolation, parser edge cases, correction,
  confirmation idempotency, immutable decisions, dashboard update, RLS, API,
  UI and documentation tests pass.

Implementation status: complete in the local build. Single-line and multiline
text-readable PDF rows are parsed locally into editable drafts; unmatched and
duplicate references block confirmation. Confirmed rows create immutable,
report-hash-linked assessments and update the existing auditor dashboard chart.
Targeted auditor tests passed 12/12; the full suite passed 87 tests with 5
PostgreSQL-only tests skipped on local SQLite. Migrations, drift check, Django
system checks and UTF-8 OpenAPI schema generation passed. Scanned/image-only
auditor verdict PDFs remain unsupported to avoid unsafe OCR status inference.

### Previous work package

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

Navigation cleanup: remove the standalone Evidence Vault link from the sidebar
because clause evidence and auditor reports are managed in their respective
workflows. The encrypted vault backend, API and stored data remain unchanged.

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
