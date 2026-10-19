# AGENTS.md — ConfigSentinel Compliance OS (Commercial Product)

## Mission
Build a production-grade, Pakistan telecom compliance and network-assurance platform under the attached Master Blueprint. No arbitrary 21-day deadline. Work in bounded quality-gated packages and retain full traceability.

## Absolute rules
1. Read the entire `ConfigSentinel_Compliance_OS_Master_Blueprint.md` and this file before modifying code. Stay within one declared work package; do not implement unrelated components.
2. NEVER fabricate PTA CTDISR legal clauses, subclauses, deadlines, applicability, certification, approvals or evidence. Regulatory items 28–84 and subclauses beyond accessible OCR are `SOURCE_PENDING` until signed official source and human legal approval. No regulatory `COMPLIANT` state without verified legal mapping.
3. NEVER claim ConfigSentinel/PTA certification, guaranteed legal compliance, regulator endorsement or full automated regulation fulfillment.
4. No production device configuration modification, commands with side effects, resets, reloads, vulnerability exploitation, destructive probes, or unauthorized scanning. Collector read-only with explicit allowlist, per-device locks, budgets, host-key verification and scope authorization.
5. NEVER treat missing, stale or unsupported collection results as PASS; return UNKNOWN/ERROR/NOT_APPLICABLE with reason. AI must not invent facts, commands, measurements or legal obligations.
6. No secrets, full sensitive configs, CNIC/CDR/subscriber data, incident attachments, access tokens or internal IP evidence in logs, tickets, public LLM calls or test snapshots. Redact and encrypt by classification and ensure tenant isolation.
7. Don't send regulatory notices automatically. Approval, official channel configuration, human submission and recorded receipts required.
8. Human approvals and third-party audit are real workflows, not automatic stamps. Separation of duties enforced. Evidence must be attributable, versioned, timestamped and tamper-evident.
9. All end-user error paths must fail safely with actionable diagnosis; maintain append-only audit history and avoid destructive migrations.
10. If legal document unavailable, deliver honest partial software scaffolding and raise a BLOCKER. Never silently infer missing law from 2020 or a competitor blog.

## Work protocol
- Begin work with `PLAN.md`: current WP, tasks, acceptance tests, dependencies, legal blockers, security threats.
- Implement migration + permission layer + API/OpenAPI + UI + automated tests + docs together for each WP.
- Run targeted and full relevant tests; report actual commands/results and limitations. Do not state tests passed unless executed.
- Add regression fixture for each vendor command version and parse edge case; data fixtures must be anonymized.
- Update ADRs and regulatory mapping coverage reports with any change to contract/schema.
- Require code review and explicit operator signoff for changes to rule packs, collector commands, cryptography, or compliance aggregation.
- Each PR concludes with: `Implemented`, `Not implemented`, `Test evidence`, `Security review`, `Regulatory source status`, `Known risks`, `Next WP`.

## Required states
Technical checks: PASS / FAIL / WARNING / UNKNOWN / NOT_APPLICABLE / ERROR. Legal source: VERIFIED / SOURCE_PENDING / SUPERSEDED. Evidence: ACCEPTED / REJECTED / STALE / MISSING / UNDER_REVIEW. Compliance: READY / GAP / INSUFFICIENT_EVIDENCE / LEGAL_UNVERIFIED / N_A. Never merge these into one score.

## Proposed stack
Django/DRF, PostgreSQL, Celery with Redis/RabbitMQ, encrypted S3-compatible object storage, on-prem outbound signed collectors, versioned parsers/rules, typed schemas, HTMX/React if justified; Python-based tests, integration contracts, OpenTelemetry. Secrets manager for credentials. No arbitrary auto-remediation.

## Mandatory shipment checklist
- Authorized scope, tenant isolation, secrets and logging tests.
- Complete official and reviewed subclause mapping for any sold CTDISR compliance claims.
- Tested collector on actual supported firmware with read-only proofs.
- Every FAIL linked to immutable evidence with source/version.
- No fake regulator connector, expired document marked valid, or status inflation.
- Audit evidence exports redacted and protected.
- Backup/restore test and incident runbook.
- Reviewed licensing and country-specific data processing requirements.

**Start with WP-REG regulatory document validation and WP-CORE security architecture. Do not start feature proliferation before the source/legal integrity foundation is established.**
