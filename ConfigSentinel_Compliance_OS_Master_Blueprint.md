# CONFIGSENTINEL COMPLIANCE OS

## Commercial Master Blueprint — PTA CTDISR 2025 + Network Assurance

**Edition:** 1.0 | **Research cutoff:** 19 October 2026 | **Document status:** Product architecture + regulatory validation plan | **Audience:** Founder, Codex agents, engineers, CISO, compliance lead, ISP customers, external auditors.

**Primary objective:** One commercial-grade platform that gives a Pakistani telecom licensee a managed path for every applicable CTDISR 2025 obligation: mapping, implementation plan, technical validation, nontechnical verification, immutable evidence, owner accountability, remediation, independent audit collaboration and regulatory readiness. It cannot make a licensee compliant merely through installation; controls must actually be implemented and a qualified auditor/legal team must validate interpretation.

**Product slogan:** From live network evidence to regulator-ready assurance.

**Scope:** Unlimited development horizon driven by quality gates—not a 21-day MVP. End-state architecture described; explicit delivery waves, prerequisites and acceptance criteria below.

**Regulatory integrity note:** The 31 Dec 2025 gazette CTDISR is described by a September 2026 secondary guide as S.R.O. 2504(I)/2025, 84 numbered regulations across 14 chapters. A publicly reproduced 89-page Gazette OCR exposes the early regulations but was not obtainable here as a complete certified authoritative file. Items 1–27 below are **working paraphrases checked against accessible reproduction/OCR (not a certified source)**; 28–84 are deliberately **UNVERIFIED LEGAL TEXT** until PTA/MoLaw gazette copy is acquired and signed off. This document DOES NOT INVENT those 57 clauses. The engine is designed to cover each exact clause/subclause once legal text is onboarded; source verification is a mandatory release gate. Source links in §29.

**No regulatory guarantee:** The system produces auditable evidence and guidance; it is not the regulator, is not a PTA-certified audit firm, and never automatically certifies compliance or sends incidents to PTA without authorized workflow.

## 1. Executive product specification

### 1.1 What the customer buys

- **Unified compliance workspace:** authoritative regulation pack, applicability, policies, departments, risk ownership, exceptions, evidence, auditor workflows and corrective actions.
- **Continuous technical assurance:** read-only collection and validated configuration assessment across Cisco IOS/IOS XE/NX-OS, Huawei VRP and MikroTik RouterOS; future firewalls, Linux, Windows, cloud and OLT modules.
- **Evidence automation:** every technical finding links to source command, device, software release, parser/rule version, immutable snapshot, date, scope, reviewer and regulatory control.
- **People/process coverage:** policies, risk assessments, supplier due diligence, incident reporting, BCP/DR, physical inspections, training and third-party audit artifacts with owner/approver roles.
- **Auditor room:** independent review with evidence request, sampling, comments, retesting, export and sign-off; no vendor self-certification.

### 1.2 North-star customer journey

Company onboard → confirm license/scope → import assets/data/processes/vendors → ingest CTDISR regulation pack → assign every relevant obligation → collect automated/manual evidence → test control design and operating effectiveness → record gaps and risks → execute customer-owned corrective actions → independent auditor review → export clause-by-clause dossier → ongoing reassessment.

### 1.3 Non-goals

Not an anti-DDoS scrubbing network, full SIEM, full EDR, NAC enforcement appliance, forensic imaging suite, vulnerability exploit framework, legal advisory service, guaranteed zero-risk network simulator, or automatic PTA-certified audit. Integrate with qualified services and tools for these outcomes.

## 2. Regulatory source of truth and update management

1. Maintain `RegulatorySource` (government URL, gazette number, publication, commencement, checksum, document copy if licensed, authority verification, reviewer and review date).
2. Store **each numbered regulation + every subregulation + each (a)/(i) obligation** separately. Do not collapse 84 headings into 84 pass/fail booleans; one regulation may have dozens of independently testable obligations.
3. `Obligation` fields: source citation to Gazette page/section, paraphrase, legal quote under permitted rights, version, scope triggers, requirement type, evidence specification, retention, recurrence, deadline, ownership, waiver conditions, automation feasibility, official direction references.
4. Mapping is versioned: `regulation_version -> obligation -> control -> test -> evidence -> assessment -> finding -> treatment -> auditor decision` with bidirectional links.
5. Two-person legal/compliance approval of each exact clause mapping, plus provenance and diff against earlier versions.
6. A clause with unverified source must show `SOURCE_PENDING`; it can have a workflow placeholder but can never receive `COMPLIANT` or claim legal coverage.
7. Separate **legal clause fulfillment**, **control-design assessment**, **operating effectiveness** and **evidence sufficiency**. Never combine them invisibly.
8. PTA circulars, directives, FAQs, nTCERT/nTSOC schemas and audit instructions become append-only `RegulatoryDirective` objects; don't silently overwrite a regulation.
9. Provide rollback and customer notification when rules change. Preserve old assessments for historic audit periods.
10. Record human sign-off and explicit applicability rationale for every clause and any N/A assessment.

**Important:** Independent audits, government filings, time limits, residency and external security services must be checked against the final authoritative text plus later directives before product claims or defaults are released. The internet sources used for research are not legal certification.

## 3. Clause traceability register — 84 slots, honest legal status

**Coverage definition:** A slot exists for every numbered regulation 1–84. `SOURCE_PENDING` is NOT `implemented`, `mapped` or `compliant`. The system will also create distinct subclause items after certified-source import. **Regulations 28–84 below are not given invented names or legal requirements**; map them during mandatory source-transcription work package WP-REG.



- **R01 — Short title/commencement; Regulation identity; gazette date; applicability control**  |  *Tool:* Regulatory Register  |  *Evidence:* Customer license and official gazette  |  *Status:* OCR reviewed, **primary confirmation required**
- **R02 — Definitions; Controlled glossary: CII, critical information, incident, evidence etc.**  |  *Tool:* Regulatory Register  |  *Evidence:* Glossary/definitions approval  |  *Status:* OCR reviewed, **primary confirmation required**
- **R03 — Scope and applicability; Licensee and CII scoping**  |  *Tool:* Scope Wizard  |  *Evidence:* License type, operating entities, critical services  |  *Status:* OCR reviewed, **primary confirmation required**
- **R04 — InfoSec roles and responsibilities; RACI, defined CEO/CISO/IT/audit responsibilities**  |  *Tool:* Governance  |  *Evidence:* Org chart, role letters, job descriptions  |  *Status:* OCR reviewed, **primary confirmation required**
- **R05 — Information Security Steering Committee; ISSC membership, agendas, approval and decisions**  |  *Tool:* Governance  |  *Evidence:* ISSC charter, member list, meeting minutes  |  *Status:* OCR reviewed, **primary confirmation required**
- **R06 — Information Security Policy; Approved, communicated and periodically reviewed policy**  |  *Tool:* Policy Center  |  *Evidence:* Signed policy and staff acknowledgement  |  *Status:* OCR reviewed, **primary confirmation required**
- **R07 — Technical and Operational Policies; Documented SOPs and security policies with owner/review**  |  *Tool:* Policy Center  |  *Evidence:* Technical standards, SOPs, approval history  |  *Status:* OCR reviewed, **primary confirmation required**
- **R08 — Security awareness and training; Role-based training, awareness and attendance evidence**  |  *Tool:* Training  |  *Evidence:* Program, attendance, surveys, content  |  *Status:* OCR reviewed, **primary confirmation required**
- **R09 — Confidentiality agreements; Employee and third-party NDAs + scheduled review**  |  *Tool:* Vendor + HR  |  *Evidence:* Signed NDAs, review records  |  *Status:* OCR reviewed, **primary confirmation required**
- **R10 — Contacts with authorities/stakeholders; Emergency contacts and relevant security groups**  |  *Tool:* Governance  |  *Evidence:* Verified contact directory  |  *Status:* OCR reviewed, **primary confirmation required**
- **R11 — Asset management; Comprehensive asset register, CII, owners, lifecycle, risks**  |  *Tool:* Asset/CII  |  *Evidence:* Inventory, reconciliation reports  |  *Status:* OCR reviewed, **primary confirmation required**
- **R12 — Asset ownership/custodianship; Owner, custodian, classification and access authority**  |  *Tool:* Asset/CII  |  *Evidence:* Ownership acknowledgements  |  *Status:* OCR reviewed, **primary confirmation required**
- **R13 — Asset classification; Critical/high/medium/low and approval**  |  *Tool:* Data/Asset Classification  |  *Evidence:* Classification matrix and exceptions  |  *Status:* OCR reviewed, **primary confirmation required**
- **R14 — Asset labeling and handling; Handling, transmission, storage, decommissioning**  |  *Tool:* Data/Asset Classification  |  *Evidence:* Labels, workflows, training  |  *Status:* OCR reviewed, **primary confirmation required**
- **R15 — Critical information/asset disposal; Sanitization methods, approvals and chain of custody**  |  *Tool:* Asset Lifecycle  |  *Evidence:* Disposal certificates and signoffs  |  *Status:* OCR reviewed, **primary confirmation required**
- **R16 — Acceptable use; AUP, acknowledgement and enforcement records**  |  *Tool:* Policy + HR  |  *Evidence:* Signed AUP and exceptions  |  *Status:* OCR reviewed, **primary confirmation required**
- **R17 — Risk methodology and planning; Approved assessment methodology, risk matrix, periodic reviews**  |  *Tool:* Risk  |  *Evidence:* Methodology, ISSC approval  |  *Status:* OCR reviewed, **primary confirmation required**
- **R18 — Risk assessment; Threat/vulnerability/impact analysis, residual risk**  |  *Tool:* Risk  |  *Evidence:* Reviewed assessment, register  |  *Status:* OCR reviewed, **primary confirmation required**
- **R19 — Risk treatment and mitigation; Treatment plan, mitigation/transfer/avoidance decisions**  |  *Tool:* Risk + CAPA  |  *Evidence:* Treatment records and retests  |  *Status:* OCR reviewed, **primary confirmation required**
- **R20 — Risk acceptance; Explicit acceptance with appropriate approval; high/critical ISSC**  |  *Tool:* Risk  |  *Evidence:* ISSC approval and expiry  |  *Status:* OCR reviewed, **primary confirmation required**
- **R21 — External party risk and service management; Due diligence, contracts, NDAs, ongoing review**  |  *Tool:* Vendor  |  *Evidence:* Vendor inventory, assessment, agreements  |  *Status:* OCR reviewed, **primary confirmation required**
- **R22 — Incident management planning; IRT policy, roles, response plan and drills**  |  *Tool:* Incident  |  *Evidence:* Plans, IRT roster, exercises  |  *Status:* OCR reviewed, **primary confirmation required**
- **R23 — Incident reporting and escalation; Severity classification, timelines, preliminary and follow-up**  |  *Tool:* Incident + PTA Reporting  |  *Evidence:* Detection timestamp, receipts, reports  |  *Status:* OCR reviewed, **primary confirmation required**
- **R24 — Evidence gathering/preservation; Chain-of-custody and required retention**  |  *Tool:* Forensic Evidence  |  *Evidence:* Custody records, secure object copies  |  *Status:* OCR reviewed, **primary confirmation required**
- **R25 — Incident and threat intelligence repository; Central incident records, threat intelligence and reporting**  |  *Tool:* Incident + Threat Intel  |  *Evidence:* Incident register, intelligence feeds  |  *Status:* OCR reviewed, **primary confirmation required**
- **R26 — Access control policy and procedures; Least privilege/zero trust policy and approval processes**  |  *Tool:* IAM + Policies  |  *Evidence:* Approved access policy, access changes  |  *Status:* OCR reviewed, **primary confirmation required**
- **R27 — Logical/network/OS access controls; Unique identities, privileged review, MFA where applicable, NAC, segmentation**  |  *Tool:* IAM + Config Assessment  |  *Evidence:* Identity review, ACLs, AAA, NAC evidence  |  *Status:* OCR reviewed, **primary confirmation required**
- **R28 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R29 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R30 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R31 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R32 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R33 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R34 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R35 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R36 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R37 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R38 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R39 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R40 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R41 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R42 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R43 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R44 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R45 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R46 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R47 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R48 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R49 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R50 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R51 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R52 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R53 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R54 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R55 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R56 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R57 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R58 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R59 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R60 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R61 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R62 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R63 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R64 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R65 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R66 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R67 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R68 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R69 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R70 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R71 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R72 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R73 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R74 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R75 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R76 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R77 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R78 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R79 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R80 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R81 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R82 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R83 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED
- **R84 — SOURCE_PENDING — no invented clause text**  |  *Tool:* Regulatory Register → assigned after legal review  |  *Evidence:* Await subclause-wise required evidence definition  |  *Status:* UNVERIFIED



### 3.1 How to actually achieve all-clause coverage

- Import complete signed-off regulation pack and split numbered headings to nested subclauses with exact coordinates/page anchors.
- For every obligation, regulatory specialist selects applicable tenant types and documents scope decision; engineer maps at least one implementable control and evidence owner.
- `CoverageGate` must fail if any applicable obligation has zero tests, zero approved manual procedure, unverified source, missing control owner or expired required evidence.
- A regulation's status is rolled up only when ALL applicable subclauses are individually assessed; unknowns are prominently shown, not excluded from denominator.
- Auditor review and customer management attestation are recorded separately. Regulatory acceptance is never inferred.
- The product gives every clause an owner, mechanism, evidence, next action and accountability—even when fulfillment requires on-site action, human review or third-party audit.

## 4. Functional domains and primary implementation method

The following 13-domain grouping (7/6/5/4/6/13/5/8/6/2/3/7/12 = 84) is **a secondary commercial mapping used for product scoping, not a verified gazette chapter map or exact regulation index**.



- **Governance** — Count (third-party): 7; Main capability: ISSC, policies, RACI and signoffs; Evidence mode: human + document; External dependency: legal/ISSC
- **Asset management** — Count (third-party): 6; Main capability: Discovery, CII, classification and custody; Evidence mode: hybrid; External dependency: CMDB/data owners
- **Risk management** — Count (third-party): 5; Main capability: Risk matrices and approvals; Evidence mode: hybrid; External dependency: management
- **Incident management** — Count (third-party): 4; Main capability: IRT, response timeline and reporting; Evidence mode: hybrid; External dependency: SOC/nTCERT
- **Access control** — Count (third-party): 6; Main capability: AAA, IAM, privileged reviews, NAC; Evidence mode: hybrid; External dependency: IdP/PAM/NAC
- **Operations and communications** — Count (third-party): 13; Main capability: Config checks, logging, crypto, vulnerabilities; Evidence mode: automated + review; External dependency: collectors/SIEM
- **BCP/DR** — Count (third-party): 5; Main capability: BIA, backups, recovery drills; Evidence mode: hybrid; External dependency: backup vendors
- **Systems acquisition/development** — Count (third-party): 8; Main capability: Secure SDLC, suppliers and change; Evidence mode: documents + integrations; External dependency: SCM/CI/CD
- **Physical/environmental** — Count (third-party): 6; Main capability: Sites, UPS, fire, badge/CCTV inspections; Evidence mode: on-site + integration; External dependency: facilities
- **Cloud security** — Count (third-party): 2; Main capability: Posture, data residency and CSP contracts; Evidence mode: API + document; External dependency: cloud accounts
- **HR security** — Count (third-party): 3; Main capability: onboarding/offboarding, NDA, training; Evidence mode: HR + evidence; External dependency: HRIS
- **Assurance/compliance/audit** — Count (third-party): 7; Main capability: Evidence, VAPT and auditor room; Evidence mode: hybrid; External dependency: authorized auditor
- **Regulatory oversight** — Count (third-party): 12; Main capability: Filing calendar, requests, legal directives; Evidence mode: document/human; External dependency: PTA official channels



**Foundational distinction:** domain count from a competitor's interpretive guide is not sufficient for clause-level legal confidence. WP-REG validates exact numbering, thresholds, deadlines, scope and exceptions.

## 5. Tool-by-tool detailed functional design (M01–M25)

**Standard module state machine:** `NOT_CONFIGURED → INTAKE → EVIDENCE_COLLECTING → REVIEW_REQUIRED → FINDING/PASS/UNKNOWN → TREATMENT → RETEST → VERIFIED/EXCEPTION`. Every workflow supports owner, reviewer, timestamps, attachment, tenant, affected obligation, history and export.

### M01 — Regulatory Framework & Clause Compiler

**Buyer-side owner:** Legal/compliance manager.

**What the customer provides:** Signed official Gazette/PDF, PTA circulars, applicability policy.

**Processing, screens and business logic:** Versioned subclause graph, requirement extraction with supervised review, mapping approvals, content diff and re-assignment on update. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** No automated legal interpretation acceptance.

**Evidence produced:** Approved clause pack, source hash, pagination, reviewer signatures.

**Definition of done:** All 84 verified headings and every subclause mapped; 0 unreviewed items on release. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

### M02 — Licensee Onboarding & Applicability

**Buyer-side owner:** Company admin / legal.

**What the customer provides:** License category and numbers (protected), operator structure, scope declaration, service footprint.

**Processing, screens and business logic:** Scope wizard; tenants, business units, locations, telecom services, applicable CII and exclusions with reasons. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** Legal review for applicability and license terms.

**Evidence produced:** Signed scope statement, tenant setup log.

**Definition of done:** No regulation can be N/A without reviewer and rationale. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

### M03 — Organization, Roles, ISSC & Governance

**Buyer-side owner:** CEO secretariat / CISO.

**What the customer provides:** Org chart, roster, reporting lines, meeting agenda, policy approvals.

**Processing, screens and business logic:** RACI matrix, quorum, meeting invites, decisions, 30-day corrective action reminders where applicable. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** Management decisions must be real.

**Evidence produced:** Signed minutes, role assignment, approval logs.

**Definition of done:** Every approval linked to real authorized role. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

### M04 — Policy & Procedure Studio

**Buyer-side owner:** CISO/policy owners.

**What the customer provides:** Existing policies, desired baselines, version owners, audience.

**Processing, screens and business logic:** Templates, review workflow, policy comparison, change history, acknowledgments, annual review calendar. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** Approval and legal fit not automatic.

**Evidence produced:** Approved PDFs, publication proofs, training acknowledgements.

**Definition of done:** No generated draft labeled approved without authorized signoff. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

### M05 — Asset, Service and CII Registry

**Buyer-side owner:** Network admin / asset owner.

**What the customer provides:** IP ranges, SNMP/SSH/API credentials, sites, ERP/CMDB exports, customer services.

**Processing, screens and business logic:** Discovery and reconciliation, relationship graph, CII tagging, business function, lifecycle and end-of-support. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** Owner and criticality manual signoff.

**Evidence produced:** Inventory version, discrepancies, asset owners, evidence snapshots.

**Definition of done:** Assets require owner, custodian, service, classification and review date. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

### M06 — Data Discovery, Classification, Handling & Residency

**Buyer-side owner:** Data owner / privacy.

**What the customer provides:** Data categories, storage inventories, subscriber/CDR flows, countries and processors.

**Processing, screens and business logic:** Data-flow catalog, classification workflows, processing location registry, approved transfers. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** No assumption all data must reside locally; legal scope check.

**Evidence produced:** Data inventory, contracts, locations, exception approvals.

**Definition of done:** Unknown data locations fail readiness; no claim based solely on IP geolocation. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

### M07 — Network Configuration & Engineering Assurance

**Buyer-side owner:** NOC/network security.

**What the customer provides:** Device inventory, read-only credentials, configs, approved baselines and peer metadata.

**Processing, screens and business logic:** Cisco/Huawei/MikroTik parser, evidence-backed rule engine, secure mgmt, routing, L2, QoS, HA, capacity, firmware checks. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** No production config writes in assessment scope.

**Evidence produced:** Device snapshot, raw command hashes, normalized facts, rule findings.

**Definition of done:** Finding MUST include rule+source+device+version+evidence+next step. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

### M08 — Access & Privileged Identity Assurance

**Buyer-side owner:** IAM/PAM administrator.

**What the customer provides:** AAA/IdP/PAM/NAC exports, user lists, job changes, reviews.

**Processing, screens and business logic:** Shared user detection, privilege review, MFA evidence, service account inventory and access revocations. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** Cannot prove MFA from router config alone.

**Evidence produced:** Access approval, IdP policy, activity logs, recertification.

**Definition of done:** Expired privileges need accountable action and proof of revocation. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

### M09 — Vulnerability, Patch & Secure Baseline Management

**Buyer-side owner:** SecOps and patch owner.

**What the customer provides:** Authorized scanner results, vendor advisories, software inventory, patch windows.

**Processing, screens and business logic:** Normalize CVEs, exploitability context, software EOS mapping, exceptions, patch campaign tracking. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** Do not run invasive scans without permit.

**Evidence produced:** Scanner signed exports, patch tickets, retest.

**Definition of done:** Distinguish vulnerability from missing scanner coverage. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

### M10 — Security Monitoring, Log & SOC Connector

**Buyer-side owner:** SOC manager.

**What the customer provides:** SIEM endpoints, log sources, SIEM rules, retention settings, nTSOC requirements.

**Processing, screens and business logic:** SIEM health/coverage, log heartbeat, correlation, event routing, evidence dashboards. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** No fake nTSOC integration; official API/access needed.

**Evidence produced:** Source logs, acknowledgments, link health.

**Definition of done:** Connectors validated; missing heartbeat becomes finding. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

### M11 — Incident Response + Regulatory Reporting

**Buyer-side owner:** IRT lead / CISO.

**What the customer provides:** IR policy, emergency contacts, incident details, impact, detection times.

**Processing, screens and business logic:** Case management, four-tier severity, clocks, 24h preliminary and 5-working-day follow-up where verified, review, drafts, dispatch receipt tracking. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** Notification requires authorized human and official approved channel.

**Evidence produced:** Timeline, emails/receipts, RCA, containment and recovery.

**Definition of done:** Deadlines based on verified rule timezone/holiday calendar, not guessed. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

### M12 — Forensic Evidence, Chain-of-Custody & Retention

**Buyer-side owner:** IR forensic officer / legal.

**What the customer provides:** Logs, hashes, disk image references, custody actors, retention policies.

**Processing, screens and business logic:** WORM-like store, hash verification, legal hold, transfer registry, integrity checks. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** Full forensic disk collection is integration/service, not magic.

**Evidence produced:** Custody events, cryptographic hashes, retention certificates.

**Definition of done:** Incident evidence >=3y per accessible reg24, subject to current direction. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

### M13 — Threat Intelligence & CERT Collaboration

**Buyer-side owner:** SOC/threat analyst.

**What the customer provides:** Feeds, TLP tags, alerts, nTCERT advisory formats.

**Processing, screens and business logic:** IOC ingestion, dedupe, relevance to assets, triage, shared intelligence repository. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** External sharing requires authorization and legal check.

**Evidence produced:** Feed provenance, analyst notes, submission receipts.

**Definition of done:** Feeds never auto-action firewalls without approval. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

### M14 — Enterprise Risk & Treatment Register

**Buyer-side owner:** Risk owner / ISSC.

**What the customer provides:** Risk appetite, matrix, BIA, asset criticalities, mitigating controls.

**Processing, screens and business logic:** Risk lifecycle, inherent/residual exposure, linked findings, owners, deadlines, ISSC approvals on high/critical. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** Risk acceptance never inferred from silence.

**Evidence produced:** Risk assessments, decisions, evidence and history.

**Definition of done:** High/critical acceptance fails without authorized committee approval. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

### M15 — Third-Party, Vendor & Supply Chain Assurance

**Buyer-side owner:** Procurement / legal / vendor owner.

**What the customer provides:** Vendor register, contracts, NDA, access, supplier reports, external SLA.

**Processing, screens and business logic:** Due diligence, questionnaire, renewals, vendor connections and third-party deviations. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** Vendor attestation independently validated.

**Evidence produced:** NDAs, contracts, service reviews, audits.

**Definition of done:** No external access without appropriate approval artifacts. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

### M16 — Backup, BIA, Business Continuity & DR

**Buyer-side owner:** IT operations / business continuity lead.

**What the customer provides:** Service inventory, backups, RPO/RTO, alternate sites, test schedule.

**Processing, screens and business logic:** Backup API evidence, BIA workflows, restoration drill tracking and gaps. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** Backup existence does not prove restorability.

**Evidence produced:** Signed BIA, restore logs, outcomes, owners.

**Definition of done:** Success requires actual restore test where applicable. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

### M17 — Physical, Environmental & Site Inspection

**Buyer-side owner:** Facilities / site owner.

**What the customer provides:** Sites, CCTV coverage, access control, UPS, fire systems, visitors.

**Processing, screens and business logic:** Inspection checklist, photo evidence, remediation tickets, IoT/BMS connectors. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** On-site attestations required for actual operation.

**Evidence produced:** Inspection and test certificates, photo hashes.

**Definition of done:** Inspection cannot pass based only on a completed form. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

### M18 — HR Lifecycle, NDA & Awareness

**Buyer-side owner:** HR/security training owner.

**What the customer provides:** Employee roster, HRIS events, job types, NDAs, training packs.

**Processing, screens and business logic:** Joiner/mover/leaver checklists, NDA attestations, training campaigns and survey results. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** Training effectiveness not inferred from attendance alone.

**Evidence produced:** Signed NDA, completion and periodic survey reports.

**Definition of done:** Expired access triggers escalation and evidence request. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

### M19 — Secure SDLC, Change, Procurement & Project Controls

**Buyer-side owner:** Engineering/DevSecOps lead.

**What the customer provides:** Jira/GitHub change issues, review reports, release plans, code scans.

**Processing, screens and business logic:** Change approval gates, SAST/DAST integrations, config diff, CAB, rollback, procurement risk. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** Security testing by customer/tool, review required.

**Evidence produced:** Change ticket, approvals, test logs, rollback result.

**Definition of done:** No privileged production change without authorization. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

### M20 — Cloud & Data Center Posture

**Buyer-side owner:** Cloud/security team.

**What the customer provides:** Read-only AWS/Azure/GCP identities and CSP contracts, hosted sites.

**Processing, screens and business logic:** Encryption, IAM, logging, region usage, exposed services, shared responsibility. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** Location and residency require legal + architecture validation.

**Evidence produced:** Cloud findings, contract and architecture records.

**Definition of done:** Cloud objects uncovered or unpermitted access show unknown. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

### M21 — VAPT, Independent Audit & Findings Management

**Buyer-side owner:** PTA-approved auditor / internal audit.

**What the customer provides:** Auditor identity, scope, VAPT authorization, third-party assessment reports.

**Processing, screens and business logic:** Auditor portal, evidence request, sample selection, nonconformity, disputes and retest workflow. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** Platform operator cannot present self-check as independent audit.

**Evidence produced:** Signed opinion/report, audit trail, evidence pack.

**Definition of done:** External auditor account isolated from maker roles. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

### M22 — Corrective Action / CAPA Management

**Buyer-side owner:** Department owners / audit committee.

**What the customer provides:** Findings, target dates, treatment types, change plans.

**Processing, screens and business logic:** Tickets, SLA, escalation, re-test and closure acceptance. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** Finding remains open till re-test proves resolution.

**Evidence produced:** CAPA register, change proofs, residual risk approvals.

**Definition of done:** Closure requires fresh evidence and reviewer. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

### M23 — PTA Regulatory Desk

**Buyer-side owner:** Regulatory affairs.

**What the customer provides:** Official circulars, requests for information, audit notices, contacts.

**Processing, screens and business logic:** Submission calendar, review/approve/submit tracking, secure response package. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** No unsolicited regulator submissions, no invented PTA API.

**Evidence produced:** Submission approvals, receipt IDs, delivery evidence.

**Definition of done:** Dispatch marked completed only on official receipt. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

### M24 — Evidence Vault, Audit Pack & Executive Reporting

**Buyer-side owner:** CISO/internal auditor.

**What the customer provides:** Artifacts from all tools, reviewer decisions, company branding.

**Processing, screens and business logic:** Hash-addressed evidence, chain linkage, redaction, clause dossiers, time-bound auditor room. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** No hiding failed/unknown clauses in headline score.

**Evidence produced:** PDF/ZIP/JSON exports with manifests and hashes.

**Definition of done:** Every claimed satisfied control has reviewed evidence and period. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

### M25 — Customer / Partner Commercial Administration

**Buyer-side owner:** Buyer finance / partner MSP.

**What the customer provides:** Contract, subscription, limits, tenant size, reseller affiliation.

**Processing, screens and business logic:** Plans, device/capacity metering, invoice, audit events, renewal and license enforcement. Expose dashboard, list/detail, assignment, history, evidence viewer, reminders, bulk import and role-aware API for this module; record any incomplete scope as a customer-action request.

**Automation boundary:** No sharing data across customers/MSPs.

**Evidence produced:** Contracts, invoices, usage reports.

**Definition of done:** Tenant isolation enforced at DB/object/API layers. Also: permissions matrix tested, multi-tenant isolation tested, documentation and negative-path tests present, no missing-source state disguised as pass.

## 6. What customers must provide: onboarding questionnaire + mandatory upload register



- **Legal/tenant** — Customer-supplied information: License category, registered entity, regulatory contact, scope; Format: form + approved docs; Who supplies: legal; Effect if missing: Scope blocked
- **Governance** — Customer-supplied information: CEO/CISO/CTO, ISSC charter, RACI, policies; Format: documents; Who supplies: governance; Effect if missing: Manual controls unknown
- **Inventory** — Customer-supplied information: PoPs/sites, critical services, routers, switches, firewalls, OLTs; Format: CSV/CMDB/API; Who supplies: network/asset; Effect if missing: Coverage gaps
- **Device access** — Customer-supplied information: read-only accounts, IP ranges, VPN/on-prem agent; Format: vault reference; Who supplies: network; Effect if missing: Offline upload only
- **Cloud/identity** — Customer-supplied information: CSP accounts, IdP, PAM, EDR, NAC connectors; Format: delegated read-only; Who supplies: security; Effect if missing: Cloud/IAM unknown
- **Data** — Customer-supplied information: location of subscriber/CDR information and processors; Format: flow inventory; Who supplies: privacy; Effect if missing: Residency unable to assess
- **Processes** — Customer-supplied information: change tickets, risk records, vendor contracts, HR training; Format: uploads + integrations; Who supplies: business units; Effect if missing: Manual evidence pending
- **Resilience** — Customer-supplied information: BIA, RTO/RPO, backup job inventories, restore results; Format: upload/API; Who supplies: operations; Effect if missing: DR effectiveness unknown
- **Incidents** — Customer-supplied information: IRT, previous cases, reporting contacts, severity rules; Format: secure import; Who supplies: CISO/IRT; Effect if missing: Reporting setup blocked
- **Audit** — Customer-supplied information: prior audit findings, external auditor, defined period; Format: archive + authorization; Who supplies: audit; Effect if missing: Historical trace missing



### 6.1 Secure customer onboarding checklist

1. Written authorization to scan assets, confirmed management IP scope, maintenance windows, per-device rate limits.
2. Establish least-privileged credential/agent, verify reachability and capture `read_only` capability attestation.
3. Consent/custody for config secrets, subscriber data, logs and audit attachments; default minimum collection.
4. Establish precise tenant/timezone, official working-day holiday calendar and verified reporting contact channels.
5. Upload/source classify legal, HR, contracts and security documents; encrypted, tenant-segregated and retention tagged.
6. Assign control owners and train them on evidence requests; require management acceptance of scope.
7. Run baseline import and report completeness BEFORE producing any compliance rating.

### 6.2 User interface home screen after onboarding

Tabs: `Readiness`, `Framework & Clauses`, `My Actions`, `Network`, `CII Inventory`, `Risk`, `Policies`, `Identity`, `Incident Desk`, `Monitoring`, `Vendors`, `BCP & DR`, `Physical`, `Training`, `Audit Room`, `Regulatory Desk`, `Settings`. Widgets: regulatory source integrity status, applicable obligations counts, insufficient-evidence counts, stale evidence, unresolved high risks, incident clocks, audit deadlines, per-device scan freshness, open CAPAs.

## 7. End-to-end user journeys (specific acceptance examples)

### Journey A — ISP CTO launches readiness assessment
1. Admin creates tenant and legal scope; compliance user confirms license, sites and services.
2. Scope Wizard pre-generates 84 regulation slots; source status shown; legal reviewer imports/certifies gazette clauses and marks applicability.
3. Asset importer reads network inventory; network engineer validates CII scope and ownership.
4. Collector completes read-only scans; creates pass/fail/unknown per rule, never legal pass.
5. Compliance user provides governance/policy/training/contract evidence.
6. Control owners review each obligation; risk owner approves remediation; independent auditor accepts or challenges evidence.
7. Executive sees compliance-readiness matrix with explicit denominator, unknowns, unverified sources and independent auditor status.

### Journey B — Cisco NX-OS Telnet/AAA gap
1. Device version and capability identified; command results captured encrypted.
2. Rule checks SSH/VTY, management VRF, SNMP and AAA. Unavailable required state ⇒ UNKNOWN.
3. Finding links to affected subclause(s) after legal pack approval; severity based on CII criticality and reachability.
4. Suggested vendor-specific mitigation with operating impact, validation and approved change ticket; no unreviewed auto push.
5. Engineer implements externally; collector rescans; reviewer closes if verified; evidence bundle preserves before/after.

### Journey C — critical incident regulatory timer
1. SIEM webhook or human detects suspected incident; detection time and source are immutable.
2. Authorized IRT validates classification and applicability; two clocks launched only after required facts known.
3. Product drafts regulator preliminary notification with evidence and missing fields, queues management/legal approval.
4. Authorized user submits to confirmed official channel, uploads receipt; follow-up report due on verified working-day schedule.
5. Case carries preserved evidence hashes, custody, forensic links, service impact and postmortem/CAPA.

### Journey D — independent yearly audit
1. Organization creates audit engagement, scope and approved auditor read-only access.
2. Auditor selects sample assets and clauses, requests artifacts; tenant responds via controlled audit room.
3. Auditor marks evidence as accepted, rejected or further testing required; independent finding has its own status.
4. Final export bundles per-obligation evidence manifests, dates, sources, risk approvals, auditor decision and open limitations.

### Journey E — vendor access expired
1. Vendor contractual end date passes; access mapping identifies VPN/firewall rules and identity accounts potentially associated.
2. Risk owner verifies whether still needed; product opens recertification and cautious change request.
3. No direct ACL or firewall removal before authorization. After change, re-collect and attach logs confirming restriction.

### Journey F — physical audit
1. Facilities manager performs on-site inspection with location, photos, measurements, signatures and timestamp.
2. Reviewer validates evidence quality; failed UPS/fire-alarm drill becomes CAPA with retest.
3. Product makes no claim it personally measured sensors unless signed BMS integrations supplied readings.

## 8. Network collector architecture (deep technical requirements)

### 8.1 Control-plane to data-plane separation

Django / DRF control plane and PostgreSQL metadata; Celery workers with Redis or RabbitMQ broker; per-customer on-prem **outbound-only collector agent** for sensitive networks; SSH/API/NX-API/NETCONF where supported, offline config upload fallback; encrypted object storage for raw outputs; normalized typed facts and a rule evaluator. Collector receives signed job payload, scoped IP allowlist, command allowlist, lock and time budget.

**State graph:** QUEUED → PREFLIGHT → CAPABILITY_PROBE → COLLECTING → PARSING → ASSESSING → COMPLETE/PARTIAL/FAILED; per-command history: planned/succeeded/unsupported/timeout/parse_error/not_applicable. Use idempotency keys and checkpoint resume; never retry a completed expensive read just because another step failed.

### 8.2 Collection constraints
- No default Telnet. Legacy devices may require explicit exception, transport risk acknowledgement and isolation; never silently downgrade from SSH.
- On Cisco NX-OS: `show version`, `show running-config`, `show interface status`, `show interface counters errors`, `show port-channel summary`, `show lacp neighbor`, `show spanning-tree summary`, `show lldp neighbors detail`, `show ip route`, platform-verified BGP/OSPF/resource commands.
- On IOS/IOS XE: `show version`, `show running-config`, `show interfaces`, `show ip interface brief`, feature-aware STP/VLAN/OSPF/BGP/CPU/AAA operational commands.
- On Huawei VRP: `display version`, `display current-configuration`, `display interface brief`, `display lldp neighbor brief`, applicable `display stp`, `display bgp peer`, `display ospf peer` and `display eth-trunk`.
- On MikroTik v7: read-only API/REST/SSH under scoped permissions; `/system/resource`, `/interface`, bridge VLAN/filter, `/ip/firewall`, `/routing/bgp`, neighbors and active state; config secrets redacted.
- Every command profile keyed by vendor, family, release and capabilities. A feature absent or inaccessible yields UNKNOWN/N/A rather than a universal failure.
- Rate limit and concurrency by device/site; command paging, prompt handling, output size guard, circuit breaker, cancel and maintenance-window policy.

### 8.3 Parser and normalization contract

Input: bytes + command + vendor/OS/release + collection timestamp + collector version. Output: typed fact set with provenance, parse confidence, unknown fields and validation errors. Use structured APIs preferentially, TextFSM/TTP for stable CLI; no LLM as sole parser. Model: Device, Interface, VLAN, BridgeDomain, LAG, RoutingProcess, BGPNeighbor, OSPFNeighbor, VRF, ACL, AccessPolicy, User, LoggingSource, Service, L2Link, L3Peer, ResourcePool and Snapshot. Preserve vendor semantics: MikroTik bridge VLAN model is not equivalent to Cisco switchport mode; Huawei MA-series GPON is separate plugin.

### 8.4 Rule result contract

`rule_id`, `rule_version`, `device_id`, `asset_scope`, `platform_capabilities`, `evidence_ids`, `finding_status (PASS/FAIL/WARN/UNKNOWN/N/A/ERROR)`, `severity`, `confidence`, `freshness`, `reason`, `remediation_template_id`, `control_mappings`, `data_quality` and `reviewed_by`. Rule execution cannot change device configuration.

### 8.5 Engineering checks to implement

Management: insecure service exposure, AAA/TACACS/RADIUS, unique IDs (where visible), SNMP v1/v2c risks, SNMP ACL, SSH ciphers per platform, NTP, syslog, management-plane ACL/VRF.
Layer 2: VLAN database/trunk mismatches, unintended allowed VLANs, STP root/edge/guard controls, storm control, LACP member inconsistencies, LLDP/CDP context.
Layer 3: BGP session stability/policies/max-prefix, route-map applicability and inheritance, OSPF adjacency/timers/passive interfaces, static route next-hop resolution, failover readiness.
Performance: utilization with sample windows, errors/discards, CPU/memory and platform hardware MAC/VLAN/TCAM limits, QoS queues/ drops and oversubscription signals; do not issue bogus thresholds.
Security: segmentation and external interconnects, ACL reachability where evidence exists, software EOS/CVE correlation, config backup and drift.

**Impact intelligence rule:** Device-local config checks alone cannot promise downstream customer reachability or that a command will cause an outage. Network/service graph and live forwarding/redundancy evidence required; otherwise report as hypothesis.

## 9. Compliance evaluation mathematics and transparency

**Do not show '100% PTA compliant' by counting 84 checkbox toggles.** Track obligation coverage, evidence sufficiency, implementation test, audit assessment and legal verification independently.

- `source_verified`: yes/no per clause/subclause.
- `applicable`: YES/NO/UNDETERMINED; NO requires justification and approval.
- `design`: ADEQUATE/GAP/UNKNOWN/NOT_APPLICABLE.
- `operation`: EFFECTIVE/INEFFECTIVE/NOT_TESTED/NOT_APPLICABLE.
- `evidence`: VALID/STALE/REJECTED/MISSING.
- `review`: SELF_REVIEWED/INTERNAL_AUDITED/EXTERNAL_AUDITED/NOT_REVIEWED.
- `readiness`: READY/GAP/INSUFFICIENT_EVIDENCE/LEGAL_UNVERIFIED/NOT_APPLICABLE.

Legal-unverified clause blocks framework-level readiness. A technical test is NOT legal sufficiency. Domain dashboards show numerator and denominator, exclusions, count stale/unknown/uncertified, period and sampling method. Weighted risk indicators are separated from compliance percent; missing controls cannot improve a score. The detailed aggregation algorithm needs regulatory validation and user configuration.

**Evidence acceptance gates:** source date and policy validity, asset/tenant match, coverage proportion, reviewer independence, currency thresholds, hash integrity, requested period, and link to exact subclause. Documents pending review are not automatically accepted.

## 10. User roles, permissions, segregation of duties



- **Platform superadmin** — Scope / can do: Infrastructure maintenance; Cannot do: Read customer secrets by default / assume tenant role silently
- **Tenant owner** — Scope / can do: Tenant settings, subscriptions; Cannot do: Fake auditor approval
- **Legal/regulatory reviewer** — Scope / can do: Approve legal packs, applicability; Cannot do: Modify immutable source history
- **CISO/compliance lead** — Scope / can do: Policies, assign owners, consolidate review; Cannot do: Mark audit externally certified
- **ISSC chair/member** — Scope / can do: Review/approve risks, decisions, minutes; Cannot do: Approve own technical evidence without recorded recusal if configured
- **NOC/network engineer** — Scope / can do: Device collection, technical findings; Cannot do: Accept high/critical organizational risk
- **SOC/IRT** — Scope / can do: Incidents, log/evidence collections; Cannot do: File to regulator without authorized approver
- **HR/facilities/procurement** — Scope / can do: Own their workflows; Cannot do: View unrelated confidential data
- **Internal audit** — Scope / can do: Independent review and challenge; Cannot do: Erase evidence/change logs
- **External authorized auditor** — Scope / can do: Time-limited scoped read/review; Cannot do: See unrelated tenants or change operational configs
- **MSP partner** — Scope / can do: Manage assigned customer tenants with delegated consent; Cannot do: Cross-tenant secret access



Require MFA on platform, SSO/SAML/OIDC enterprise option, fine-grained tenant/site/asset/sensitivity grants, dual approval for high-risk export, audit of impersonation, least privilege for collectors and reviewer segregation. Log every evidence download and cross-organization access.

## 11. Canonical data model and database invariants

### 11.1 Core entities

Tenant, LegalEntity, License, ScopeDeclaration, Site, BusinessService, DataCategory, DataFlow, Asset, CIIDesignation, AssetRelationship, CredentialReference, CollectorAgent, Device, PlatformCapability, CollectionRun, CommandExecution, RawSnapshot, NormalizedFact, Rule, RuleVersion, TechnicalFinding, RemediationPlan, Recheck, PolicyException.

RegulatorySource, RegulatoryVersion, Regulation, SubClause, Obligation, ApplicabilityDecision, ControlDefinition, ControlImplementation, TestProcedure, TestExecution, EvidenceRequirement, EvidenceArtifact, EvidenceManifest, EvidenceReview, ComplianceAssessment, AuditEngagement, AuditorFinding, CorrectiveAction, Risk, RiskTreatment, RiskApproval, DocumentVersion, PolicyAttestation, Approval, Meeting, Vendor, Contract, AccessEntitlement, AccessReview, Incident, IncidentReport, RegulatorSubmission, SubmissionReceipt, CustodyEvent, RetentionHold, BackupJob, RestoreTest, BIA, DRExercise, TrainingCampaign, PhysicalInspection, Notification, BillingPlan, Invoice, Subscription, AuditEvent.

### 11.2 Key relationships

`RegulatoryVersion 1..n Regulations 1..n SubClauses 1..n Obligations`.
`Obligation n..n ControlDefinition` (many-to-many with reviewer signoff).
`ControlImplementation -> tenant / scope / owner / approval`.
`ControlImplementation 1..n TestExecution 1..n EvidenceArtifact`.
`TechnicalFinding -> Asset -> BusinessService / CII`.
`Obligation -> ComplianceAssessment -> EvidenceReview -> AuditorFinding`.
`Finding -> CorrectiveAction -> Retest -> closure`.
`Incident -> EvidenceArtifact -> CustodyEvent`, report and regulator receipt.

### 11.3 Database rules

All business rows tenant-scoped via enforced tenant key plus object access control; raw attachments tenant-key encrypted. DB unique constraints on source+version+clause path and finding fingerprint. Append-only evidence manifests and audit events, monotonic job state transitions, immutable reviewer comments after finalization (corrections appended), per-tenant retention and legal-hold guards. Foreign keys prevent orphaned evidence. Store raw configs in encrypted object storage, not full text in user-search indexes. Partition large event tables as needed.

## 12. REST API and event contracts



- **`/api/v1/tenants/{id}/scope`** — Method: GET/PUT; Purpose: Signed legal/site/asset scope
- **`/api/v1/frameworks/import`** — Method: POST; Purpose: Submit gazette pack (review queue)
- **`/api/v1/frameworks/{id}/obligations`** — Method: GET; Purpose: Hierarchical source-linked clauses
- **`/api/v1/obligations/{id}/applicability`** — Method: POST; Purpose: Approved scope decision
- **`/api/v1/controls/{id}/assessments`** — Method: POST; Purpose: Start evidence review
- **`/api/v1/evidence`** — Method: POST; Purpose: Upload encrypted evidence
- **`/api/v1/collector-agents`** — Method: POST; Purpose: Register on-prem signed agent
- **`/api/v1/devices/{id}/collections`** — Method: POST; Purpose: Read-only data collection
- **`/api/v1/device-findings`** — Method: GET; Purpose: Technical findings by rule/version
- **`/api/v1/risks`** — Method: GET/POST; Purpose: Risk register and links
- **`/api/v1/incidents`** — Method: GET/POST; Purpose: Cases, timers and evidence
- **`/api/v1/submissions/{id}/approve`** — Method: POST; Purpose: Authorized regulatory signoff
- **`/api/v1/audits/{id}/requests`** — Method: POST; Purpose: Auditor evidence requests
- **`/api/v1/audit-packs`** — Method: POST; Purpose: Versioned export with manifest
- **`/api/v1/capa/{id}/retest`** — Method: POST; Purpose: Test remediation evidence



Idempotency for POST actions, versioned OpenAPI schema, cursor pagination, per-user audit events, signed webhook validation, DLQ for failed integrations, no free-form network command endpoint. Webhook topics: `evidence.accepted`, `control.unknown`, `finding.created`, `incident.detected`, `deadline.approaching`, `remediation.retested`, `audit.requested`, `regulatory.source_changed`.

## 13. Secure deployment, privacy and commercial trust

Three supported deployment patterns: **Pakistan-hosted dedicated SaaS**, **customer-owned on-prem**, and **hybrid control plane with data-resident collector/evidence storage**. Customer data must not be exported to foreign services when prohibited by law, license terms or contract; legal/data-flow assessment is mandatory. For high sensitivity, local inference or no AI inference. Do not assume generic LLM API is allowed to receive running-config/subscriber information.

- TLS 1.2+ where applicable, SSH host key verification, mTLS between agents/control plane, short-lived tokens, rotation, secrets manager/HSM/KMS, encryption at rest, per-tenant KEKs if supported.
- Zero inbound connectivity to customer site by default; signed agent, least-privilege service identity, command allowlists, user-controlled connection and approval.
- No sensitive full configs in application logs, analytics products, bug trackers or public LLM calls; redact at collection and before AI.
- Backup/restore of **the platform itself** tested; PITR, encryption key recovery, documented RTO/RPO.
- Secure SDLC: SAST/DAST/SCA/SBOM, dependency pinning, pen test, architecture threat modeling, release signatures and penetration test by independent authorized party.
- Data controls: segregation, configurable retention, lawful export, audit access, incident response to own SaaS breaches, DPA, DPA subprocessors, security questionnaires, deletion proof after retention/legal hold.
- Commercial SLAs with exclusion language: uptime measured by control plane and collector agent separately; audit/scan timeliness, not guarantee of security or PTA acceptance.
- Platform self-audit: signed release hash, test runs, reviewer approval, changes to regulation pack; strict RBAC, full traceable API logs.

## 14. AI design: recommendation, extraction and limits

Use deterministic parsers and signed rule packs for any machine-generated FAIL. AI is an **assistant**, not primary detection or regulatory authority. Supported tasks: explain evidence, draft a policy/response document, summarize audit deficiencies, propose vendor/version-aware read-only verification and human-approved remediation, classify documents for review, map candidate evidence to subclauses (requires human validation).

**Inference context contract:** bounded approved evidence with cryptographic reference, redacted secrets, supported software release, typed normalized facts, exact approved clause version and data classification. Outputs: finding ID, relevant evidence IDs, explanation, tested facts, unknowns, recommended action, potential side effects, validation and rollback checklist, confidence, `manual_review_required`. Fail closed when missing support, no guessed commands, no auto-execution.

**Prompt injection defense:** treat imported configurations, SIEM data, documents and web pages as untrusted content; block model directives inside evidence; use strict schemas, tool allowlists, independent validator and redaction. No agent has broad admin credentials. Legal clause text authored by a human approver, not automatically rewritten by AI. On-prem models where required.

## 15. Reports and customer-facing deliverables

1. **Regulation dossier:** source/version, exact subclause reference, obligation, applicability, owner, implementation, tests, evidence, gaps, treatment, auditor comments, reviewer approval, validity period.
2. **Executive readiness pack:** CII scope, source-status warning, critical gaps, prioritized budget actions, incident/reporting exposure, capability maturity and evidence staleness.
3. **NOC engineering report:** per-device findings, affected services, vendor/release, raw redacted evidence, proposed fix, testing and rollback checklist.
4. **External auditor pack:** scoped evidence ZIP+PDF+JSON manifest with hashes, custody, export authorization and retention instructions; never include excluded secrets.
5. **Governance pack:** meeting agenda/minutes, pending approvals, high/critical risks, CAPA aging, training and third-party posture.
6. **Regulator response pack:** regulatory request reference, approved disclosure set, traceable delivery checklist, receipt and reporting timeline.

**Every report must carry a scope statement:** what was tested, what was not tested, sample size, evidence time window, source/pack version, acceptance authority and disclaimer that no software guarantees legal compliance.

## 16. Commercial product packaging & pricing hypotheses

**Positioning:** Telecom cybersecurity compliance and network evidence automation, not a generic policy-template app. Competitive wedge: real Cisco/Huawei/MikroTik engineering evidence linked to full governance/audit processes. Qualify any 'PTA-certified' branding with actual certification and audit-firm authorizations; do not imply a government endorsement.



- **Network Assurance** — Buyer: ISP NOC/MSP; Capability: Device inventory, read-only audit, rule findings, evidence; Indicative annual list price (UNVALIDATED): USD 6k–18k
- **Compliance Professional** — Buyer: ISP compliance/CISO; Capability: Framework, policy, evidence, CAPA, risk, auditor pack; Indicative annual list price (UNVALIDATED): USD 18k–45k
- **Telecom Enterprise** — Buyer: Larger operator; Capability: All modules, on-prem, SIEM/IdP, SSO, custom reports; Indicative annual list price (UNVALIDATED): USD 50k–150k+
- **MSP / Audit Partner** — Buyer: Security provider; Capability: Delegated tenant workspaces, reviewer portal, white-label; Indicative annual list price (UNVALIDATED): Custom revenue share



**Packaging caveats:** Pricing is a research hypothesis, not customer willingness-to-pay. Validate contract size and local procurement realities through paid design partners. Avoid device-only pricing for organizational GRC; consider a base tenant license + assets/agents + evidence storage + professional onboarding + advanced connectors.

### Go-to-market motion

1. Target 15 Pakistani ISPs of various license sizes, 5 MSPs and at least 3 qualified third-party audit firms for discovery; do not promise audit status.
2. Paid structured gap-assessment pilot under written permission, clear deliverables and independent acceptance criteria; avoid free indefinite pilots.
3. Sell to CEO/CTO/CISO and compliance function jointly. ROI = manual audit hours reduced, unknown asset exposure identified, evidence retrieval time shortened, remediation faster and fewer unowned risks.
4. Provide migration from spreadsheets, previous audit reports and current network-monitoring apps, without requiring OptiVerse.
5. Channel model: accredited audit firms may license evidence tooling but must preserve auditor independence; independent audit remains separate engagement.
6. Future country packs only after official legal mapping; ISO/IEC 27001/NIST packs require licensing and appropriate crosswalk attribution.

### Deal process and legal terms

Discovery → NDA → scoped technical trial → paid proof-of-value → DPA/security review → on-prem or Pakistan region architecture assessment → contract/SLA → onboarding milestones → quarterly review → annual renewal. Contract must set customer control ownership, compliance disclaimer, data/controller responsibilities, subprocessor listing, indemnity limits, incident notification responsibilities, export/deletion and exit assistance.

## 17. Competitive differentiation and barriers to entry

Generic GRC platform, SIEM, network configuration manager and vulnerability scanner all overlap portions of scope. Do not claim novelty for clause tracking or backup/AAA scans. Durable advantages can be:

- Trusted **technical evidence provenance** across mixed networking vendors and exact software versions;
- Verified regulation-to-subclause-to-control mappings continuously maintained with independent legal review;
- One evidence source reused across network security, ISO, governance and auditor questions without duplicate uploads;
- Strong on-prem/sovereign deployment to satisfy sensitive Pakistani telecom customers;
- Accumulated vendor parser test corpus, control-library review dataset, proven operational workflows and regulator submission metadata (without pretending official integrations);
- MSP/auditor ecosystems with careful independence controls.

Risks: huge scope and long implementation time; regional license-based market ceiling; competition from established compliance tools; data access concerns; regulatory ambiguity; cost of continuous legal maintenance. Mitigation: modular architecture and revenue from technical-assessment/evidence automation before all integrations are production-ready, while retaining full end-state design.

## 18. Engineering delivery waves — NO 21-DAY DEADLINE

**Sequence is dependency-driven rather than arbitrary weeks.** Launch only when stated quality gates pass. Tasks here describe the full product, not a promise that all modules can be completed together.

### Wave 0 — Regulatory verification and product discovery
- Obtain officially authenticated CTDISR 2025 gazette text and updates/requirements from PTA, counsel and suitable audit partner.
- Transcribe all 84 regulations and subordinate obligations; sign source, page and clause map, retention/reporting clock requirements and license-specific applicability.
- Build regulated-user research, risk/legal review, data residency assessment, initial security model and target customer economics.
- **Gate:** no `SOURCE_PENDING` among clauses used in sold compliance assertions; documented validation signatures.

### Wave 1 — Trust foundation / multi-tenant control plane
- Build Django/DRF, PostgreSQL, authentication, fine-grained RBAC, immutable audit log, document storage, encryption, tenant isolation, signed regulatory-pack workflow.
- Design system-of-record data model and contract tests. Import framework + nested obligations, scope and evidence objects.
- **Gate:** threat model reviewed, isolation tests pass, source-to-evidence traceability complete.

### Wave 2 — Regulatory, evidence and human compliance workflows
- M01–M04, M14, M21–M24: applicability, policy approvals, risk, evidence, auditor room, CAPA, regulatory requests, scope-controlled reports.
- Build evidence acceptance, expiration, external auditor independence and monitoring.
- **Gate:** external auditor can reproduce and challenge every tested clause assessment without vendor-admin access.

### Wave 3 — Network engineering assessment
- M05 and M07: offline inputs first, NX-OS then IOS/IOS XE, Huawei VRP and RouterOS; reliable signed collector agent, parser fixture suite, normalized facts, version-specific rules, service dependency graph.
- **Gate:** no undocumented commands, no false passes on missing data, 100% verified findings have evidence lineage; parser quality audited by network experts.

### Wave 4 — Integrated security ecosystem
- M08–M10 and M13/M20: IAM/PAM/NAC, vulnerability/EOS, SIEM, threat intelligence, cloud connectors; integrations with third-party authoritative systems, not reinventions.
- **Gate:** connector failure and missing coverage visible, no unapproved active scanning or automatic enforcement.

### Wave 5 — People, facilities, suppliers and resilience
- M06, M15–M19: data governance, vendor risk, BCP/DR, physical surveys, HR and secure development/change workflows.
- **Gate:** end-to-end manual and hybrid evidence tested with real department owners.

### Wave 6 — Incident and regulator-grade workflows
- M11, M12, M23: detection-time evidence, severity rules, deadlines, legal hold, authorized notifications and receipts; official nTSOC/nTCERT integration only if approved.
- **Gate:** tabletop exercise passes including clock, holidays, failed submission, receipts, disputed classification and chain-of-custody.

### Wave 7 — Commercial hardening and enterprise launch
- Dedicated/on-prem deployment, SSO, billing, backups/restore, HA monitoring, RBAC penetration test, privacy review, independent audit preparation, support runbooks, partner licensing.
- **Gate:** design partner acceptance, external penetration assessment closed, platform restore demonstrated, SLAs and legal terms finalized.

### Wave 8 — Continuous governance / later releases
- Rule pack and regulatory changes, additional vendors, IPv6 maturity/telemetry, advisory integration, capacity and service graph; outcome analytics and self-service migration. Customer feedback may reprioritize waves but cannot bypass legal/security gates.

## 19. Exact Codex work packages and completion artifacts



- **WP-REG** — Codex implementation request: Versioned legal ontology and review workflow; Outputs: migrations, signed importer, admin UI; Test/check: 84 headings / subclauses / source hash
- **WP-CORE** — Codex implementation request: Tenant/auth/RBAC/secrets/audit; Outputs: Django apps + API; Test/check: IDOR, permission + MFA tests
- **WP-EVID** — Codex implementation request: Encrypted evidence vault and reviewer; Outputs: object store adapter; Test/check: tamper, hash, retention/hold tests
- **WP-ASSET** — Codex implementation request: Asset/CII/owners and services; Outputs: importer, forms, APIs; Test/check: reconciliation + missing fields
- **WP-NET** — Codex implementation request: Collectors and vendor profiles; Outputs: signed agent, job FSM; Test/check: timeouts/idempotent resume
- **WP-PARSE** — Codex implementation request: CLI parsers / normalized schemas; Outputs: fixtures, typed facts; Test/check: regression against real outputs
- **WP-RULE** — Codex implementation request: Deterministic evidence-backed rules; Outputs: rule catalogue + mappings; Test/check: false-pass prevention
- **WP-GRC** — Codex implementation request: Controls, policies, approvals, risks; Outputs: workflow UI, reports; Test/check: SoD + expiry cases
- **WP-IR** — Codex implementation request: Incident, custody, reporting workflows; Outputs: clocks, receipt records; Test/check: 24h and working-day scenarios
- **WP-INTEG** — Codex implementation request: SIEM, IdP, HRIS, backup, cloud links; Outputs: isolated connectors; Test/check: rate limits and auth failures
- **WP-AUD** — Codex implementation request: External auditor room, CAPA; Outputs: review states, manifest export; Test/check: immutable challenge/retest
- **WP-COM** — Codex implementation request: Billing + installation/operations; Outputs: plans, telemetry, docs; Test/check: upgrade and tenant limits



**Execution method for Codex:** one bounded WP per task branch; read AGENTS.md before every change; submit DB migration + API contract + UI + tests + docs + acceptance log together; demonstrate tests; do not self-certify a module or invent equipment outputs; use fixture sets and signed-off requirements. Keep a decision log and unresolved blockers per PR.

## 20. Quality strategy and validation matrix

- **Legal:** 100% of published obligation text/mappings accepted by legal reviewer (not just 84 top-level entries). Regression test when source changes.
- **Security:** cross-tenant IDOR tests; uploaded hostile files; injection into parsed config; collector privilege escalation; data export; backup key recovery; MFA and restricted auditor roles.
- **Networking:** device/OS matrix, snapshots from multiple real firmware versions, CLI pagination/truncation, unsupported outputs, device HA cases, BGP/OSPF implicit policies, MikroTik bridge VLAN semantics.
- **Reliability:** 10k object inventory load tests, thousands of evidence artifacts, job crashes/resume, agent disconnection, isolated tenants, queue backlog and backpressure.
- **Workflow:** approval rejection, overdue actions, high-risk approval, false positive dispute, evidence expiry, audit period cutoff, incident filing timeout and regulator receipt validation.
- **Adversarial:** LLM tries to hallucinate compliance, untrusted CLI output contains prompt injection, generated remediation is destructive, malicious uploaded PDF attempts exfiltration—system fails safely.
- **Customer acceptance:** customer can answer an auditor’s chosen subclause in minutes with exact current evidence, and clearly show gaps/unknowns when not possible.

**Suggested technical SLO targets** are to be determined by paid pilots; never advertise unmeasured performance. Version and monitor each rule's false positives/false negatives with engineer feedback.

## 21. Organization and staffing for commercial quality

Recommended disciplines: CTO/architect, backend Django engineer(s), network automation engineer(s), security engineer/SOC SME, GRC analyst, Pakistani telecom legal/regulatory advisor, frontend/UI, QA/automation, DevSecOps/SRE, product/customer-success and business development. A qualified external auditor should review audit-room design and source coverage; avoid independence conflicts. Staffing is phased to revenue and quality gates, not assumed available on day one.

**Governance model:** Weekly engineering review of data privacy/security issues; monthly regulatory pack review; product steering with real ISP design partners; change advisory board for production automation; quarterly platform security and disaster-recovery exercise.

## 22. Business case, budget and acquisition strategy

**Revenue hypothesis:** annual B2B contracts with paid onboarding, enterprise implementation fees, advanced connectors, premium support, on-prem license and audit-partner tenant seats. No guarantee of multimillion-dollar exit. Long-term strategic attractiveness comes from recurring high-retention customer contracts, verified proprietary integration/rule corpus, healthy margins and independent governance evidence.

**Unit economics to track:** annual contract value, deployment cost, support hours/customer/month, rule update cost, net revenue retention, gross margin, paid-pilot conversion, procurement cycle, time-to-first-auditor-pack and security incident cost. Budget defensively for regulation maintenance and hardware test lab; not just code delivery.

**Potential buyer classes (NOT expressions of interest):** enterprise network management, cybersecurity governance platforms, MSSPs, SIEM/SOAR vendors and specialized telecom assurance vendors. Demonstrate scalable distribution beyond Pakistan through configurable framework engine; do not assume automatic international acceptance of PTA rules.

**Exit preparation:** avoid dependence on one customer, document IP ownership, license compliance, data processing agreements, security posture, code ownership, operational runbooks, customer renewal metrics, independent auditor limitations, and change-of-control provisions.

## 23. Product analytics and operator KPIs

Customer outcomes: asset coverage against approved CII scope; valid evidence coverage of applicable subclauses; overdue approvals; average age of gaps; CAPA reopen rate; incident report timeliness; training completion + awareness quality; backup restore test success; stale credentials and unsupported firmware; number of audits supported with complete dossiers.

Internal platform: scans per device, command retries and error distribution, parser coverage by OS release, rule precision/recall from manual reviews, document upload rejection, evidence hash verification, tenant isolation incidents, resource consumption, collector health, retention purges and customer support responsiveness.

Never gamify by burying UNKNOWN or SOURCE_PENDING. Dashboard design should prioritize actionable missing evidence over a vanity percentage.

## 24. Concrete UI specification for engineering agents

- **Regulatory Matrix:** left hierarchical clause tree (chapter → regulation → subclause), right tabs Overview / Applicability / Controls / Tests / Evidence / Issues / Audits / Version History. Search, bulk assignment, deadlines, source certainty banner.
- **Device Assessment:** fleet inventory and filters, device detail (model, software, role, sites, scan health), configuration findings, raw excerpt diff with redactions, risk context, approved remediation plan and recheck.
- **Evidence Request Center:** who requested, evidence type, period, owner, DLP class, deadline, upload, hash, reviewer feedback; all visible in audit trail.
- **Risk Register:** grid and matrix, linked CII/service, inherent/residual, treatments, owners, ISSC signatures and exception expiry.
- **Incident Desk:** priority, incident-detection timeline, source of report, legal/regulator clock, custody, approval chain, receipt status and postmortem.
- **Audit Room:** engagement/scope/period, auditor-only reviewer workspace, samples, accepted/rejected artifacts, finding register, signed report and export.
- **Admin & Tenancy:** connected collectors, data residency, secrets references (never raw read-back), SSO, RBAC, secure export rights, encryption keys, plan and subscription.

UX accessibility and localization: English first, later Urdu labels optional; timezones explicit `Asia/Karachi` for local business calendars, timestamps stored UTC; dark/light mode, print-friendly audit dossiers, keyboard accessibility, CSV imports with row-level validation.

## 25. Report-to-clause example: evidence chain

**Example use case (illustrative, not legal verdict):** a CII core switch exposes SNMP v2c with broad access.

`Device Cisco NX-OS` → `signed collector read` → `raw snapshot hash` → `parsed SNMP config fact` → `rule CS-MGMT-004 FAIL` → `approved technical control` → `applicable CTDISR subclause after legal mapping` → `network engineer action` → `change record` → `rescanned evidence` → `auditor review`.

An issue can be technically remediated while a required access control policy/approval record remains missing. End-state assessment stays GAP/INSUFFICIENT_EVIDENCE, never auto-compliant. All exports include full trace.

## 26. Documentation deliverables required from implementation team

Architecture Decision Records (ADRs), threat model, data-flow and residency map, API OpenAPI schema, migration plan, vendor support matrix, parser fixtures, technical control catalogue, regulatory crosswalk with approval record, secure operation SOPs, incident response runbook, billing/licensing contract, privacy/DPA templates reviewed by counsel, customer admin and auditor guides, evidence manifest spec, backup/restore SOP, change log and end-of-life communication procedure.

## 27. Acceptance framework for complete product readiness

**Platform-level completion is reached only when:**

1. All 84 numbered CTDISR regulations and all applicable nested subclauses imported from verified primary text, reviewed and versioned; every clause assigned controls/required evidence or documented defensible N/A.
2. All modules M01–M25 pass their documented functional, security and negative-path tests; missing third-party services are integrations with explicit evidence expectations and customer obligations.
3. Technical engine operates read-only with proper vendor/version compatibility; unsupported checks are openly UNKNOWN.
4. Human evidence workflows yield real documents/inspection/approval records with accountability; physical/training governance cannot be simulated by UI.
5. Auditor can independently test, reject and approve without compromising segregation of duties, with a preserved immutable trail.
6. Regulatory incident workflows have verified notice conditions/deadlines and successful manual delivery/receipt evidence for test cases.
7. Customer can generate a clause-wise dossier including all open/unknown items and technical evidence lineage.
8. Privacy/security/HA/backup and contract requirements reviewed for commercial deployment; no unauthorized outbound transfer of sensitive data.
9. Product terminology avoids governmental endorsement and never suggests installing software alone guarantees PTA compliance.

**Two separate outcomes:** `PRODUCT_CAPABLE_OF_SUPPORTING_EACH_CLAUSE` (platform acceptance after verified mapping) vs `CUSTOMER_HAS_SATISFIED_EACH_APPLICABLE_REQUIREMENT` (requires actual customer controls, evidence and independent judgment). Neither can be truthfully set until demonstrated.

## 28. Known legal verification blockers and immediate next actions



- **Certified complete Gazette text unavailable in this research environment** — Why it matters: Later numbered rules/subclauses cannot be quoted/mapped without speculation; Required next action: Obtain PTA/MoLaw complete 89-page official copy and amendments; source/legal team performs WP-REG
- **OCR truncation after early Access Control text** — Why it matters: Subclauses of Regulation 27 and regulations 28–84 not reliable from accessible reproduction; Required next action: Manual page-by-page authoritative transcription, dual review, source checksum
- **Secondary source counts 84 headings / 14 chapters** — Why it matters: Good planning anchor but not legal evidence for exact clause obligations; Required next action: Reconcile to gazette, check schedules/annexures
- **nTSOC/nTCERT integration specifics** — Why it matters: Official API/channel format and authentication may not be public; Required next action: Formal authorized integration agreement, otherwise manual receipt workflow
- **Reporting/audit/localization/IPv6 obligations** — Why it matters: Exact triggers, exceptions, scope and deadlines may vary by directives and license; Required next action: Lawyer+PTA/auditor check before hardcoding, maintain changeable policy pack
- **Full technical compliance not software-solvable** — Why it matters: Governance, physical controls and trained responders require organizational action; Required next action: Human-owned evidence workflows and independent review



**First activity before building commercial rule pack:** request official current Gazette + all later PTA directions from the regulator/authorized counsel or client. No completion claim until this issue is resolved.

## 29. Research sources and provenance (accessed 19 October 2026)

**S1 — Public Gazette reproduction (not certified):** https://www.scribd.com/document/1034210006/003-Critical-Telecom-Data-and-Infrastructure-Security-Regulations-CTDISR-2025 — 89 pages advertised, OCR accessible only partly; used for working summaries of regulations 1–27 and incident timing in regulation 23. Do not redistribute third-party full copyrighted text through this blueprint.

**S2 — Faseel CTDISR overview, updated 28 Sep 2026 (secondary source, not law):** https://faseel.app/compliance/ctdisr — S.R.O. 2504(I)/2025, Gazette date 31 Dec 2025, 84/14 count and product-level domain grouping; claims about annual audit, nTSOC, location and IPv6 require official confirmation.

**S3 — PTA NT CERT National Cyber Security Framework for Telecom, 7 July 2022 (official but superseded baseline):** https://ntcert.pta.gov.pk/sops/national_cs_framework_for_telecom_07-07-2022.pdf — valuable legacy interpretation of CTDISR 2020; DO NOT use as the governing text for 2025 obligations.

**S4 — PTA NT CERT older regulations 2020 (official historical baseline):** https://ntcert.pta.gov.pk/sops/critical_telecom_data_reg_20112020.pdf — do not substitute 2020 for 2025.

**S5 — Pakistan National CERT public laws list:** https://pkcert.gov.pk/policies-and-legislation.asp — currently lists CTDISR 2020 in the surfaced public inventory; reinforces requirement for obtaining verified latest primary text.

**S6 — Third-party product reference:** https://waaqi.ai/workspaces/ctdisr — shows existing Pakistan GRC competitive overlap; not a regulatory authority.

**S7 — PTA 2026 VAPT tender (demand signal only):** https://epms.ppra.gov.pk/public/tenders/tender-details/TS0000000631E — not evidence of adoption/pricing.

**Research caution:** Several third-party pages disagree about revision chronology and requirements; any claim that a legal clause exists or imposes a specific target must be backed by the official 2025 Gazette and relevant subsequent PTA directions before coding it as mandatory.

## 30. Founder decision summary

**Build the whole operating system, not only a scanner.** The commercially useful architectural unit is not 'regulation = checkbox'; it is 'approved regulation subclause = owner + scope + tested control + evidence + gap + action + audit record'. The network assessment core creates unique evidence and technical value, while compliance, governance, incident and third-party workflows make it an enterprise purchasing decision.

**No arbitrary deadline:** build as quality-gated product waves; sell narrow honestly-described capabilities during development without claiming complete compliance until the legal mapping and all acceptance gates are cleared. A credible commercial product should openly report all things it cannot assess and all controls the customer must physically operate.

