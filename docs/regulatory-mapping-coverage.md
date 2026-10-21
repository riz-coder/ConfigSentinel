# Regulatory mapping coverage

## Current product capability

ConfigSentinel can preserve and review an exact versioned chain:

`verified obligation → control → test procedure → evidence requirement`

Coverage counts a chain only after two independent decisions: legal approval
and compliance approval. The author cannot provide either approval. Rejected,
draft, partially reviewed, cross-tenant, or legally unverified chains never
increase coverage.

## Current legal-data status

No authenticated complete CTDISR 2025 Gazette was supplied in this workspace.
Therefore this release publishes no populated production mapping catalogue and
makes no assertion that any CTDISR clause is fulfilled. Test fixtures contain
only explicit synthetic text.

## Explicitly not measured yet

- Whether a customer has implemented a mapped control.
- Whether a test has executed or passed.
- Whether evidence exists, is authentic, current, sufficient, or accepted.
- Applicability, operating effectiveness, audit opinion, or legal compliance.

Those states remain separate future workflows and must not be inferred from an
approved design mapping.

## Preliminary local evidence checks

The local evidence engine performs non-authoritative triage of readable active
files. It checks action-linked roles/items, recurrence/date indicators,
approval/signature indicators, readability, embedded-image limitations and
repetitive-text risk. A keyword occurrence alone is not proof. These results do
not authenticate a document, accept evidence, verify a legal mapping or issue a
legal compliance conclusion; those decisions remain human workflows.
JPG/JPEG/PNG files and image-only DOCX media are processed with local OCR. Only
recognized text participates in preliminary checks; image authenticity and the
depicted real-world event remain subject to human review.

## Independent clause assessment

`WP-EVID/AUD-01` adds an independent auditor layer after preliminary analysis.
Each active file receives a hash-verified accept/reject decision, followed by a
versioned clause assessment. The assessment snapshots evidence hashes and is
shown as stale if files are later added or withdrawn. Source verification,
machine analysis, evidence-file state, and clause compliance state remain
separate; pending source or mapping gates force `LEGAL_UNVERIFIED`.
Auditor PDF imports retain the exact report hash and human-reported status, but
they do not bypass this gate. `Compliant` in an external report is displayed as
`LEGAL_UNVERIFIED` until the referenced source and mappings are verified.
For source text that explicitly names a controlled document type, the engine
also reports document presence, governance markers (purpose, scope, ownership,
approval, version and review/effective date), and potential coverage of exact
source-derived fragments. Potential coverage is not legal mapping approval,
document authentication, evidence acceptance or operating-effectiveness proof.
Screenshots, logs and other operational artifacts are presented separately as
supporting evidence. They can corroborate a specific operational signal (for
example, backup/recovery activity) but cannot stand in for a required controlled
document such as a policy, procedure, BIA or plan.

The displayed preliminary evidence-coverage percentage is a transparent
completeness indicator, not a compliance score or legal conclusion. When a
required controlled document is missing, supporting operational artifacts are
capped at 10% so they cannot inflate the assessment.

## Corrective actions

A corrective action is linked to a human auditor rejection or request for
updated evidence, not to an inferred legal mapping or preliminary AI result.
Closing an action records workflow closure after retest; it does not change
the source, mapping, or legal verification state.

## Asset scope

The asset register provides accountable scope context for later clause,
evidence and technical-control mappings. Marking an asset as a CII candidate
does not verify legal applicability and does not change any clause status.

For operational triage, less than 50% preliminary evidence coverage is shown
as `NON_COMPLIANT` and 50–99% as `PARTIAL`. At 100%, the UI remains
`PARTIAL` with `EVIDENCE_COMPLETE_LEGAL_REVIEW_PENDING` unless the source,
subclause and approved obligation mapping have all been verified; this protects
against representing evidence completeness as a legal compliance conclusion.
