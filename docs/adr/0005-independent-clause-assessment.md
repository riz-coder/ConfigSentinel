# ADR 0005: Independent clause assessment is append-only and fail-closed

## Status

Accepted for `WP-EVID/AUD-01`.

## Decision

Evidence-file review and clause assessment are separate records. Only an active
tenant auditor can create them, and an uploader cannot review their own
evidence. Each file is decrypted and hash-verified before its immutable review
is recorded. Clause assessments snapshot file identifiers, hashes and evidence
states; they never include file contents.

A new assessment creates a new sequence rather than replacing history. If the
active evidence hashes later differ from the latest snapshot, the UI and report
mark that decision as requiring reassessment.

The auditor decision does not alter legal-source state. Until the exact source,
clause, obligations and mappings are verified, the only clause compliance state
the workflow may emit is `LEGAL_UNVERIFIED`. Once those gates are complete,
accepted evidence can yield `READY`, rejected evidence `GAP`, and an update
request `INSUFFICIENT_EVIDENCE`.

## Consequences

- Preliminary machine findings remain advisory and are displayed separately.
- Reports can show defensible review history without claiming certification.
- PostgreSQL RLS and database triggers enforce tenant scope and append-only
  behavior in production; SQLite tests cover application boundaries only.
- Tenant owners may create dedicated auditor identities, but cannot exercise
  auditor decisions. Passwords pass Django validation and are never logged or
  returned after creation.
- An auditor may upload an encrypted signed/on-site PDF report as an immutable
  audit artifact. The upload never bulk-sets clause outcomes; each clause
  decision remains separately attributable and source-gated.
- Local deterministic PDF extraction may prepare clause/status/remarks drafts.
  Drafts have no dashboard effect; only an explicit auditor confirmation creates
  immutable assessments. Unmatched and duplicate clause references fail closed.
- Auditor gap decisions create one traceable corrective-action draft. ISP-side
  owners provide remediation and versioned evidence; only an independent auditor
  can close or reopen retest workflow. Closing an action does not change legal
  source state or make a regulatory compliance claim.
