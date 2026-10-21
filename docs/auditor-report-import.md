# Auditor PDF decision import

`WP-AUD-02` imports explicit human auditor decisions from a tenant-supplied,
text-readable PDF. Parsing is local and deterministic; the document is never
sent to Gemini or another external model.

Supported rows identify a clause, status and remarks, for example:

```text
Clause 8 | Partial | Annual recurrence evidence was not available.
Clause 11 - Compliant - Asset register and ownership were verified on site.
```

The three values may also appear on separate lines. Accepted source statuses
are Compliant, Partial/Partially Compliant, Non-Compliant and Not Applicable.

Extraction creates draft rows only. An auditor must review/correct the exact
clause, status and remarks, resolve duplicate or unmatched references, and then
confirm the complete batch. Confirmation is idempotent and creates immutable
clause assessment versions linked to the encrypted report hash.

An imported `Compliant` statement becomes platform `READY` only when the exact
legal source and mapping gates are verified. Otherwise the result remains
`LEGAL_UNVERIFIED`. PDF wording is never treated as regulator certification.

Scanned/image-only PDFs are not imported by this package. The auditor should
upload a text-readable signed copy; OCR of audit verdicts is intentionally not
used because status transcription requires explicit human confirmation.
