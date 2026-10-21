# Regulatory pack format and approval gate

ConfigSentinel accepts tenant-scoped JSON manifests signed with a detached
Ed25519 signature. This mechanism proves that a manifest came from a configured
key; it does not prove that the text is legally correct or that a regulator has
approved ConfigSentinel.

## Trust and signing

1. A tenant owner registers the publisher's 32-byte raw Ed25519 public key as
   standard base64. Private keys must never be uploaded to ConfigSentinel.
2. The publisher serializes the manifest as UTF-8 JSON with keys sorted, no
   insignificant whitespace, and separators `,` and `:`. Unicode is not escaped.
3. The publisher signs those canonical bytes and uploads the original JSON plus
   the raw 64-byte detached signature.
4. ConfigSentinel reparses, validates, canonicalizes, and verifies the manifest
   before opening one atomic database transaction. The manifest limit is 2 MiB.

Python canonicalization equivalent:

```python
json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
```

## Required structure

```json
{
  "schema_version": 1,
  "source": {
    "title": "Publisher-provided title",
    "authority_url": "https://authority.example/document.pdf",
    "gazette_identifier": "PUBLISHER-ID",
    "sha256": "64 hexadecimal characters for the source document"
  },
  "version": {"label": "publisher-version", "effective_date": "2025-01-01"},
  "regulations": [{
    "number": 1,
    "title": "Publisher-provided text",
    "source_page": "1",
    "subclauses": [{
      "path": "1.1",
      "parent_path": null,
      "title": "Publisher-provided text",
      "source_page": "1",
      "obligations": [{
        "key": "publisher-stable-key",
        "paraphrase": "Publisher-provided paraphrase",
        "requirement_type": "publisher-defined type",
        "evidence_specification": "",
        "control_reference": "",
        "test_procedure_reference": ""
      }]
    }]
  }]
}
```

Regulation numbers must be unique and between 1 and 84. Clause paths must be
unique within a regulation; parent paths must exist and cannot form cycles.
Obligation keys must be unique within their clause. Unknown fields are rejected.

## Review and coverage semantics

An import begins `UNDER_REVIEW`, with all legal content `SOURCE_PENDING`. A user
with the legal-reviewer role and a different user with the compliance-lead role
must independently approve it. A rejection returns the immutable version to
`DRAFT`; corrections require a newly signed version.

Approval verifies source governance, but does not by itself make coverage ready.
The coverage gate separately reports missing regulation numbers, obligations,
control mappings, test procedures, and evidence specifications. Until an
authenticated complete Gazette is supplied and reviewed, no production legal
coverage claim should be made.

## PDF intake review gate

Tenant-uploaded PDFs remain `SOURCE_PENDING`. Before independent legal and
compliance approval, the UI requires an authority URL, gazette/SRO identifier,
source hash, regulation/subclause page coordinates, extracted source text for
PDF-backed versions, and at least one human-authored obligation per subclause.
The version API exposes the same blocker codes. Source review and complete
84-regulation mapping coverage are separate gates; passing one never implies
the other.
