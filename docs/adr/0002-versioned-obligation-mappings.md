# ADR 0002: Approve exact versioned obligation mappings

## Status

Accepted for WP-REG-02.

## Decision

Represent assurance design as an exact chain from a verified `Obligation` to a
versioned `ControlDefinition`, `TestProcedure`, and `EvidenceRequirement`.
Submit that chain as an `ObligationControlMapping`. The mapping author cannot
review it; one legal reviewer and a different compliance lead must approve it.
Only an approved mapping contributes to regulatory coverage.

Each catalogue record is immutable after it is referenced. Final mapping and
review records are append-only in both the Django model boundary and PostgreSQL
triggers. Corrections create new catalogue versions and a new mapping rather
than rewriting historic audit meaning.

## Why

A free-text reference cannot prove which procedure or evidence expectation was
approved at a point in time. Exact foreign keys preserve bidirectional lineage,
allow deterministic coverage checks, and prevent later catalogue edits from
changing an old approval silently.

## Consequences

- `SOURCE_PENDING` obligations cannot enter the approval workflow.
- Draft and partially reviewed mappings remain coverage gaps.
- Evidence requirements describe expected artifacts only; they are not proof
  that an artifact exists, is current, or has been accepted.
- Evidence artifact encryption, retention enforcement, review, and legal holds
  remain a separate `WP-EVID` boundary.
- Database superusers can remove triggers and therefore must not be application
  identities.
