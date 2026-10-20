# ADR 0004: Collector trust boundary before transport or commands

- Status: accepted for WP-COLLECT-01
- Date: 2026-10-20

## Decision

Represent device identity, an opaque external credential reference, collector
identity, written authorization, hard budgets, approved command-profile identity
and collection jobs as separate tenant-scoped records. A job is admitted only
when every exact relationship and time window is valid and the observed SSH host
key equals the out-of-band pinned fingerprint.

This package contains no socket, subprocess, SSH/API client or vendor command.
Command profiles remain non-executable drafts unless a later signed manifest is
reviewed by network engineering and explicitly approved by an operator. Raw
credentials are never stored or returned; only secrets-manager references exist.

Collection success means only that collection data was received. It is not a
technical PASS and never implies legal compliance. Missing or failed collection
remains `UNKNOWN` or `ERROR`.

## Consequences

The application now makes the customer inputs and authorization gates visible,
while real device access remains blocked. A later package must provide mTLS,
signed/replay-resistant jobs, an outbound-only agent, production secrets-manager
resolution, encrypted raw snapshots, timeouts and tested vendor command packs.

