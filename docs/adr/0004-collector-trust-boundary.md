# ADR 0004: Collector trust boundary before transport or commands

- Status: accepted for WP-COLLECT-01
- Date: 2026-10-20

## Decision

Represent device identity, an opaque external credential reference, collector
identity, written authorization, hard budgets, approved command-profile identity
and collection jobs as separate tenant-scoped records. A job is admitted only
when every exact relationship and time window is valid and the observed SSH host
key equals the out-of-band pinned fingerprint.

The Django control plane contains no socket, subprocess or SSH/Telnet client.
WP-NET-01 adds exact versioned command definitions and a reviewed Cisco
IOS/IOS-XE manifest, but execution remains an outbound-agent responsibility.
Profiles require integrity verification, a network-engineering/code-review
signoff reference and approval by someone other than the installer. Raw
credentials are never stored or returned; only secrets-manager references exist.

SSH is the default and requires a pinned host key. Telnet is represented only
as a blocked legacy exception with written rationale and independent approval;
there is no automatic downgrade. A device is linked to an active tenant asset.

Collection success means only that collection data was received. It is not a
technical PASS and never implies legal compliance. Missing or failed collection
remains `UNKNOWN` or `ERROR`.

## Consequences

The application now makes the customer inputs and authorization gates visible,
while real device access remains blocked. A later package must provide mTLS,
signed/replay-resistant jobs, an outbound-only agent, production secrets-manager
resolution, encrypted raw snapshots, timeouts and tested vendor command packs.

