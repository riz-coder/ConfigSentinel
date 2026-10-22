# ADR 0004: Collector trust boundary before transport or commands

- Status: superseded in part by WP-NET-02 local-agent execution
- Date: 2026-10-20

## Decision

Represent device identity, an opaque external credential reference, collector
identity, written authorization, hard budgets, approved command-profile identity
and collection jobs as separate tenant-scoped records. A job is admitted only
when every exact relationship and time window is valid and the observed SSH host
key equals the out-of-band pinned fingerprint.

The web request path contains no socket, subprocess or SSH/Telnet execution.
WP-NET-02 supplies a separately invoked local management-command agent for lab
and controlled on-prem use. It resolves an agent-local encrypted credential,
verifies the pinned SSH host key before authentication, and runs only exact
commands from an approved Cisco IOS/IOS-XE manifest.
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

Real device access is now possible from the explicitly invoked local agent and
is bounded by authorization windows and command/runtime/output budgets. Raw
snapshots are encrypted and hashed. A later package must separate and sign the
agent distribution, provide mTLS and replay-resistant remote claims, integrate
a production secrets manager, add distributed device locks, and validate every
supported vendor/firmware command pack on real hardware.

