# Read-only collector foundation operations

## WP-NET-01 collection-plan capability

The control plane can now bind a device to an active tenant asset, record SSH
or an independently approved legacy Telnet exception, save an opaque
ISP-controlled vault reference and install a versioned Cisco IOS/IOS-XE
collection manifest. The manifest exposes every exact command, purpose,
sensitive-output flag, count and SHA-256 digest before approval.

Telnet devices are created blocked. A different owner/compliance lead must
approve the recorded exception and clear-text transport-risk acknowledgement.
SSH always requires a separately verified pinned host key; no SSH-to-Telnet
downgrade exists.

## What an operator enters

1. Device name, vendor/platform, management address and an SSH SHA256 host-key
   fingerprint verified through an independent trusted channel.
2. Only an opaque secrets-manager reference such as `vault://...`; never paste a
   username, password, private key or token into the application.
3. Customer-side agent identity fingerprint. API registration creates a pending
   identity; activation requires a future authenticated enrollment workflow.
4. Written authorization reference, exact device/agent/credential, purpose,
   validity window and conservative command/time/output budgets.
5. A different authorized operator approves the scope.

## Current safety stop

The reviewed Cisco command plan is bundled, but no networking library or live
socket is invoked. Profile approval means only that its exact allowlist and
manifest passed two-person review with a recorded network-engineering/code-review
signoff reference. It is not permission to run from the Django
server. Signed agent enrollment, agent job claim, production vault resolution,
encrypted output ingestion and real-firmware parser fixtures remain required.

Use `/collector/` for the setup/readiness view and `/api/v1/openapi/` for API
contracts. Collection jobs always begin with technical result `UNKNOWN`; no
collector outcome can create a legal compliance conclusion.

## VPS prerequisites for the later execution package

- Outbound-only on-prem agent with mTLS and short-lived/replay-resistant jobs.
- Production secrets manager; the control plane must never receive raw secrets.
- Encrypted tenant-resident raw snapshot storage and redaction policy.
- PostgreSQL, queue backpressure, per-device distributed locks, observability,
  backup/restore tests and incident response runbooks.
- Network-engineer-reviewed commands and anonymized fixtures for every supported
  vendor, platform and firmware release.
