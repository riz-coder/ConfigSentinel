# Read-only collector foundation operations

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

No vendor commands are bundled and no networking library is invoked. Command
profiles created through the API are drafts. Do not change an agent or command
profile to approved in production: signed enrollment, command review, firmware
fixtures and explicit operator signoff are not yet implemented.

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
