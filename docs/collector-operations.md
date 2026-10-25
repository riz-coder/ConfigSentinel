# Read-only collector operations

## WP-NET-08 structured device report

New assessments derive bounded counts and health observations for interfaces,
VLANs, trunks, port channels, STP, topology neighbors, OSPF, BGP, HSRP, vPC and
interface error counters. Reports group findings by technical category and retain
the exact approved command plus output SHA-256 as evidence lineage. They never
render the raw running configuration or neighbor IP addresses.

An unfamiliar output format produces UNKNOWN, not PASS. Counts prove collection
visibility only; they do not establish correct design or PTA compliance. Parser
support still requires validation against anonymized captures from each claimed
firmware train.

Commands unavailable on a discovered model/release are listed as COMPATIBILITY
findings with their execution state and reason. A replacement command must enter
a new immutable profile revision and receive independent operator/code review;
the collector never lets an AI improvise a live command or silently substitute it.

## WP-NET-07 Cisco deep-assessment v2

The collector UI can create separate IOS/IOS-XE and NX-OS v2 draft manifests.
They contain exactly 30 reviewed read-only commands, so approved v1 manifests
remain immutable and usable. A different tenant owner or compliance lead must
inspect and approve each exact manifest before it is eligible for collection.

The capability planner uses the already captured running configuration only to
skip irrelevant VRF, vPC, HSRP, trunk, OSPF and BGP commands. It cannot construct
commands from device text. The assessment records bounded vPC health, interface
error-counter and spanning-tree observations. Cumulative counters require an
operator baseline; inventory visibility alone does not assert healthy design.

Actual supported-firmware validation and signed operator review remain required.
This technical output does not establish PTA compliance.

## WP-NET-02 local/on-prem execution slice

The application can now dispatch an authorized job from the Collector Setup UI
to a detached local worker. The worker performs SSH
host-key verification before authentication, discovers the Cisco platform with
the approved `show version` command, then executes only the exact commands in
the independently approved profile. There is no arbitrary command input or
SSH-to-Telnet fallback.

Raw credentials remain outside the database. An authorized operator provisions
them from the Collector Setup screen directly into the local encrypted store.
The password is write-only: it is not rendered back, logged, audited or sent to
an external model. If `CONFIGSENTINEL_COLLECTOR_SECRET_KEY` is unset, this local
deployment generates a protected key file under `.collector_secrets`; production
deployments must supply the key through their secrets manager.

The command output is encrypted locally using authenticated encryption. Each
device output is stored as a separate encrypted, hashed snapshot. Output size,
runtime and command count are bounded by the approved scope grant. Unsupported,
denied, timed-out and truncated commands remain explicit; they never become a
technical PASS or a legal compliance conclusion.

This package is suitable for controlled local development and lab validation.
Production still requires a separately packaged outbound-only agent, mTLS and
signed/replay-resistant job claims, a production secrets manager, distributed
locks and testing on the exact supported firmware.

The management command remains an operator recovery/diagnostic interface, but
normal users queue and run scans from the application. The web request launches
only the fixed worker entry point with an exact job UUID and returns immediately;
it does not accept command text or keep a network session inside the request.

## WP-NET-01 collection-plan capability

The control plane can now bind a device to an active tenant asset, record SSH
or an independently approved legacy Telnet exception, save an opaque
ISP-controlled vault reference and install a versioned Cisco IOS/IOS-XE
collection manifest. The manifest exposes every exact command, purpose,
sensitive-output flag, count and SHA-256 digest before approval. Manual profile
installation is not exposed to customers; the outbound agent package will
select a reviewed profile only after platform/capability discovery.

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

## WP-NET-01 foundation retained

Profile approval means only that its exact allowlist and manifest passed
two-person review with a recorded network-engineering/code-review signoff
reference. It is not a compliance approval. Live execution is deliberately
available only through the local collector management command, not a web
request.

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
