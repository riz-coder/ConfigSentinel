# Cisco IOS/IOS-XE collector profile

Status: implementation candidate; network-engineer and real-firmware signoff
required before live use.

The built-in v1 profile is an exact read-only allowlist. It covers:

- discovery: platform/release and interface inventory;
- configuration: running configuration, VLAN, STP, EtherChannel and routing
  protocol configuration;
- topology: detailed CDP and LLDP neighbors;
- security: AAA server state, SSH posture, logging, NTP, SNMP and access lists;
- operations: interface state/errors, route table, OSPF/BGP neighbors, CPU and
  memory.

Some commands are feature-, privilege- or release-dependent. Unsupported,
denied, truncated or unparseable output must become `UNKNOWN`,
`NOT_APPLICABLE` or `ERROR` with a reason, never `PASS`. Running configuration,
logging, SNMP and ACL output is classified sensitive and must be encrypted and
redacted before display or export.

CDP/LLDP output creates candidate links only. A link is not confirmed until
both endpoints agree or an authorized operator reviews it. Discovery protocol
absence cannot prove that no physical/logical link exists.

## Legal boundary

The uploaded source is still `SOURCE_PENDING`. The following headings are
candidate areas where device evidence may eventually contribute after exact
subclause mapping and dual legal review: asset inventory/ownership/classification
(11–13), logical access and access review (27, 31), operations and network
security (32, 35), logging/SIEM evidence (39–40), backup/security testing
(42–43), disaster-recovery technical state (48), cryptographic controls (57),
periodic testing (63), KPIs/dashboard (69, 75), and emerging technology (84).

This is a planning index, not a legal crosswalk. Router configuration alone
cannot prove policy approval, operating effectiveness, SIEM receipt, restore
success, physical protection, business continuity or legal compliance.

## WP-NET-03 deterministic assessment baseline

After collection, the local agent authenticates and decrypts each successful
snapshot and runs version 1 of the Cisco IOS/IOS-XE baseline. Current checks
cover running-configuration readability, AAA new-model, privileged-secret
handling, explicit SSHv2, VTY Telnet exposure, plain HTTP management, remote
logging configuration/state, NTP configuration/state, SNMP community versus
SNMPv3 configuration, collection transport and snapshot integrity.

Every finding links to the exact command execution and output hash. Missing,
unsupported or unreadable commands return UNKNOWN/ERROR rather than PASS. Cisco
PSIRT/advisory correlation remains UNKNOWN until an official reviewed feed,
exact platform/release matching and update governance are implemented.
