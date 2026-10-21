# Asset and CII register

WP-ASSET-01 introduces tenant-scoped sites, critical services, assets and
explicit asset dependencies. Every asset has an accountable owner and
custodian, criticality, classification and lifecycle. A CII checkbox records a
customer scope candidate only; it is not a legal CII determination.

Owners and compliance leads may create records through `/inventory/` or the
API. CSV, XLSX and XLS intake recognizes documented header aliases, maps them
to the internal schema, and is all-or-nothing. It rejects missing required
details, unknown enum values, duplicate identifiers, foreign users and unresolved scope references. Viewer and auditor
roles are read-only. PostgreSQL row-level security provides a second tenant
boundary below application filtering.

Missing site/service assignments and overdue reviews remain visible coverage
gaps. This package does not poll devices, infer legal applicability or produce
a compliance result.
