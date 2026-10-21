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

CSV decoding accepts UTF-8, UTF-16/32, Windows-1252 and Latin-1 exports and
detects comma, semicolon, tab or pipe delimiters. XLS/XLSX file signatures take
precedence over a misleading `.csv` filename.

Missing site/service assignments and overdue reviews remain visible coverage
gaps. This package does not poll devices, infer legal applicability or produce
a compliance result.

## Standard template

The CSV/XLSX download contains three sample rows and fixed columns derived from
the minimum Asset Register attribute categories visible in Regulation 11(3) of
the user-supplied 2025 source copy. It is a ConfigSentinel operational
template, not a regulator-issued form, while the source remains
`SOURCE_PENDING`.

The acquisition, last-review and next-review dates accept blank values when
they are genuinely unknown. They remain inventory data-quality gaps instead
of blocking every row. Repeated validation failures are grouped into compact
row ranges rather than rendering one duplicate message per row.
