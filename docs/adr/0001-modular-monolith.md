# ADR 0001: Start with a modular Django monolith

## Status

Accepted for WP-CORE-01.

## Decision

Use one Django deployment with separately bounded domain applications and one
PostgreSQL database. Keep evidence blobs behind a storage interface and keep
future collectors outside the web process. Use server-rendered HTML for the
initial operator interface and DRF for versioned APIs.

## Why

The platform requires transactional links between legal sources, controls,
evidence, findings, and audit history. A modular monolith provides those
guarantees with lower deployment and operational risk on an initial VPS. Domain
boundaries and asynchronous contracts can later be extracted where measured
load or security boundaries justify it.

## Consequences

- Tenant filtering is mandatory in every business query and API endpoint.
- PostgreSQL row-level security remains a planned defense-in-depth addition;
  application filtering is present but is not claimed as sufficient forever.
- Background collectors and evidence storage must not be tightly coupled to
  local web-server files.

