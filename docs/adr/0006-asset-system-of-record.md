# ADR 0006: Tenant asset system of record

Status: accepted for WP-ASSET-01.

Sites, critical services, assets and directed dependencies are separate
tenant-scoped records. Assets require owner and custodian accountability and
carry explicit lifecycle, criticality and data-classification values. A CII
flag means customer scope candidate only; legal applicability remains in the
reviewed regulatory workflow.

Application filtering is backed by PostgreSQL forced RLS. CSV intake validates
the complete batch before insertion. Collector endpoints are not merged into
the asset record in this package: a later reviewed migration will link them so
inventory remains useful even where no technical collection is available.

The schema retains the minimum attribute categories transcribed from Regulation
11(3) of the uploaded source copy. Fixed-column CSV/XLSX templates provide
examples and imports fail atomically when required data is absent. This does
not mark the source or mapping `VERIFIED`.

Source-register owner and custodian text is stored separately from application
accountability. A matching active tenant user is linked when available;
otherwise the authenticated importer is linked while the original person,
team or role remains unchanged and visible.
