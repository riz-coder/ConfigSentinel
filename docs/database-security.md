# Database security and operations

## Roles

`configsentinel_owner` owns the schema and is used only by the one-shot migration
container. `configsentinel_runtime` is non-superuser, cannot create roles or
databases, and is used by the web process. Never grant `BYPASSRLS` or ownership
of tenant tables to the runtime role.

The PostgreSQL initialization script creates the runtime role and owner default
privileges. Changing passwords in `.env` after a database volume has already
been initialized does not rotate database credentials; perform an explicit
`ALTER ROLE` under an approved maintenance procedure.

## Row-level security

Tenant context is stored with transaction-local PostgreSQL settings. Regulatory
source/version/regulation tables use forced RLS and default-deny when no tenant
context is present. Application query filtering remains in place as a second
layer. Tenant identity/membership tables are part of the identity plane and are
not yet protected by RLS; access to them remains service/API controlled.

Audit events are tenant-filtered for reads. Inserts must match active tenant
context, except redacted platform authentication failures which have no tenant.
A database trigger rejects update and delete operations. Superusers can still
alter/drop controls, so superuser credentials must not be available to the app.

## Backups

Backup scripts require standard PostgreSQL environment variables and generate a
custom-format archive plus SHA-256 file. Transfer archives only to encrypted,
approved off-host storage. A checksum proves transfer integrity, not secrecy.
Restore scripts are destructive and require the exact target database name as a
second argument. Perform restores only in an approved maintenance window and
run migrations plus application smoke tests afterward.
