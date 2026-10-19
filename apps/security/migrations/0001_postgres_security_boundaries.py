from django.db import migrations


TABLE_POLICIES = {
    "regulatory_regulatorysource": "tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid",
    "regulatory_regulatoryversion": "EXISTS (SELECT 1 FROM regulatory_regulatorysource s WHERE s.id = source_id AND s.tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid)",
    "regulatory_regulation": "EXISTS (SELECT 1 FROM regulatory_regulatoryversion v JOIN regulatory_regulatorysource s ON s.id = v.source_id WHERE v.id = version_id AND s.tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid)",
}


def enable_postgres_guards(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        for table, expression in TABLE_POLICIES.items():
            cursor.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
            cursor.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
            cursor.execute(
                f'CREATE POLICY tenant_isolation ON "{table}" USING ({expression}) WITH CHECK ({expression})'
            )

        cursor.execute('ALTER TABLE "auditlog_auditevent" ENABLE ROW LEVEL SECURITY')
        cursor.execute('ALTER TABLE "auditlog_auditevent" FORCE ROW LEVEL SECURITY')
        cursor.execute(
            """
            CREATE POLICY audit_tenant_select ON auditlog_auditevent
            FOR SELECT USING (
                tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid
            )
            """
        )
        cursor.execute(
            """
            CREATE POLICY audit_tenant_insert ON auditlog_auditevent
            FOR INSERT WITH CHECK (
                tenant_id IS NULL OR
                tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid
            )
            """
        )
        cursor.execute(
            """
            CREATE FUNCTION configsentinel_reject_audit_mutation() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
                RAISE EXCEPTION 'audit events are append-only';
            END;
            $$
            """
        )
        cursor.execute(
            """
            CREATE TRIGGER audit_event_append_only
            BEFORE UPDATE OR DELETE ON auditlog_auditevent
            FOR EACH ROW EXECUTE FUNCTION configsentinel_reject_audit_mutation()
            """
        )


def disable_postgres_guards(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute('DROP TRIGGER IF EXISTS audit_event_append_only ON "auditlog_auditevent"')
        cursor.execute("DROP FUNCTION IF EXISTS configsentinel_reject_audit_mutation()")
        cursor.execute('DROP POLICY IF EXISTS audit_tenant_insert ON "auditlog_auditevent"')
        cursor.execute('DROP POLICY IF EXISTS audit_tenant_select ON "auditlog_auditevent"')
        cursor.execute('ALTER TABLE "auditlog_auditevent" NO FORCE ROW LEVEL SECURITY')
        cursor.execute('ALTER TABLE "auditlog_auditevent" DISABLE ROW LEVEL SECURITY')
        for table in TABLE_POLICIES:
            cursor.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
            cursor.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
            cursor.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')


class Migration(migrations.Migration):
    dependencies = [
        ("auditlog", "0002_alter_auditevent_tenant"),
        ("regulatory", "0001_initial"),
        ("tenancy", "0001_initial"),
    ]

    operations = [migrations.RunPython(enable_postgres_guards, disable_postgres_guards)]
