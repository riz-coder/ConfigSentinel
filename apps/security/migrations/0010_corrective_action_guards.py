from django.db import migrations


INDIRECT = {
    "regulatory_correctiveactionevent": (
        "EXISTS (SELECT 1 FROM regulatory_correctiveaction a WHERE a.id = action_id "
        "AND a.tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid)"
    ),
    "regulatory_correctiveactionevidence": (
        "EXISTS (SELECT 1 FROM regulatory_correctiveaction a WHERE a.id = action_id "
        "AND a.tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid)"
    ),
}


def forward(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    tenant = "tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid"
    with schema_editor.connection.cursor() as cursor:
        cursor.execute('ALTER TABLE "regulatory_correctiveaction" ENABLE ROW LEVEL SECURITY')
        cursor.execute('ALTER TABLE "regulatory_correctiveaction" FORCE ROW LEVEL SECURITY')
        cursor.execute(f'CREATE POLICY tenant_isolation ON "regulatory_correctiveaction" USING ({tenant}) WITH CHECK ({tenant})')
        for table, expression in INDIRECT.items():
            cursor.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
            cursor.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
            cursor.execute(f'CREATE POLICY tenant_isolation ON "{table}" USING ({expression}) WITH CHECK ({expression})')
            cursor.execute(f'CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON "{table}" FOR EACH ROW EXECUTE FUNCTION configsentinel_reject_audit_mutation()')


def backward(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        for table in INDIRECT:
            cursor.execute(f'DROP TRIGGER IF EXISTS {table}_append_only ON "{table}"')
            cursor.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
            cursor.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
            cursor.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
        cursor.execute('DROP POLICY IF EXISTS tenant_isolation ON "regulatory_correctiveaction"')
        cursor.execute('ALTER TABLE "regulatory_correctiveaction" NO FORCE ROW LEVEL SECURITY')
        cursor.execute('ALTER TABLE "regulatory_correctiveaction" DISABLE ROW LEVEL SECURITY')


class Migration(migrations.Migration):
    dependencies = [
        ("regulatory", "0014_correctiveaction_correctiveactionevent_and_more"),
        ("security", "0009_auditor_report_import_guards"),
    ]
    operations = [migrations.RunPython(forward, backward)]
