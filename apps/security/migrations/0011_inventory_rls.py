from django.db import migrations


TABLES = ("inventory_site", "inventory_criticalservice", "inventory_asset", "inventory_assetdependency")


def forward(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    predicate = "tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid"
    with schema_editor.connection.cursor() as cursor:
        for table in TABLES:
            cursor.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
            cursor.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
            cursor.execute(f'CREATE POLICY tenant_isolation ON "{table}" USING ({predicate}) WITH CHECK ({predicate})')


def backward(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        for table in TABLES:
            cursor.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
            cursor.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
            cursor.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')


class Migration(migrations.Migration):
    dependencies = [("inventory", "0001_initial"), ("security", "0010_corrective_action_guards")]
    operations = [migrations.RunPython(forward, backward)]
