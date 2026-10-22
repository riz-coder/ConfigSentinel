from django.db import migrations


def add_guards(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        tenant = "tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid"
        for table in ("collector_deviceassessment", "collector_technicalfinding"):
            cursor.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
            cursor.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
            cursor.execute(f'CREATE POLICY tenant_isolation ON "{table}" USING ({tenant}) WITH CHECK ({tenant})')


def remove_guards(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        for table in ("collector_deviceassessment", "collector_technicalfinding"):
            cursor.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')


class Migration(migrations.Migration):
    dependencies = [("collector", "0005_deviceassessment_technicalfinding"), ("security", "0013_collector_execution_guards")]
    operations = [migrations.RunPython(add_guards, remove_guards)]
