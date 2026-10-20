from django.db import migrations


def forward(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql": return
    tenant = "tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid"
    with schema_editor.connection.cursor() as cursor:
        cursor.execute('ALTER TABLE "regulatory_clauseevidence" ENABLE ROW LEVEL SECURITY')
        cursor.execute('ALTER TABLE "regulatory_clauseevidence" FORCE ROW LEVEL SECURITY')
        cursor.execute(f'CREATE POLICY tenant_isolation ON "regulatory_clauseevidence" USING ({tenant}) WITH CHECK ({tenant})')
        cursor.execute('ALTER TABLE "regulatory_sourcedocument" ENABLE ROW LEVEL SECURITY')
        cursor.execute('ALTER TABLE "regulatory_sourcedocument" FORCE ROW LEVEL SECURITY')
        rule = "EXISTS (SELECT 1 FROM regulatory_regulatorysource s WHERE s.id = source_id AND s.tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid)"
        cursor.execute(f'CREATE POLICY tenant_isolation ON "regulatory_sourcedocument" USING ({rule}) WITH CHECK ({rule})')


def backward(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql": return
    with schema_editor.connection.cursor() as cursor:
        for table in ('regulatory_clauseevidence','regulatory_sourcedocument'):
            cursor.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
            cursor.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
            cursor.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')


class Migration(migrations.Migration):
    dependencies=[('regulatory','0005_clauseevidence_sourcedocument'),('security','0005_collector_boundary_guards')]
    operations=[migrations.RunPython(forward,backward)]
