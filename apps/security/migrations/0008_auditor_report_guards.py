from django.db import migrations


def forward(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    tenant = "tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid"
    with schema_editor.connection.cursor() as cursor:
        cursor.execute('ALTER TABLE "regulatory_auditorreport" ENABLE ROW LEVEL SECURITY')
        cursor.execute('ALTER TABLE "regulatory_auditorreport" FORCE ROW LEVEL SECURITY')
        cursor.execute(
            f'CREATE POLICY tenant_isolation ON "regulatory_auditorreport" '
            f'USING ({tenant}) WITH CHECK ({tenant})'
        )
        cursor.execute(
            'CREATE TRIGGER auditor_report_append_only BEFORE UPDATE OR DELETE '
            'ON "regulatory_auditorreport" FOR EACH ROW '
            'EXECUTE FUNCTION configsentinel_reject_audit_mutation()'
        )


def backward(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute('DROP TRIGGER IF EXISTS auditor_report_append_only ON "regulatory_auditorreport"')
        cursor.execute('DROP POLICY IF EXISTS tenant_isolation ON "regulatory_auditorreport"')
        cursor.execute('ALTER TABLE "regulatory_auditorreport" NO FORCE ROW LEVEL SECURITY')
        cursor.execute('ALTER TABLE "regulatory_auditorreport" DISABLE ROW LEVEL SECURITY')


class Migration(migrations.Migration):
    dependencies = [
        ("regulatory", "0012_auditorreport"),
        ("security", "0007_clause_audit_guards"),
    ]
    operations = [migrations.RunPython(forward, backward)]
