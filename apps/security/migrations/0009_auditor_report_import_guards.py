from django.db import migrations


POLICIES = {
    "regulatory_auditorreportimport": (
        "EXISTS (SELECT 1 FROM regulatory_auditorreport r WHERE r.id = report_id "
        "AND r.tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid)"
    ),
    "regulatory_auditorreportimportrow": (
        "EXISTS (SELECT 1 FROM regulatory_auditorreportimport b "
        "JOIN regulatory_auditorreport r ON r.id = b.report_id "
        "WHERE b.id = batch_id AND r.tenant_id = "
        "nullif(current_setting('configsentinel.tenant_id', true), '')::uuid)"
    ),
}


def forward(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        for table, expression in POLICIES.items():
            cursor.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
            cursor.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
            cursor.execute(f'CREATE POLICY tenant_isolation ON "{table}" USING ({expression}) WITH CHECK ({expression})')
        cursor.execute(
            """
            CREATE FUNCTION configsentinel_guard_auditor_import() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
                IF TG_TABLE_NAME = 'regulatory_auditorreportimport' THEN
                    IF TG_OP = 'DELETE' OR OLD.status = 'CONFIRMED' THEN
                        RAISE EXCEPTION 'confirmed auditor imports are immutable';
                    END IF;
                ELSE
                    IF TG_OP = 'DELETE' AND OLD.confirmed_assessment_id IS NOT NULL THEN
                        RAISE EXCEPTION 'confirmed auditor import rows are immutable';
                    END IF;
                    IF TG_OP = 'UPDATE' AND OLD.confirmed_assessment_id IS NOT NULL THEN
                        RAISE EXCEPTION 'confirmed auditor import rows are immutable';
                    END IF;
                END IF;
                IF TG_OP = 'DELETE' THEN
                    RETURN OLD;
                END IF;
                RETURN NEW;
            END;
            $$
            """
        )
        cursor.execute('CREATE TRIGGER auditor_import_guard BEFORE UPDATE OR DELETE ON "regulatory_auditorreportimport" FOR EACH ROW EXECUTE FUNCTION configsentinel_guard_auditor_import()')
        cursor.execute('CREATE TRIGGER auditor_import_row_guard BEFORE UPDATE OR DELETE ON "regulatory_auditorreportimportrow" FOR EACH ROW EXECUTE FUNCTION configsentinel_guard_auditor_import()')


def backward(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute('DROP TRIGGER IF EXISTS auditor_import_row_guard ON "regulatory_auditorreportimportrow"')
        cursor.execute('DROP TRIGGER IF EXISTS auditor_import_guard ON "regulatory_auditorreportimport"')
        cursor.execute('DROP FUNCTION IF EXISTS configsentinel_guard_auditor_import()')
        for table in POLICIES:
            cursor.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
            cursor.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
            cursor.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')


class Migration(migrations.Migration):
    dependencies = [
        ("regulatory", "0013_clauseauditassessment_auditor_report_and_more"),
        ("security", "0008_auditor_report_guards"),
    ]
    operations = [migrations.RunPython(forward, backward)]
