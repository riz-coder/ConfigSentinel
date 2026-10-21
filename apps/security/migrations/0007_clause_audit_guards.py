from django.db import migrations


def forward(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    tenant = "tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid"
    review_scope = (
        "EXISTS (SELECT 1 FROM regulatory_clauseevidence e "
        "WHERE e.id = artifact_id AND e.tenant_id = "
        "nullif(current_setting('configsentinel.tenant_id', true), '')::uuid)"
    )
    with schema_editor.connection.cursor() as cursor:
        cursor.execute('ALTER TABLE "regulatory_clauseauditassessment" ENABLE ROW LEVEL SECURITY')
        cursor.execute('ALTER TABLE "regulatory_clauseauditassessment" FORCE ROW LEVEL SECURITY')
        cursor.execute(
            f'CREATE POLICY tenant_isolation ON "regulatory_clauseauditassessment" '
            f'USING ({tenant}) WITH CHECK ({tenant})'
        )
        cursor.execute('ALTER TABLE "regulatory_clauseevidencereview" ENABLE ROW LEVEL SECURITY')
        cursor.execute('ALTER TABLE "regulatory_clauseevidencereview" FORCE ROW LEVEL SECURITY')
        cursor.execute(
            f'CREATE POLICY tenant_isolation ON "regulatory_clauseevidencereview" '
            f'USING ({review_scope}) WITH CHECK ({review_scope})'
        )
        for table, trigger in (
            ("regulatory_clauseauditassessment", "clause_audit_assessment_append_only"),
            ("regulatory_clauseevidencereview", "clause_evidence_review_append_only"),
        ):
            cursor.execute(
                f'CREATE TRIGGER {trigger} BEFORE UPDATE OR DELETE ON "{table}" '
                'FOR EACH ROW EXECUTE FUNCTION configsentinel_reject_audit_mutation()'
            )


def backward(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        for table, trigger in (
            ("regulatory_clauseauditassessment", "clause_audit_assessment_append_only"),
            ("regulatory_clauseevidencereview", "clause_evidence_review_append_only"),
        ):
            cursor.execute(f'DROP TRIGGER IF EXISTS {trigger} ON "{table}"')
            cursor.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
            cursor.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
            cursor.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')


class Migration(migrations.Migration):
    dependencies = [
        ("regulatory", "0011_clauseevidencereview_clauseauditassessment"),
        ("security", "0006_regulatory_source_document_rls"),
    ]
    operations = [migrations.RunPython(forward, backward)]
