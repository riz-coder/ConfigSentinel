from django.db import migrations


TABLE_POLICIES = {
    "regulatory_trustedsigningkey": "tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid",
    "regulatory_regulatoryimportbatch": "tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid",
    "regulatory_subclause": "EXISTS (SELECT 1 FROM regulatory_regulation r JOIN regulatory_regulatoryversion v ON v.id = r.version_id JOIN regulatory_regulatorysource s ON s.id = v.source_id WHERE r.id = regulation_id AND s.tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid)",
    "regulatory_obligation": "EXISTS (SELECT 1 FROM regulatory_subclause c JOIN regulatory_regulation r ON r.id = c.regulation_id JOIN regulatory_regulatoryversion v ON v.id = r.version_id JOIN regulatory_regulatorysource s ON s.id = v.source_id WHERE c.id = subclause_id AND s.tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid)",
    "regulatory_regulatoryreview": "EXISTS (SELECT 1 FROM regulatory_regulatoryversion v JOIN regulatory_regulatorysource s ON s.id = v.source_id WHERE v.id = version_id AND s.tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid)",
}


def enable_pack_rls(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        for table, expression in TABLE_POLICIES.items():
            cursor.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
            cursor.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
            cursor.execute(f'CREATE POLICY tenant_isolation ON "{table}" USING ({expression}) WITH CHECK ({expression})')


def disable_pack_rls(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        for table in TABLE_POLICIES:
            cursor.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
            cursor.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
            cursor.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')


class Migration(migrations.Migration):
    dependencies = [("regulatory", "0002_regulatorysource_verification_completed_at_subclause_and_more"), ("security", "0001_postgres_security_boundaries")]
    operations = [migrations.RunPython(enable_pack_rls, disable_pack_rls)]
