from django.db import migrations


DIRECT_TABLES = (
    "regulatory_controldefinition",
    "regulatory_testprocedure",
    "regulatory_evidencerequirement",
    "regulatory_obligationcontrolmapping",
)


def enable_mapping_guards(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    tenant = "tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid"
    with schema_editor.connection.cursor() as cursor:
        for table in DIRECT_TABLES:
            cursor.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
            cursor.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
            cursor.execute(f'CREATE POLICY tenant_isolation ON "{table}" USING ({tenant}) WITH CHECK ({tenant})')
        review_expression = "EXISTS (SELECT 1 FROM regulatory_obligationcontrolmapping m WHERE m.id = mapping_id AND m.tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid)"
        cursor.execute('ALTER TABLE "regulatory_mappingreview" ENABLE ROW LEVEL SECURITY')
        cursor.execute('ALTER TABLE "regulatory_mappingreview" FORCE ROW LEVEL SECURITY')
        cursor.execute(f'CREATE POLICY tenant_isolation ON "regulatory_mappingreview" USING ({review_expression}) WITH CHECK ({review_expression})')
        cursor.execute(
            """
            CREATE FUNCTION configsentinel_reject_final_mapping_mutation() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
                IF OLD.status IN ('APPROVED', 'REJECTED') THEN
                    RAISE EXCEPTION 'finalized regulatory mappings are immutable';
                END IF;
                IF TG_OP = 'DELETE' THEN
                    RETURN OLD;
                END IF;
                RETURN NEW;
            END;
            $$
            """
        )
        cursor.execute(
            """
            CREATE TRIGGER final_mapping_immutable
            BEFORE UPDATE OR DELETE ON regulatory_obligationcontrolmapping
            FOR EACH ROW EXECUTE FUNCTION configsentinel_reject_final_mapping_mutation()
            """
        )
        cursor.execute(
            """
            CREATE TRIGGER mapping_review_append_only
            BEFORE UPDATE OR DELETE ON regulatory_mappingreview
            FOR EACH ROW EXECUTE FUNCTION configsentinel_reject_audit_mutation()
            """
        )
        cursor.execute(
            """
            CREATE FUNCTION configsentinel_reject_referenced_catalog_mutation() RETURNS trigger
            LANGUAGE plpgsql AS $$
            DECLARE referenced boolean;
            BEGIN
                IF TG_TABLE_NAME = 'regulatory_controldefinition' THEN
                    SELECT EXISTS (SELECT 1 FROM regulatory_obligationcontrolmapping WHERE control_id = OLD.id) INTO referenced;
                ELSIF TG_TABLE_NAME = 'regulatory_testprocedure' THEN
                    SELECT EXISTS (SELECT 1 FROM regulatory_obligationcontrolmapping WHERE test_procedure_id = OLD.id) INTO referenced;
                ELSE
                    SELECT EXISTS (SELECT 1 FROM regulatory_obligationcontrolmapping WHERE evidence_requirement_id = OLD.id) INTO referenced;
                END IF;
                IF referenced THEN
                    RAISE EXCEPTION 'referenced mapping catalogue versions are immutable';
                END IF;
                IF TG_OP = 'DELETE' THEN
                    RETURN OLD;
                END IF;
                RETURN NEW;
            END;
            $$
            """
        )
        for table in ("regulatory_controldefinition", "regulatory_testprocedure", "regulatory_evidencerequirement"):
            cursor.execute(
                f'CREATE TRIGGER referenced_catalog_immutable BEFORE UPDATE OR DELETE ON "{table}" '
                'FOR EACH ROW EXECUTE FUNCTION configsentinel_reject_referenced_catalog_mutation()'
            )


def disable_mapping_guards(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        for table in ("regulatory_controldefinition", "regulatory_testprocedure", "regulatory_evidencerequirement"):
            cursor.execute(f'DROP TRIGGER IF EXISTS referenced_catalog_immutable ON "{table}"')
        cursor.execute("DROP FUNCTION IF EXISTS configsentinel_reject_referenced_catalog_mutation()")
        cursor.execute('DROP TRIGGER IF EXISTS mapping_review_append_only ON "regulatory_mappingreview"')
        cursor.execute('DROP TRIGGER IF EXISTS final_mapping_immutable ON "regulatory_obligationcontrolmapping"')
        cursor.execute("DROP FUNCTION IF EXISTS configsentinel_reject_final_mapping_mutation()")
        cursor.execute('DROP POLICY IF EXISTS tenant_isolation ON "regulatory_mappingreview"')
        cursor.execute('ALTER TABLE "regulatory_mappingreview" NO FORCE ROW LEVEL SECURITY')
        cursor.execute('ALTER TABLE "regulatory_mappingreview" DISABLE ROW LEVEL SECURITY')
        for table in DIRECT_TABLES:
            cursor.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
            cursor.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
            cursor.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')


class Migration(migrations.Migration):
    dependencies = [
        ("regulatory", "0003_controldefinition_evidencerequirement_and_more"),
        ("security", "0002_regulatory_pack_rls"),
    ]
    operations = [migrations.RunPython(enable_mapping_guards, disable_mapping_guards)]
