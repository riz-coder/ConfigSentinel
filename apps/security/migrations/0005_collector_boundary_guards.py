from django.db import migrations


TABLES = (
    "collector_device", "collector_credentialreference", "collector_collectoragent",
    "collector_commandprofile", "collector_scopegrant", "collector_collectionjob",
)


def enable_guards(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    tenant = "tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid"
    with schema_editor.connection.cursor() as cursor:
        for table in TABLES:
            cursor.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
            cursor.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
            cursor.execute(f'CREATE POLICY tenant_isolation ON "{table}" USING ({tenant}) WITH CHECK ({tenant})')
        cursor.execute(
            """
            CREATE FUNCTION configsentinel_guard_scope_grant() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'scope grants cannot be deleted'; END IF;
                IF (to_jsonb(NEW) - ARRAY['status','approved_by_id','approved_at','revoked_at'])
                   IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['status','approved_by_id','approved_at','revoked_at']) THEN
                    RAISE EXCEPTION 'authorized scope fields are immutable';
                END IF;
                IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
                    (OLD.status = 'DRAFT' AND NEW.status = 'APPROVED') OR
                    (OLD.status = 'APPROVED' AND NEW.status = 'REVOKED')) THEN
                    RAISE EXCEPTION 'invalid scope transition';
                END IF;
                RETURN NEW;
            END; $$
            """
        )
        cursor.execute("CREATE TRIGGER scope_grant_guard BEFORE UPDATE OR DELETE ON collector_scopegrant FOR EACH ROW EXECUTE FUNCTION configsentinel_guard_scope_grant()")
        cursor.execute("CREATE TRIGGER collection_job_append_only BEFORE UPDATE OR DELETE ON collector_collectionjob FOR EACH ROW EXECUTE FUNCTION configsentinel_reject_audit_mutation()")


def disable_guards(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute("DROP TRIGGER IF EXISTS collection_job_append_only ON collector_collectionjob")
        cursor.execute("DROP TRIGGER IF EXISTS scope_grant_guard ON collector_scopegrant")
        cursor.execute("DROP FUNCTION IF EXISTS configsentinel_guard_scope_grant()")
        for table in TABLES:
            cursor.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
            cursor.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
            cursor.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')


class Migration(migrations.Migration):
    dependencies = [("collector", "0001_initial"), ("security", "0004_evidence_vault_guards")]
    operations = [migrations.RunPython(enable_guards, disable_guards)]
