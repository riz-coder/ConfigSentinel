from django.db import migrations


TABLES = ("collector_commandexecution", "collector_rawsnapshot")


def enable_guards(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    tenant = "tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid"
    with schema_editor.connection.cursor() as cursor:
        for table in TABLES:
            cursor.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
            cursor.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
            cursor.execute(f'CREATE POLICY tenant_isolation ON "{table}" USING ({tenant}) WITH CHECK ({tenant})')
        cursor.execute("DROP TRIGGER IF EXISTS collection_job_append_only ON collector_collectionjob")
        cursor.execute(
            """
            CREATE FUNCTION configsentinel_guard_collection_job() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'collection jobs cannot be deleted'; END IF;
                IF (to_jsonb(NEW) - ARRAY['state','technical_result','failure_reason','claimed_at','started_at','finished_at','collector_version','discovered_vendor','discovered_platform','discovered_model','discovered_release'])
                   IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['state','technical_result','failure_reason','claimed_at','started_at','finished_at','collector_version','discovered_vendor','discovered_platform','discovered_model','discovered_release']) THEN
                    RAISE EXCEPTION 'immutable collection job fields changed';
                END IF;
                IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
                    (OLD.state='QUEUED' AND NEW.state IN ('PREFLIGHT','FAILED','CANCELLED')) OR
                    (OLD.state='PREFLIGHT' AND NEW.state IN ('CAPABILITY_PROBE','FAILED','TIMED_OUT')) OR
                    (OLD.state='CAPABILITY_PROBE' AND NEW.state IN ('COLLECTING','FAILED','PARTIAL','TIMED_OUT')) OR
                    (OLD.state='COLLECTING' AND NEW.state IN ('PARSING','FAILED','PARTIAL','TIMED_OUT')) OR
                    (OLD.state='PARSING' AND NEW.state IN ('ASSESSING','FAILED','PARTIAL')) OR
                    (OLD.state='ASSESSING' AND NEW.state IN ('COMPLETE','FAILED','PARTIAL'))
                ) THEN RAISE EXCEPTION 'invalid collection job state transition'; END IF;
                RETURN NEW;
            END; $$
            """
        )
        cursor.execute("CREATE TRIGGER collection_job_guard BEFORE UPDATE OR DELETE ON collector_collectionjob FOR EACH ROW EXECUTE FUNCTION configsentinel_guard_collection_job()")
        cursor.execute(
            """
            CREATE FUNCTION configsentinel_guard_command_execution() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'command executions cannot be deleted'; END IF;
                IF OLD.state <> 'PLANNED' THEN RAISE EXCEPTION 'completed command executions are immutable'; END IF;
                IF (to_jsonb(NEW) - ARRAY['state','reason','output_size_bytes','output_sha256','started_at','finished_at'])
                   IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['state','reason','output_size_bytes','output_sha256','started_at','finished_at']) THEN
                    RAISE EXCEPTION 'immutable command execution fields changed';
                END IF;
                RETURN NEW;
            END; $$
            """
        )
        cursor.execute("CREATE TRIGGER command_execution_guard BEFORE UPDATE OR DELETE ON collector_commandexecution FOR EACH ROW EXECUTE FUNCTION configsentinel_guard_command_execution()")
        cursor.execute("CREATE TRIGGER raw_snapshot_append_only BEFORE UPDATE OR DELETE ON collector_rawsnapshot FOR EACH ROW EXECUTE FUNCTION configsentinel_reject_audit_mutation()")


def disable_guards(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute("DROP TRIGGER IF EXISTS raw_snapshot_append_only ON collector_rawsnapshot")
        cursor.execute("DROP TRIGGER IF EXISTS command_execution_guard ON collector_commandexecution")
        cursor.execute("DROP FUNCTION IF EXISTS configsentinel_guard_command_execution()")
        cursor.execute("DROP TRIGGER IF EXISTS collection_job_guard ON collector_collectionjob")
        cursor.execute("DROP FUNCTION IF EXISTS configsentinel_guard_collection_job()")
        cursor.execute("CREATE TRIGGER collection_job_append_only BEFORE UPDATE OR DELETE ON collector_collectionjob FOR EACH ROW EXECUTE FUNCTION configsentinel_reject_audit_mutation()")
        for table in TABLES:
            cursor.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
            cursor.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
            cursor.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')


class Migration(migrations.Migration):
    dependencies = [("collector", "0004_commandexecution_rawsnapshot_and_more"), ("security", "0012_collector_command_definition_guards")]
    operations = [migrations.RunPython(enable_guards, disable_guards)]
