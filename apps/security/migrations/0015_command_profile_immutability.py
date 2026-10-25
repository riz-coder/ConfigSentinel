from django.db import migrations


def enable_guard(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            """
            CREATE FUNCTION configsentinel_guard_command_profile() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF TG_OP = 'DELETE' AND OLD.status <> 'DRAFT' THEN
                    RAISE EXCEPTION 'approved command profiles cannot be deleted';
                END IF;
                IF TG_OP = 'UPDATE' AND OLD.status <> 'DRAFT' AND (
                    NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
                    NEW.name IS DISTINCT FROM OLD.name OR
                    NEW.vendor IS DISTINCT FROM OLD.vendor OR
                    NEW.platform IS DISTINCT FROM OLD.platform OR
                    NEW.target_model IS DISTINCT FROM OLD.target_model OR
                    NEW.version IS DISTINCT FROM OLD.version OR
                    NEW.manifest_sha256 IS DISTINCT FROM OLD.manifest_sha256 OR
                    NEW.command_count IS DISTINCT FROM OLD.command_count OR
                    NEW.created_by_id IS DISTINCT FROM OLD.created_by_id
                ) THEN
                    RAISE EXCEPTION 'approved command profile manifests and targets are immutable';
                END IF;
                RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
            END; $$
            """
        )
        cursor.execute("CREATE TRIGGER command_profile_guard BEFORE UPDATE OR DELETE ON collector_commandprofile FOR EACH ROW EXECUTE FUNCTION configsentinel_guard_command_profile()")


def disable_guard(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute("DROP TRIGGER IF EXISTS command_profile_guard ON collector_commandprofile")
        cursor.execute("DROP FUNCTION IF EXISTS configsentinel_guard_command_profile()")


class Migration(migrations.Migration):
    dependencies = [("collector", "0008_commandprofile_target_model"), ("security", "0014_collector_assessment_guards")]
    operations = [migrations.RunPython(enable_guard, disable_guard)]
