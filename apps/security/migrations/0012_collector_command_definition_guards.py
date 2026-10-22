from django.db import migrations


def enable_guards(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    tenant = "tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid"
    with schema_editor.connection.cursor() as cursor:
        cursor.execute('ALTER TABLE "collector_commanddefinition" ENABLE ROW LEVEL SECURITY')
        cursor.execute('ALTER TABLE "collector_commanddefinition" FORCE ROW LEVEL SECURITY')
        cursor.execute(f'CREATE POLICY tenant_isolation ON "collector_commanddefinition" USING ({tenant}) WITH CHECK ({tenant})')
        cursor.execute(
            """
            CREATE FUNCTION configsentinel_guard_command_definition() RETURNS trigger LANGUAGE plpgsql AS $$
            DECLARE profile_status text;
            BEGIN
                SELECT status INTO profile_status FROM collector_commandprofile WHERE id = OLD.profile_id;
                IF profile_status <> 'DRAFT' THEN
                    RAISE EXCEPTION 'approved command definitions are immutable';
                END IF;
                RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
            END; $$
            """
        )
        cursor.execute("CREATE TRIGGER command_definition_guard BEFORE UPDATE OR DELETE ON collector_commanddefinition FOR EACH ROW EXECUTE FUNCTION configsentinel_guard_command_definition()")


def disable_guards(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute("DROP TRIGGER IF EXISTS command_definition_guard ON collector_commanddefinition")
        cursor.execute("DROP FUNCTION IF EXISTS configsentinel_guard_command_definition()")
        cursor.execute('DROP POLICY IF EXISTS tenant_isolation ON "collector_commanddefinition"')
        cursor.execute('ALTER TABLE "collector_commanddefinition" NO FORCE ROW LEVEL SECURITY')
        cursor.execute('ALTER TABLE "collector_commanddefinition" DISABLE ROW LEVEL SECURITY')


class Migration(migrations.Migration):
    dependencies = [("collector", "0002_device_asset_device_telnet_approved_at_and_more"), ("security", "0011_inventory_rls")]
    operations = [migrations.RunPython(enable_guards, disable_guards)]
