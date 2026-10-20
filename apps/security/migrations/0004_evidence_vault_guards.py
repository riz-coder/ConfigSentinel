from django.db import migrations


INDIRECT_POLICIES = {
    "evidence_evidencereview": "EXISTS (SELECT 1 FROM evidence_evidenceartifact a WHERE a.id = artifact_id AND a.tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid)",
    "evidence_retentionhold": "EXISTS (SELECT 1 FROM evidence_evidenceartifact a WHERE a.id = artifact_id AND a.tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid)",
    "evidence_custodyevent": "EXISTS (SELECT 1 FROM evidence_evidenceartifact a WHERE a.id = artifact_id AND a.tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid)",
}


def enable_evidence_guards(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    tenant = "tenant_id = nullif(current_setting('configsentinel.tenant_id', true), '')::uuid"
    with schema_editor.connection.cursor() as cursor:
        cursor.execute('ALTER TABLE "evidence_evidenceartifact" ENABLE ROW LEVEL SECURITY')
        cursor.execute('ALTER TABLE "evidence_evidenceartifact" FORCE ROW LEVEL SECURITY')
        cursor.execute(f'CREATE POLICY tenant_isolation ON "evidence_evidenceartifact" USING ({tenant}) WITH CHECK ({tenant})')
        for table, expression in INDIRECT_POLICIES.items():
            cursor.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
            cursor.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
            cursor.execute(f'CREATE POLICY tenant_isolation ON "{table}" USING ({expression}) WITH CHECK ({expression})')
        cursor.execute(
            """
            CREATE FUNCTION configsentinel_guard_evidence_manifest() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
                IF TG_OP = 'DELETE' THEN
                    RAISE EXCEPTION 'evidence manifests cannot be deleted';
                END IF;
                IF (to_jsonb(NEW) - ARRAY['status', 'finalized_at', 'purged_at'])
                    IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['status', 'finalized_at', 'purged_at']) THEN
                    RAISE EXCEPTION 'evidence manifest fields are immutable';
                END IF;
                IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
                    (OLD.status = 'UNDER_REVIEW' AND NEW.status IN ('ACCEPTED', 'REJECTED')) OR
                    (OLD.status = 'ACCEPTED' AND NEW.status = 'STALE')
                ) THEN
                    RAISE EXCEPTION 'invalid evidence status transition';
                END IF;
                IF OLD.finalized_at IS NOT NULL AND NEW.finalized_at IS DISTINCT FROM OLD.finalized_at THEN
                    RAISE EXCEPTION 'evidence finalization is immutable';
                END IF;
                IF OLD.purged_at IS NOT NULL AND NEW.purged_at IS DISTINCT FROM OLD.purged_at THEN
                    RAISE EXCEPTION 'evidence purge marker is immutable';
                END IF;
                RETURN NEW;
            END;
            $$
            """
        )
        cursor.execute(
            """
            CREATE TRIGGER evidence_manifest_immutable
            BEFORE UPDATE OR DELETE ON evidence_evidenceartifact
            FOR EACH ROW EXECUTE FUNCTION configsentinel_guard_evidence_manifest()
            """
        )
        for table, trigger in (("evidence_evidencereview", "evidence_review_append_only"), ("evidence_custodyevent", "custody_event_append_only")):
            cursor.execute(
                f'CREATE TRIGGER {trigger} BEFORE UPDATE OR DELETE ON "{table}" '
                'FOR EACH ROW EXECUTE FUNCTION configsentinel_reject_audit_mutation()'
            )
        cursor.execute(
            """
            CREATE FUNCTION configsentinel_guard_retention_hold() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
                IF TG_OP = 'DELETE' THEN
                    RAISE EXCEPTION 'retention holds cannot be deleted';
                END IF;
                IF OLD.released_at IS NOT NULL THEN
                    RAISE EXCEPTION 'released retention holds are immutable';
                END IF;
                IF (to_jsonb(NEW) - ARRAY['released_by_id', 'released_at', 'release_reason'])
                    IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['released_by_id', 'released_at', 'release_reason']) THEN
                    RAISE EXCEPTION 'applied retention hold fields are immutable';
                END IF;
                RETURN NEW;
            END;
            $$
            """
        )
        cursor.execute(
            """
            CREATE TRIGGER retention_hold_guard
            BEFORE UPDATE OR DELETE ON evidence_retentionhold
            FOR EACH ROW EXECUTE FUNCTION configsentinel_guard_retention_hold()
            """
        )


def disable_evidence_guards(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute('DROP TRIGGER IF EXISTS retention_hold_guard ON "evidence_retentionhold"')
        cursor.execute("DROP FUNCTION IF EXISTS configsentinel_guard_retention_hold()")
        cursor.execute('DROP TRIGGER IF EXISTS custody_event_append_only ON "evidence_custodyevent"')
        cursor.execute('DROP TRIGGER IF EXISTS evidence_review_append_only ON "evidence_evidencereview"')
        cursor.execute('DROP TRIGGER IF EXISTS evidence_manifest_immutable ON "evidence_evidenceartifact"')
        cursor.execute("DROP FUNCTION IF EXISTS configsentinel_guard_evidence_manifest()")
        for table in ("evidence_evidenceartifact", *INDIRECT_POLICIES.keys()):
            cursor.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
            cursor.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
            cursor.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')


class Migration(migrations.Migration):
    dependencies = [("evidence", "0001_initial"), ("security", "0003_control_mapping_guards")]
    operations = [migrations.RunPython(enable_evidence_guards, disable_evidence_guards)]
