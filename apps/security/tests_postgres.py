from django.contrib.auth import get_user_model
from django.db import DatabaseError, connection, transaction
from django.test import TransactionTestCase, skipUnlessDBFeature
from django.utils import timezone

from apps.auditlog.models import AuditEvent
import base64

from apps.regulatory.models import (
    ControlDefinition, EvidenceRequirement, LegalSourceStatus, Obligation,
    ObligationControlMapping, Regulation, RegulatorySource, RegulatoryVersion,
    SubClause, TestProcedure, TrustedSigningKey,
)
from apps.tenancy.models import Tenant
from apps.tenancy.rls import set_rls_context


class PostgreSQLBoundaryTests(TransactionTestCase):
    @skipUnlessDBFeature("supports_transactions")
    def test_forced_rls_hides_and_rejects_cross_tenant_rows(self):
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL-specific RLS test")
        alpha = Tenant.objects.create(name="RLS Alpha", slug="rls-alpha")
        beta = Tenant.objects.create(name="RLS Beta", slug="rls-beta")
        with transaction.atomic():
            set_rls_context(tenant_id=alpha.pk)
            source = RegulatorySource.objects.create(tenant=alpha, title="Alpha confidential source")
            set_rls_context(tenant_id=beta.pk)
            self.assertFalse(RegulatorySource.objects.filter(pk=source.pk).exists())
            with self.assertRaises(DatabaseError), transaction.atomic():
                RegulatorySource.objects.create(tenant=alpha, title="Blocked cross-tenant write")

    @skipUnlessDBFeature("supports_transactions")
    def test_pack_tables_inherit_forced_tenant_boundary(self):
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL-specific RLS test")
        alpha = Tenant.objects.create(name="Pack RLS Alpha", slug="pack-rls-alpha")
        beta = Tenant.objects.create(name="Pack RLS Beta", slug="pack-rls-beta")
        with transaction.atomic():
            set_rls_context(tenant_id=alpha.pk)
            key = TrustedSigningKey.objects.create(tenant=alpha, name="Alpha key", public_key_base64=base64.b64encode(b"a" * 32).decode())
            source = RegulatorySource.objects.create(tenant=alpha, title="Alpha pack")
            version = RegulatoryVersion.objects.create(source=source, version_label="test")
            regulation = Regulation.objects.create(version=version, number=1)
            clause = SubClause.objects.create(regulation=regulation, clause_path="1.1", title="Test", source_page="1")
            set_rls_context(tenant_id=beta.pk)
            self.assertFalse(TrustedSigningKey.objects.filter(pk=key.pk).exists())
            self.assertFalse(SubClause.objects.filter(pk=clause.pk).exists())

    @skipUnlessDBFeature("supports_transactions")
    def test_mapping_rls_and_finalized_database_guard(self):
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL-specific mapping guard test")
        user = get_user_model().objects.create_user(username="mapping-db-guard")
        alpha = Tenant.objects.create(name="Mapping DB Alpha", slug="mapping-db-alpha")
        beta = Tenant.objects.create(name="Mapping DB Beta", slug="mapping-db-beta")
        with transaction.atomic():
            set_rls_context(user_id=user.pk, tenant_id=alpha.pk)
            now = timezone.now()
            source = RegulatorySource.objects.create(
                tenant=alpha, title="Verified DB source", authority_url="https://example.gov.pk/db.pdf",
                gazette_identifier="DB-GUARD", sha256="c" * 64, legal_status=LegalSourceStatus.VERIFIED,
                reviewed_by=user, reviewed_at=now, verification_completed_at=now,
            )
            version = RegulatoryVersion.objects.create(source=source, version_label="db", approval_status=RegulatoryVersion.ApprovalStatus.APPROVED)
            regulation = Regulation.objects.create(version=version, number=1, source_page="1", legal_status=LegalSourceStatus.VERIFIED)
            clause = SubClause.objects.create(regulation=regulation, clause_path="1", title="DB", source_page="1", legal_status=LegalSourceStatus.VERIFIED)
            obligation = Obligation.objects.create(subclause=clause, obligation_key="DB", paraphrase="DB test", requirement_type="TEST", legal_status=LegalSourceStatus.VERIFIED)
            control = ControlDefinition.objects.create(tenant=alpha, control_key="DB", version=1, title="DB", description="DB", created_by=user)
            procedure = TestProcedure.objects.create(tenant=alpha, control=control, procedure_key="DB", version=1, title="DB", procedure="DB", expected_result="DB", created_by=user)
            requirement = EvidenceRequirement.objects.create(tenant=alpha, test_procedure=procedure, requirement_key="DB", version=1, title="DB", description="DB", created_by=user)
            mapping = ObligationControlMapping.objects.create(tenant=alpha, obligation=obligation, control=control, test_procedure=procedure, evidence_requirement=requirement, rationale="DB guard", created_by=user)
            ObligationControlMapping.objects.filter(pk=mapping.pk).update(status=ObligationControlMapping.Status.APPROVED, finalized_at=now)
            with self.assertRaises(DatabaseError), transaction.atomic():
                ObligationControlMapping.objects.filter(pk=mapping.pk).update(rationale="tampered")
            set_rls_context(user_id=user.pk, tenant_id=beta.pk)
            self.assertFalse(ControlDefinition.objects.filter(pk=control.pk).exists())
            self.assertFalse(ObligationControlMapping.objects.filter(pk=mapping.pk).exists())

    @skipUnlessDBFeature("supports_transactions")
    def test_database_trigger_rejects_raw_audit_mutation(self):
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL-specific audit trigger test")
        user = get_user_model().objects.create_user(username="db-guard")
        tenant = Tenant.objects.create(name="Audit Guard", slug="audit-guard")
        with transaction.atomic():
            set_rls_context(user_id=user.pk, tenant_id=tenant.pk)
            event = AuditEvent.objects.create(
                tenant=tenant, actor=user, action="guard.created", object_type="Guard", object_id="1"
            )
            with connection.cursor() as cursor:
                cursor.execute("UPDATE auditlog_auditevent SET action = %s WHERE id = %s", ["tampered", event.pk])
                self.assertEqual(cursor.rowcount, 0, "Default-deny RLS must block audit updates before the trigger")
                cursor.execute(
                    "SELECT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'audit_event_append_only' AND NOT tgisinternal)"
                )
                self.assertTrue(cursor.fetchone()[0], "Append-only database trigger must be installed")
            event.refresh_from_db()
            self.assertEqual(event.action, "guard.created")
