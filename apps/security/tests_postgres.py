from django.contrib.auth import get_user_model
from django.db import DatabaseError, connection, transaction
from django.test import TransactionTestCase, skipUnlessDBFeature
from django.utils import timezone

from apps.auditlog.models import AuditEvent
from apps.evidence.models import CustodyEvent, EvidenceArtifact
from apps.collector.models import CommandProfile, Device
from apps.inventory.models import Site
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
    def test_approved_command_profile_target_is_database_immutable(self):
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL-specific command-profile guard test")
        user = get_user_model().objects.create_user(username="profile-db-guard")
        tenant = Tenant.objects.create(name="Profile Guard", slug="profile-guard")
        with transaction.atomic():
            set_rls_context(user_id=user.pk, tenant_id=tenant.pk)
            profile = CommandProfile.objects.create(
                tenant=tenant, name="Reviewed profile", vendor=Device.Vendor.CISCO,
                platform="IOS_IOS_XE", target_model="WS-C4948E-F", version=3,
                manifest_sha256="a" * 64, command_count=1, status=CommandProfile.Status.APPROVED,
                created_by=user, approved_by=user, approved_at=timezone.now(), approval_reference="TEST-REVIEW",
            )
            with self.assertRaises(DatabaseError), transaction.atomic():
                CommandProfile.objects.filter(pk=profile.pk).update(target_model="OTHER")

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
            mapping.refresh_from_db()
            artifact = EvidenceArtifact.objects.create(
                tenant=alpha, mapping=mapping, requirement=requirement, title="DB evidence", original_filename="db.txt",
                media_type="text/plain", size_bytes=2, plaintext_sha256="a" * 64, ciphertext_sha256="b" * 64,
                storage_key="objects/db/db.blob", wrapped_dek="wrapped", wrap_nonce="nonce",
                content_nonce="nonce", uploaded_by=user,
            )
            event = CustodyEvent.objects.create(artifact=artifact, actor=user, kind=CustodyEvent.Kind.UPLOADED)
            with self.assertRaises(DatabaseError), transaction.atomic():
                EvidenceArtifact.objects.filter(pk=artifact.pk).update(title="tampered")
            with self.assertRaises(DatabaseError), transaction.atomic():
                CustodyEvent.objects.filter(pk=event.pk).update(kind=CustodyEvent.Kind.DOWNLOADED)
            set_rls_context(user_id=user.pk, tenant_id=beta.pk)
            self.assertFalse(ControlDefinition.objects.filter(pk=control.pk).exists())
            self.assertFalse(ObligationControlMapping.objects.filter(pk=mapping.pk).exists())
            self.assertFalse(EvidenceArtifact.objects.filter(pk=artifact.pk).exists())

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

    @skipUnlessDBFeature("supports_transactions")
    def test_collector_device_rls_boundary(self):
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL-specific collector RLS test")
        user = get_user_model().objects.create_user(username="collector-db-guard")
        alpha = Tenant.objects.create(name="Collector DB Alpha", slug="collector-db-alpha")
        beta = Tenant.objects.create(name="Collector DB Beta", slug="collector-db-beta")
        with transaction.atomic():
            set_rls_context(user_id=user.pk, tenant_id=alpha.pk)
            device = Device.objects.create(
                tenant=alpha, name="Synthetic device", vendor=Device.Vendor.CISCO,
                platform="NX-OS", management_address="192.0.2.44",
                pinned_host_key_sha256="SHA256:synthetic-db-fingerprint", created_by=user,
            )
            set_rls_context(user_id=user.pk, tenant_id=beta.pk)
            self.assertFalse(Device.objects.filter(pk=device.pk).exists())
            with self.assertRaises(DatabaseError), transaction.atomic():
                Device.objects.create(
                    tenant=alpha, name="Blocked device", vendor=Device.Vendor.CISCO,
                    platform="NX-OS", management_address="192.0.2.45",
                    pinned_host_key_sha256="SHA256:blocked-db-fingerprint", created_by=user,
                )

    @skipUnlessDBFeature("supports_transactions")
    def test_inventory_site_rls_boundary(self):
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL-specific inventory RLS test")
        user = get_user_model().objects.create_user(username="inventory-db-guard")
        alpha = Tenant.objects.create(name="Inventory DB Alpha", slug="inventory-db-alpha")
        beta = Tenant.objects.create(name="Inventory DB Beta", slug="inventory-db-beta")
        with transaction.atomic():
            set_rls_context(user_id=user.pk, tenant_id=alpha.pk)
            site = Site.objects.create(tenant=alpha, code="A", name="Alpha site", kind=Site.Kind.POP, created_by=user)
            set_rls_context(user_id=user.pk, tenant_id=beta.pk)
            self.assertFalse(Site.objects.filter(pk=site.pk).exists())
            with self.assertRaises(DatabaseError), transaction.atomic():
                Site.objects.create(tenant=alpha, code="B", name="Blocked", kind=Site.Kind.OTHER, created_by=user)
