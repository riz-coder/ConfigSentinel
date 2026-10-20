import base64
import tempfile
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone
from django_otp.plugins.otp_totp.models import TOTPDevice
from rest_framework.test import APIClient

from apps.auditlog.models import AuditEvent
from apps.regulatory.models import (
    ControlDefinition, EvidenceRequirement, LegalSourceStatus, Obligation,
    ObligationControlMapping, Regulation, RegulatorySource, RegulatoryVersion,
    SubClause, TestProcedure,
)
from apps.tenancy.models import Membership, Tenant
from apps.tenancy.rls import set_rls_context

from .models import CustodyEvent, EvidenceArtifact, EvidenceReview, EvidenceStatus
from .services import apply_hold, purge_ciphertext, release_hold, retrieve_evidence, review_evidence, upload_evidence
from .vault import EvidenceIntegrityError, LocalEncryptedObjectStore, VaultConfigurationError, VaultError


class EvidenceVaultTests(TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.settings_override = self.settings(
            EVIDENCE_STORAGE_ROOT=Path(self.temp_dir.name),
            EVIDENCE_MASTER_KEY=base64.b64encode(b"k" * 32).decode(),
            EVIDENCE_MAX_UPLOAD_BYTES=1024,
        )
        self.settings_override.enable()
        users = get_user_model().objects
        self.owner = users.create_user(username="evidence-owner", password="test-password")
        self.compliance = users.create_user(username="evidence-reviewer", password="test-password")
        self.auditor = users.create_user(username="evidence-auditor", password="test-password")
        self.tenant = Tenant.objects.create(name="Evidence tenant", slug="evidence-tenant")
        Membership.objects.create(user=self.owner, tenant=self.tenant, role=Membership.Role.OWNER)
        Membership.objects.create(user=self.compliance, tenant=self.tenant, role=Membership.Role.COMPLIANCE_LEAD)
        Membership.objects.create(user=self.auditor, tenant=self.tenant, role=Membership.Role.AUDITOR)
        set_rls_context(user_id=self.owner.pk, tenant_id=self.tenant.pk)
        self.mapping = self._mapping(self.tenant, self.owner, "A")

    def tearDown(self):
        self.settings_override.disable()
        self.temp_dir.cleanup()

    def _mapping(self, tenant, actor, suffix):
        now = timezone.now()
        source = RegulatorySource.objects.create(
            tenant=tenant, title=f"Verified source {suffix}", authority_url=f"https://example.gov.pk/{suffix}.pdf",
            gazette_identifier=f"EVID-{suffix}", sha256=(suffix.lower()[0] if suffix[0].lower() in "abcdef" else "a") * 64,
            legal_status=LegalSourceStatus.VERIFIED, reviewed_by=actor, reviewed_at=now,
            verification_completed_at=now,
        )
        version = RegulatoryVersion.objects.create(source=source, version_label="1", approval_status=RegulatoryVersion.ApprovalStatus.APPROVED)
        regulation = Regulation.objects.create(version=version, number=1, title="Test", source_page="1", legal_status=LegalSourceStatus.VERIFIED)
        clause = SubClause.objects.create(regulation=regulation, clause_path="1", title="Test", source_page="1", legal_status=LegalSourceStatus.VERIFIED)
        obligation = Obligation.objects.create(subclause=clause, obligation_key="TEST", paraphrase="Synthetic test", requirement_type="TEST", legal_status=LegalSourceStatus.VERIFIED)
        control = ControlDefinition.objects.create(tenant=tenant, control_key=f"CTRL-{suffix}", version=1, title="Test", description="Test", created_by=actor)
        procedure = TestProcedure.objects.create(tenant=tenant, control=control, procedure_key=f"PROC-{suffix}", version=1, title="Test", procedure="Inspect", expected_result="Documented", created_by=actor)
        requirement = EvidenceRequirement.objects.create(
            tenant=tenant, test_procedure=procedure, requirement_key=f"REQ-{suffix}", version=1,
            title="Test", description="Synthetic evidence", retention_days=1, freshness_days=1, created_by=actor,
        )
        return ObligationControlMapping.objects.create(
            tenant=tenant, obligation=obligation, control=control, test_procedure=procedure,
            evidence_requirement=requirement, rationale="Synthetic approved mapping",
            status=ObligationControlMapping.Status.APPROVED, created_by=actor, finalized_at=now,
        )

    def upload(self, content=b"synthetic evidence bytes", actor=None, filename="evidence.txt", media_type="text/plain"):
        return upload_evidence(
            tenant=self.tenant, actor=actor or self.owner, mapping=self.mapping, title="Synthetic artifact",
            filename=filename, media_type=media_type, content=content,
        )

    def api_client(self, user):
        client = APIClient()
        device = TOTPDevice.objects.create(user=user, name=f"evidence-{user.pk}", confirmed=True)
        client.force_login(user)
        session = client.session
        session["otp_device_id"] = device.persistent_id
        session.save()
        return client

    def test_round_trip_stores_only_ciphertext_and_records_custody(self):
        plaintext = b"synthetic confidential evidence"
        artifact = self.upload(plaintext)
        path = Path(self.temp_dir.name) / artifact.storage_key
        self.assertTrue(path.exists())
        self.assertNotEqual(path.read_bytes(), plaintext)
        self.assertNotIn(plaintext, path.read_bytes())
        self.assertEqual(retrieve_evidence(artifact=artifact, actor=self.owner), plaintext)
        self.assertEqual(list(artifact.custody_events.values_list("kind", flat=True)), ["UPLOADED", "DOWNLOADED"])

    def test_ciphertext_tamper_fails_without_returning_plaintext(self):
        artifact = self.upload()
        path = Path(self.temp_dir.name) / artifact.storage_key
        path.write_bytes(path.read_bytes()[:-1] + b"x")
        with self.assertRaises(EvidenceIntegrityError):
            retrieve_evidence(artifact=artifact, actor=self.owner)
        self.assertEqual(artifact.custody_events.filter(kind=CustodyEvent.Kind.DOWNLOADED).count(), 0)

    def test_tenant_or_artifact_metadata_swap_fails_authentication(self):
        artifact = self.upload()
        artifact.id = EvidenceArtifact().id
        with self.assertRaises(EvidenceIntegrityError):
            LocalEncryptedObjectStore().retrieve_and_verify(artifact)

    def test_missing_or_invalid_master_key_fails_closed(self):
        with self.settings(EVIDENCE_MASTER_KEY="not-base64"):
            with self.assertRaises(VaultConfigurationError):
                self.upload()
        self.assertEqual(EvidenceArtifact.objects.count(), 0)
        self.assertEqual(list(Path(self.temp_dir.name).rglob("*.blob")), [])

    def test_unsupported_oversized_and_path_filename_fail_safely(self):
        with self.assertRaises(ValidationError):
            self.upload(media_type="application/x-msdownload")
        with self.assertRaises(VaultError):
            self.upload(content=b"x" * 1025)
        artifact = self.upload(filename="../../secret.txt")
        self.assertEqual(artifact.original_filename, "secret.txt")

    def test_uploader_cannot_review_and_independent_review_verifies_integrity(self):
        artifact = self.upload()
        Membership.objects.filter(user=self.owner, tenant=self.tenant).update(role=Membership.Role.COMPLIANCE_LEAD)
        with self.assertRaises(ValidationError):
            review_evidence(artifact=artifact, reviewer=self.owner, decision=EvidenceReview.Decision.ACCEPTED, note="self")
        review_evidence(artifact=artifact, reviewer=self.auditor, decision=EvidenceReview.Decision.ACCEPTED, note="Synthetic review")
        artifact.refresh_from_db()
        self.assertEqual(artifact.status, EvidenceStatus.ACCEPTED)
        self.assertTrue(artifact.custody_events.filter(kind=CustodyEvent.Kind.INTEGRITY_VERIFIED).exists())

    def test_tampered_artifact_cannot_be_accepted(self):
        artifact = self.upload()
        path = Path(self.temp_dir.name) / artifact.storage_key
        path.write_bytes(b"tampered")
        with self.assertRaises(EvidenceIntegrityError):
            review_evidence(artifact=artifact, reviewer=self.compliance, decision=EvidenceReview.Decision.ACCEPTED, note="No")
        artifact.refresh_from_db()
        self.assertEqual(artifact.status, EvidenceStatus.UNDER_REVIEW)
        self.assertFalse(EvidenceReview.objects.filter(artifact=artifact).exists())

    def test_expired_accepted_evidence_reports_stale(self):
        artifact = self.upload()
        review_evidence(artifact=artifact, reviewer=self.compliance, decision=EvidenceReview.Decision.ACCEPTED, note="Accepted")
        artifact.refresh_from_db()
        with patch("apps.evidence.models.timezone.now", return_value=timezone.now() + timedelta(days=2)):
            self.assertEqual(artifact.effective_status, EvidenceStatus.STALE)

    def test_stale_command_persists_and_audits_expiry(self):
        old_now = timezone.now() - timedelta(days=2)
        with patch("apps.evidence.services.timezone.now", return_value=old_now):
            artifact = self.upload()
        review_evidence(artifact=artifact, reviewer=self.compliance, decision=EvidenceReview.Decision.ACCEPTED, note="Accepted")
        call_command("mark_stale_evidence")
        artifact.refresh_from_db()
        self.assertEqual(artifact.status, EvidenceStatus.STALE)
        self.assertTrue(artifact.custody_events.filter(kind=CustodyEvent.Kind.STALE_MARKED).exists())

    def test_retention_and_hold_block_purge_then_released_hold_allows_it(self):
        artifact = self.upload()
        future = timezone.now() + timedelta(days=2)
        with self.assertRaises(ValidationError):
            purge_ciphertext(artifact=artifact, actor=self.owner)
        hold = apply_hold(artifact=artifact, actor=self.auditor, reason="Synthetic audit hold")
        with self.assertRaises(ValidationError):
            purge_ciphertext(artifact=artifact, actor=self.owner, now=future)
        release_hold(hold=hold, actor=self.owner, reason="Synthetic audit completed")
        purge_ciphertext(artifact=artifact, actor=self.owner, now=future)
        artifact.refresh_from_db()
        self.assertIsNotNone(artifact.purged_at)
        self.assertFalse((Path(self.temp_dir.name) / artifact.storage_key).exists())
        self.assertTrue(EvidenceArtifact.objects.filter(pk=artifact.pk).exists())

    def test_cross_tenant_api_upload_is_denied_and_audited(self):
        other = Tenant.objects.create(name="Other evidence", slug="other-evidence")
        Membership.objects.create(user=self.owner, tenant=other, role=Membership.Role.OWNER)
        set_rls_context(user_id=self.owner.pk, tenant_id=other.pk)
        foreign_mapping = self._mapping(other, self.owner, "B")
        set_rls_context(user_id=self.owner.pk, tenant_id=self.tenant.pk)
        response = self.api_client(self.owner).post("/api/v1/evidence/", {
            "mapping": str(foreign_mapping.pk), "title": "Denied",
            "file": SimpleUploadedFile("denied.txt", b"not stored", content_type="text/plain"),
        }, format="multipart")
        self.assertEqual(response.status_code, 400)
        self.assertTrue(AuditEvent.objects.filter(tenant=self.tenant, action="evidence.upload_denied").exists())

    def test_cross_tenant_download_is_denied_and_audited(self):
        other = Tenant.objects.create(name="Other download", slug="other-download")
        Membership.objects.create(user=self.owner, tenant=other, role=Membership.Role.OWNER)
        set_rls_context(user_id=self.owner.pk, tenant_id=other.pk)
        mapping = self._mapping(other, self.owner, "C")
        foreign = upload_evidence(
            tenant=other, actor=self.owner, mapping=mapping, title="Foreign",
            filename="foreign.txt", media_type="text/plain", content=b"foreign",
        )
        set_rls_context(user_id=self.owner.pk, tenant_id=self.tenant.pk)
        response = self.api_client(self.owner).get(f"/api/v1/evidence/{foreign.pk}/download/")
        self.assertEqual(response.status_code, 404)
        self.assertTrue(AuditEvent.objects.filter(tenant=self.tenant, action="evidence.download_denied").exists())

    def test_api_download_uses_opaque_attachment_name_and_no_store(self):
        artifact = self.upload(filename="customer-secret-name.txt")
        response = self.api_client(self.owner).get(f"/api/v1/evidence/{artifact.pk}/download/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"synthetic evidence bytes")
        self.assertNotIn("customer-secret-name", response["Content-Disposition"])
        self.assertEqual(response["Cache-Control"], "no-store")

    def test_evidence_center_renders_without_sensitive_content(self):
        artifact = self.upload(content=b"never render this raw content")
        response = self.api_client(self.owner).get("/evidence/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Encrypted evidence vault")
        self.assertNotContains(response, "never render this raw content")
        self.assertContains(response, artifact.plaintext_sha256)
