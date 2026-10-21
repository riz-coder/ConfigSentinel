import base64
import tempfile
from pathlib import Path

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.test import TestCase
from django_otp.plugins.otp_totp.models import TOTPDevice

from apps.tenancy.models import Membership, Tenant

from .models import ClauseAuditAssessment, ClauseEvidence, Regulation, RegulatorySource, RegulatoryVersion, SubClause
from .services import assess_clause, review_clause_evidence, upload_clause_evidence


class ClauseAuditorWorkflowTests(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.override = self.settings(
            EVIDENCE_STORAGE_ROOT=Path(self.temp.name),
            EVIDENCE_MASTER_KEY=base64.b64encode(b"a" * 32).decode(),
        )
        self.override.enable()
        users = get_user_model().objects
        self.owner = users.create_user(username="assessment-owner", password="test-password")
        self.auditor = users.create_user(username="independent-auditor", password="test-password")
        self.other = users.create_user(username="unassigned-reviewer", password="test-password")
        self.tenant = Tenant.objects.create(name="Assessment tenant", slug="assessment-tenant")
        Membership.objects.create(user=self.owner, tenant=self.tenant, role=Membership.Role.OWNER)
        Membership.objects.create(user=self.auditor, tenant=self.tenant, role=Membership.Role.AUDITOR)
        source = RegulatorySource.objects.create(tenant=self.tenant, title="Supplied source", sha256="a" * 64)
        version = RegulatoryVersion.objects.create(source=source, version_label="v1", approval_status=RegulatoryVersion.ApprovalStatus.UNDER_REVIEW)
        regulation = Regulation.objects.create(version=version, number=1, title="Synthetic clause", source_page="1", source_excerpt="Source text")
        self.clause = SubClause.objects.create(regulation=regulation, clause_path="1", title="Synthetic clause", source_page="1")
        self.artifact = upload_clause_evidence(
            tenant=self.tenant, actor=self.owner, subclause=self.clause, title="Policy",
            filename="policy.txt", content=b"Synthetic approved policy evidence without sensitive data.",
        )

    def tearDown(self):
        self.override.disable()
        self.temp.cleanup()

    def test_auditor_reviews_file_then_records_legal_unverified_assessment(self):
        review_clause_evidence(
            artifact=self.artifact, reviewer=self.auditor,
            decision=ClauseEvidence.Status.ACCEPTED, note="Integrity and relevance checked.",
        )
        assessment = assess_clause(
            subclause=self.clause, reviewer=self.auditor,
            decision=ClauseAuditAssessment.Decision.ACCEPT,
            note="Evidence set is sufficient for audit review.",
        )

        self.artifact.refresh_from_db()
        self.assertEqual(self.artifact.status, ClauseEvidence.Status.ACCEPTED)
        self.assertEqual(assessment.compliance_status, ClauseAuditAssessment.ComplianceStatus.LEGAL_UNVERIFIED)
        self.assertEqual(assessment.evidence_snapshot[0]["sha256"], self.artifact.plaintext_sha256)

    def test_accept_clause_requires_all_active_files_to_be_accepted(self):
        with self.assertRaisesMessage(ValidationError, "Every active evidence file"):
            assess_clause(
                subclause=self.clause, reviewer=self.auditor,
                decision=ClauseAuditAssessment.Decision.ACCEPT, note="Premature acceptance.",
            )

    def test_only_auditor_can_review_and_review_is_immutable(self):
        with self.assertRaises(PermissionDenied):
            review_clause_evidence(
                artifact=self.artifact, reviewer=self.owner,
                decision=ClauseEvidence.Status.ACCEPTED, note="Self review.",
            )
        with self.assertRaises(PermissionDenied):
            review_clause_evidence(
                artifact=self.artifact, reviewer=self.other,
                decision=ClauseEvidence.Status.ACCEPTED, note="No membership.",
            )
        review = review_clause_evidence(
            artifact=self.artifact, reviewer=self.auditor,
            decision=ClauseEvidence.Status.REJECTED, note="Wrong reporting period.",
        )
        review.note = "Changed"
        with self.assertRaisesMessage(ValidationError, "append-only"):
            review.save()

    def test_request_update_requires_specific_gaps_and_preserves_history(self):
        with self.assertRaisesMessage(ValidationError, "identify the gaps"):
            assess_clause(
                subclause=self.clause, reviewer=self.auditor,
                decision=ClauseAuditAssessment.Decision.REQUEST_UPDATE,
                note="Update required.", gaps="",
            )
        first = assess_clause(
            subclause=self.clause, reviewer=self.auditor,
            decision=ClauseAuditAssessment.Decision.REQUEST_UPDATE,
            note="Update required.", gaps="Provide the signed current-period policy.",
        )
        second = assess_clause(
            subclause=self.clause, reviewer=self.auditor,
            decision=ClauseAuditAssessment.Decision.REJECT,
            note="Evidence remains unsupported.", gaps="Approval is absent.",
        )
        self.assertEqual((first.sequence, second.sequence), (1, 2))
        self.assertEqual(self.clause.audit_assessments.count(), 2)

    def test_report_is_tenant_scoped_and_excludes_file_content(self):
        self.client.force_login(self.auditor)
        device = TOTPDevice.objects.create(user=self.auditor, name="test", confirmed=True)
        session = self.client.session
        session["otp_device_id"] = device.persistent_id
        session.save()
        response = self.client.get("/auditor/report/?format=csv")
        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        self.assertIn("Synthetic clause", body)
        self.assertNotIn("Synthetic approved policy evidence", body)
