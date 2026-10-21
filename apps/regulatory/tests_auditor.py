import base64
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.test import TestCase
from django_otp.plugins.otp_totp.models import TOTPDevice

from apps.tenancy.models import Membership, Tenant

from .models import AuditorReport, AuditorReportImport, AuditorReportImportRow, ClauseAuditAssessment, ClauseEvidence, Regulation, RegulatorySource, RegulatoryVersion, SubClause
from .services import assess_clause, confirm_auditor_report_import, create_auditor_account, extract_auditor_report_decisions, review_clause_evidence, update_auditor_import_row, upload_auditor_report, upload_clause_evidence


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

    def test_owner_creates_dedicated_auditor_account(self):
        user = create_auditor_account(
            tenant=self.tenant, actor=self.owner, username="field-auditor",
            email="auditor@example.test", password="Unique-Audit-Pass-9274!",
        )
        membership = Membership.objects.get(user=user, tenant=self.tenant)
        self.assertEqual(membership.role, Membership.Role.AUDITOR)
        self.assertTrue(user.check_password("Unique-Audit-Pass-9274!"))
        with self.assertRaises(PermissionDenied):
            create_auditor_account(
                tenant=self.tenant, actor=self.auditor, username="forbidden-auditor",
                email="", password="Unique-Audit-Pass-9275!",
            )

    def test_auditor_pdf_is_encrypted_and_download_is_authorized(self):
        content = b"%PDF-1.4\nSynthetic signed auditor report"
        report = upload_auditor_report(
            tenant=self.tenant, actor=self.auditor, title="On-site review 2026",
            filename="signed-review.pdf", content=content,
        )
        stored = (Path(self.temp.name) / report.storage_key).read_bytes()
        self.assertNotEqual(stored, content)
        self.assertEqual(AuditorReport.objects.count(), 1)
        with self.assertRaises(PermissionDenied):
            upload_auditor_report(
                tenant=self.tenant, actor=self.owner, title="Invalid uploader",
                filename="report.pdf", content=content,
            )

        self.client.force_login(self.owner)
        device = TOTPDevice.objects.create(user=self.owner, name="download-test", confirmed=True)
        session = self.client.session
        session["otp_device_id"] = device.persistent_id
        session.save()
        response = self.client.get(f"/auditor/reports/{report.id}/download/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(b"".join(response.streaming_content), content)

    def test_dashboard_shows_latest_human_auditor_state(self):
        assess_clause(
            subclause=self.clause, reviewer=self.auditor,
            decision=ClauseAuditAssessment.Decision.REQUEST_UPDATE,
            note="More evidence required.", gaps="Provide approval record.",
        )
        self.client.force_login(self.owner)
        device = TOTPDevice.objects.create(user=self.owner, name="dashboard-test", confirmed=True)
        session = self.client.session
        session["otp_device_id"] = device.persistent_id
        session.save()
        response = self.client.get("/")
        self.assertContains(response, "Independent auditor distribution")
        self.assertEqual(response.context["auditor_legal_unverified_count"], 1)

    def _report_with_extracted_text(self, text):
        report = upload_auditor_report(
            tenant=self.tenant, actor=self.auditor, title="On-site clause matrix",
            filename="onsite-matrix.pdf", content=b"%PDF-1.4 synthetic",
        )

        class Page:
            def extract_text(self):
                return text

        class Reader:
            is_encrypted = False
            pages = [Page()]

        with patch("apps.regulatory.services.PdfReader", return_value=Reader()):
            return report, extract_auditor_report_decisions(report=report, actor=self.auditor)

    def test_pdf_rows_require_preview_before_confirming_immutable_assessments(self):
        version = self.clause.regulation.version
        regulation2 = Regulation.objects.create(version=version, number=2, title="Second", source_page="2", source_excerpt="Source")
        SubClause.objects.create(regulation=regulation2, clause_path="2", title="Second", source_page="2")
        report, batch = self._report_with_extracted_text(
            "Clause 1 | Compliant | Control was verified on site.\n"
            "Clause 2 - Non-Compliant - Approval record was missing."
        )

        self.assertEqual(batch.status, AuditorReportImport.Status.READY)
        self.assertEqual(batch.rows.count(), 2)
        self.assertEqual(ClauseAuditAssessment.objects.count(), 0)

        confirm_auditor_report_import(batch=batch, actor=self.auditor)
        batch.refresh_from_db()
        assessments = ClauseAuditAssessment.objects.filter(auditor_report=report)
        self.assertEqual(batch.status, AuditorReportImport.Status.CONFIRMED)
        self.assertEqual(assessments.count(), 2)
        self.assertSetEqual(set(assessments.values_list("reported_status", flat=True)), {"COMPLIANT", "NON_COMPLIANT"})
        self.assertTrue(all(item.compliance_status == ClauseAuditAssessment.ComplianceStatus.LEGAL_UNVERIFIED for item in assessments))
        with self.assertRaisesMessage(ValidationError, "already confirmed"):
            confirm_auditor_report_import(batch=batch, actor=self.auditor)

    def test_unmatched_pdf_row_is_corrected_before_confirmation(self):
        _, batch = self._report_with_extracted_text(
            "Clause 999 | Partial | Annual test proof needs an update."
        )
        row = batch.rows.get()
        self.assertTrue(row.validation_error)
        with self.assertRaisesMessage(ValidationError, "Resolve every"):
            confirm_auditor_report_import(batch=batch, actor=self.auditor)

        update_auditor_import_row(
            row=row, actor=self.auditor, subclause=self.clause,
            reported_status=AuditorReportImportRow.ReportedStatus.PARTIAL,
            remarks="Annual test proof needs an update.",
        )
        batch.refresh_from_db()
        self.assertEqual(batch.status, AuditorReportImport.Status.READY)
        confirm_auditor_report_import(batch=batch, actor=self.auditor)
        assessment = self.clause.audit_assessments.first()
        self.assertEqual(assessment.reported_status, AuditorReportImportRow.ReportedStatus.PARTIAL)
        self.assertEqual(assessment.decision, ClauseAuditAssessment.Decision.REQUEST_UPDATE)

    def test_report_parser_rejects_non_auditor_and_unsupported_layout(self):
        report = upload_auditor_report(
            tenant=self.tenant, actor=self.auditor, title="Report", filename="report.pdf",
            content=b"%PDF-1.4 synthetic",
        )
        with self.assertRaises(PermissionDenied):
            extract_auditor_report_decisions(report=report, actor=self.owner)

        class EmptyReader:
            is_encrypted = False
            pages = []

        with patch("apps.regulatory.services.PdfReader", return_value=EmptyReader()):
            batch = extract_auditor_report_decisions(report=report, actor=self.auditor)
        self.assertEqual(batch.status, AuditorReportImport.Status.ERROR)
        self.assertEqual(batch.rows.count(), 0)

    def test_multiline_pdf_table_layout_is_extracted(self):
        _, batch = self._report_with_extracted_text(
            "Clause 1\nPartially Compliant\nAnnual evidence was incomplete."
        )
        row = batch.rows.get()
        self.assertEqual(row.raw_clause_reference, "1")
        self.assertEqual(row.reported_status, AuditorReportImportRow.ReportedStatus.PARTIAL)
        self.assertEqual(row.remarks, "Annual evidence was incomplete.")

        self.client.force_login(self.auditor)
        device = TOTPDevice.objects.create(user=self.auditor, name="import-preview", confirmed=True)
        session = self.client.session
        session["otp_device_id"] = device.persistent_id
        session.save()
        response = self.client.get("/auditor/")
        self.assertContains(response, "Confirm all reviewed rows")
        self.assertContains(response, "Annual evidence was incomplete.")
