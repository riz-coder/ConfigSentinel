import base64
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.tenancy.models import Membership, Tenant

from .models import ClauseEvidence, LegalSourceStatus, Regulation, SourceDocument, SubClause
from .services import analyze_clause_evidence, extract_source_regulations, upload_clause_evidence, upload_source_pdf, withdraw_clause_evidence
from apps.evidence.vault import LocalEncryptedObjectStore
from .ai import analyze_clause, deterministic_assessment


class SourcePdfIntakeTests(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.override = self.settings(EVIDENCE_STORAGE_ROOT=Path(self.temp.name), EVIDENCE_MASTER_KEY=base64.b64encode(b"k" * 32).decode())
        self.override.enable()
        self.user = get_user_model().objects.create_user(username="source-uploader")
        self.tenant = Tenant.objects.create(name="Source tenant", slug="source-tenant")
        Membership.objects.create(user=self.user, tenant=self.tenant, role=Membership.Role.OWNER)

    def tearDown(self):
        self.override.disable(); self.temp.cleanup()

    def test_pdf_intake_is_encrypted_and_source_pending(self):
        source, version = upload_source_pdf(tenant=self.tenant, actor=self.user, title="Synthetic official source", version_label="v1", filename="official.pdf", content=b"%PDF-1.4 synthetic source")
        document = SourceDocument.objects.get(source=source)
        self.assertEqual(source.legal_status, LegalSourceStatus.SOURCE_PENDING)
        self.assertEqual(version.approval_status, version.ApprovalStatus.UNDER_REVIEW)
        self.assertNotEqual((Path(self.temp.name) / document.storage_key).read_bytes(), b"%PDF-1.4 synthetic source")
        self.assertEqual(LocalEncryptedObjectStore().retrieve_and_verify(document), b"%PDF-1.4 synthetic source")

    def test_extraction_creates_pending_cards_without_inventing_evidence(self):
        source, version = upload_source_pdf(tenant=self.tenant, actor=self.user, title="Synthetic official source", version_label="v1", filename="official.pdf", content=b"%PDF-1.4 synthetic source")

        class Page:
            def __init__(self, text): self.text = text
            def extract_text(self): return self.text
        class Reader:
            is_encrypted = False
            pages = [
                Page("1. First heading. — (1) Source requirement one."),
                Page("2. Second heading. —\n(1) Source requirement two."),
            ]

        with patch("apps.regulatory.services.LocalEncryptedObjectStore.retrieve_and_verify", return_value=b"source"), patch("apps.regulatory.services.PdfReader", return_value=Reader()):
            cards = extract_source_regulations(version=version, actor=self.user)

        self.assertEqual([item["number"] for item in cards], [1, 2])
        self.assertEqual(Regulation.objects.filter(version=version).count(), 2)
        first = Regulation.objects.get(version=version, number=1)
        self.assertEqual(first.legal_status, LegalSourceStatus.SOURCE_PENDING)
        self.assertIn("Source requirement one", first.source_excerpt)
        self.assertFalse(first.subclauses.get().obligations.exists())

    def test_local_assessment_finds_missing_named_roles(self):
        result = deterministic_assessment(
            "(a) Chief Executive Officer: accountable. (b) Chief Information Security Officer: responsible.",
            ["This incident policy assigns duties to all employees."],
        )
        self.assertEqual(result["status"], "NON_COMPLIANT")
        self.assertEqual(len(result["gaps"]), 2)

    @patch.dict("os.environ", {"GEMINI_ENABLED": "false", "GEMINI_API_KEY": "configured-but-unused"})
    @patch("apps.regulatory.ai.urlopen")
    def test_gemini_is_not_called_while_feature_is_paused(self, mocked_urlopen):
        result = analyze_clause(clause_text="Annual approved training is required.", evidence_texts=["training"])

        mocked_urlopen.assert_not_called()
        self.assertEqual(result["engine"], "LOCAL_RULES_V2")
        self.assertIn("paused", result["summary"].lower())

    def test_keywords_without_action_linkage_do_not_prove_named_roles(self):
        result = deterministic_assessment(
            "Chief Information Security Officer: shall approve the programme.",
            ["Chief Information Security Officer programme security policy words copied here."],
        )

        self.assertNotEqual(result["status"], "COMPLIANT")
        self.assertTrue(any("action-linked" in gap for gap in result["gaps"]))

    def test_capitalized_deadline_prose_is_not_misread_as_a_named_role(self):
        result = deterministic_assessment(
            "The licensee shall report to the Authority within twenty-four (24) hours.",
            ["The incident reporting procedure requires notification to the authority within 24 hours and records a timestamp."],
        )

        requirements = [item["requirement"] for item in result["requirement_checks"]]
        self.assertNotIn("Authority within twenty-four", requirements)
        self.assertIn("Deadline 24", requirements)
        self.assertTrue(result["document_observations"][0]["extracted_characters"] > 40)

    def test_image_only_document_is_non_compliant_below_50_percent_coverage(self):
        result = deterministic_assessment(
            "Annual security awareness training shall be conducted.",
            evidence_documents=[{"filename": "photos.docx", "text": "", "embedded_images": 4}],
        )

        self.assertEqual(result["status"], "NON_COMPLIANT")
        self.assertEqual(result["preliminary_evidence_coverage"]["percent"], 0)
        self.assertTrue(any("manual visual review" in gap for gap in result["gaps"]))

    def test_full_evidence_remains_partial_until_legal_mapping_is_verified(self):
        result = deterministic_assessment(
            "Security Officer: shall maintain the control.",
            ["Security Officer is responsible to maintain the control."],
        )

        self.assertEqual(result["preliminary_evidence_coverage"]["percent"], 100)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["preliminary_outcome"], "EVIDENCE_COMPLETE_LEGAL_REVIEW_PENDING")

    def test_required_policy_is_reported_missing_when_no_policy_document_exists(self):
        result = deterministic_assessment(
            "The licensee shall establish an information security policy.\n(a) The policy shall define access control responsibilities.",
            evidence_documents=[{"filename": "attendance.csv", "text": "employee,date\nA,2026-01-01" * 4}],
        )

        self.assertEqual(result["document_requirement"]["status"], "MISSING")
        self.assertTrue(any("Documented policy is missing" in gap for gap in result["gaps"]))

    def test_policy_presence_governance_and_content_are_reported_separately(self):
        result = deterministic_assessment(
            "The licensee shall maintain a security policy.\n(a) The policy shall define access control responsibilities.",
            evidence_documents=[{
                "filename": "security_policy.docx",
                "text": "Security Policy Purpose Scope Document owner Version 2 Approved 2026. Access control responsibilities are assigned and reviewed.",
            }],
        )

        assessment = result["document_requirement"]
        self.assertEqual(assessment["status"], "PRESENT_UNVERIFIED")
        self.assertTrue(all(item["status"] == "PRESENT" for item in assessment["governance"]))
        self.assertEqual(assessment["coverage"][0]["status"], "POTENTIALLY_COVERED")

    def test_bia_requires_an_actual_bia_document_not_backup_screenshots(self):
        result = deterministic_assessment(
            "Each Licensee shall conduct and maintain a documented Business Impact Analysis (BIA) to identify:\n"
            "(a) critical services and business processes;\n(b) detailed risk assessment;\n"
            "(c) Recovery Time Objectives (RTOs) and Recovery Point Objectives (RPOs).\n"
            "BIA shall be reviewed at least annually.",
            evidence_documents=[{"filename": "BIA_SS1.jpeg", "text": "Scheduled backup task every day. SQL backup completed 2025."}],
        )

        assessment = result["document_requirement"]
        self.assertEqual(assessment["required_type"], "business impact analysis")
        self.assertEqual(assessment["status"], "MISSING")
        self.assertTrue(any("Documented business impact analysis is missing" in gap for gap in result["gaps"]))
        self.assertTrue(any(check["requirement"] == "Annual recurrence" and check["status"] == "MISSING" for check in result["requirement_checks"]))
        support = assessment["supporting_evidence"][0]
        self.assertEqual(support["classification"], "SUPPORTING_OPERATIONAL_EVIDENCE")
        self.assertIn("Backup/recovery activity", support["supports"])
        self.assertIn("does not replace", support["limitation"])
        self.assertEqual(result["preliminary_evidence_coverage"]["percent"], 10)

    def test_withdraw_purges_ciphertext_and_keeps_only_tombstone(self):
        source, version = upload_source_pdf(
            tenant=self.tenant, actor=self.user, title="Source", version_label="v1",
            filename="source.pdf", content=b"%PDF-1.4 source",
        )
        regulation = Regulation.objects.create(version=version, number=1)
        clause = SubClause.objects.create(regulation=regulation, clause_path="1", title="Clause", source_page="1")
        artifact = upload_clause_evidence(
            tenant=self.tenant, actor=self.user, subclause=clause, title="Evidence",
            filename="evidence.txt", content=b"Approved responsibility record dated 2026.",
        )
        stored_path = Path(self.temp.name) / artifact.storage_key
        self.assertTrue(stored_path.exists())

        withdraw_clause_evidence(tenant=self.tenant, actor=self.user, artifact=artifact)
        artifact.refresh_from_db()

        self.assertFalse(stored_path.exists())
        self.assertIsNotNone(artifact.purged_at)
        self.assertEqual(artifact.wrapped_dek, "")
        self.assertFalse(ClauseEvidence.objects.filter(pk=artifact.pk, withdrawn_at__isnull=True).exists())

    @patch("apps.regulatory.services._local_ocr", return_value=("Annual approved training attendance record dated 2026.", 0.94))
    def test_jpeg_evidence_uses_local_ocr(self, mocked_ocr):
        source, version = upload_source_pdf(
            tenant=self.tenant, actor=self.user, title="OCR Source", version_label="v1",
            filename="source.pdf", content=b"%PDF-1.4 source",
        )
        regulation = Regulation.objects.create(
            version=version, number=8,
            source_excerpt="Annual approved training shall be conducted.",
        )
        clause = SubClause.objects.create(regulation=regulation, clause_path="8", title="Training", source_page="1")
        upload_clause_evidence(
            tenant=self.tenant, actor=self.user, subclause=clause, title="Photo",
            filename="training.jpeg", content=b"synthetic-image-fixture",
        )

        analysis = analyze_clause_evidence(tenant=self.tenant, actor=self.user, subclause=clause)

        mocked_ocr.assert_called_once()
        observation = analysis.result["document_observations"][0]
        self.assertEqual(observation["readability"], "READABLE")
        self.assertTrue(observation["ocr_used"])
        self.assertEqual(observation["ocr_confidence"], 0.94)
