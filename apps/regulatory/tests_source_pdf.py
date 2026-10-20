import base64
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.tenancy.models import Membership, Tenant

from .models import ClauseEvidence, LegalSourceStatus, Regulation, SourceDocument, SubClause
from .services import extract_source_regulations, upload_clause_evidence, upload_source_pdf, withdraw_clause_evidence
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

    def test_image_only_document_remains_insufficient(self):
        result = deterministic_assessment(
            "Annual security awareness training shall be conducted.",
            evidence_documents=[{"filename": "photos.docx", "text": "", "embedded_images": 4}],
        )

        self.assertEqual(result["status"], "INSUFFICIENT_EVIDENCE")
        self.assertTrue(any("manual visual review" in gap for gap in result["gaps"]))

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
