import base64
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.tenancy.models import Membership, Tenant

from .models import LegalSourceStatus, Regulation, SourceDocument
from .services import extract_source_regulations, upload_source_pdf
from apps.evidence.vault import LocalEncryptedObjectStore


class SourcePdfIntakeTests(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.override = self.settings(EVIDENCE_STORAGE_ROOT=Path(self.temp.name), EVIDENCE_MASTER_KEY=base64.b64encode(b"k" * 32).decode())
        self.override.enable()
        self.user = get_user_model().objects.create_user(username="source-uploader")
        self.tenant = Tenant.objects.create(name="Source tenant", slug="source-tenant")
        Membership.objects.create(user=self.user, tenant=self.tenant, role=Membership.Role.LEGAL_REVIEWER)

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
