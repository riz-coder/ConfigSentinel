import base64
import tempfile
from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.tenancy.models import Membership, Tenant

from .models import LegalSourceStatus, SourceDocument
from .services import upload_source_pdf
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
