from datetime import date

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from apps.auditlog.models import AuditEvent
from apps.tenancy.models import Membership, Tenant

from .models import LegalSourceStatus, Regulation, RegulatorySource, RegulatoryVersion


class RegulatoryIntegrityTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="legal", password="a-secure-test-password")
        self.tenant = Tenant.objects.create(name="Alpha", slug="alpha")

    def test_verified_source_requires_integrity_and_review_metadata(self):
        source = RegulatorySource(tenant=self.tenant, title="Incomplete", legal_status=LegalSourceStatus.VERIFIED)
        with self.assertRaises(ValidationError):
            source.save()

    def test_approved_version_requires_verified_source(self):
        source = RegulatorySource.objects.create(tenant=self.tenant, title="Pending source")
        version = RegulatoryVersion(source=source, version_label="2025", approval_status=RegulatoryVersion.ApprovalStatus.APPROVED)
        with self.assertRaises(ValidationError):
            version.save()

    def test_regulation_verification_requires_approved_version_and_page(self):
        source = RegulatorySource.objects.create(
            tenant=self.tenant,
            title="Verified source",
            authority_url="https://example.gov.pk/gazette.pdf",
            gazette_identifier="SRO-TEST",
            sha256="a" * 64,
            legal_status=LegalSourceStatus.VERIFIED,
            reviewed_by=self.user,
            reviewed_at=timezone.now(),
        )
        version = RegulatoryVersion.objects.create(
            source=source, version_label="2025", approval_status=RegulatoryVersion.ApprovalStatus.APPROVED, effective_date=date(2025, 12, 31)
        )
        regulation = Regulation(version=version, number=1, legal_status=LegalSourceStatus.VERIFIED)
        with self.assertRaises(ValidationError):
            regulation.save()

    def test_seed_command_creates_exactly_84_pending_slots_idempotently(self):
        call_command("seed_pending_ctdisr", self.tenant.slug)
        call_command("seed_pending_ctdisr", self.tenant.slug)
        queryset = Regulation.objects.filter(version__source__tenant=self.tenant)
        self.assertEqual(queryset.count(), 84)
        self.assertEqual(queryset.exclude(legal_status=LegalSourceStatus.SOURCE_PENDING).count(), 0)


class TenantIsolationApiTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.alpha_user = user_model.objects.create_user(username="alpha-user", password="a-secure-test-password")
        self.alpha = Tenant.objects.create(name="Alpha", slug="alpha")
        self.beta = Tenant.objects.create(name="Beta", slug="beta")
        Membership.objects.create(user=self.alpha_user, tenant=self.alpha, role=Membership.Role.LEGAL_REVIEWER)
        self.alpha_source = RegulatorySource.objects.create(tenant=self.alpha, title="Alpha source")
        self.beta_source = RegulatorySource.objects.create(tenant=self.beta, title="Beta secret source")
        self.client = APIClient()
        self.client.force_authenticate(self.alpha_user)

    def test_list_only_returns_active_tenant_data(self):
        response = self.client.get("/api/v1/regulatory-sources/")
        self.assertEqual(response.status_code, 200)
        titles = [item["title"] for item in response.data["results"]]
        self.assertEqual(titles, ["Alpha source"])

    def test_cross_tenant_object_id_returns_not_found(self):
        response = self.client.get(f"/api/v1/regulatory-sources/{self.beta_source.pk}/")
        self.assertEqual(response.status_code, 404)

    def test_cross_tenant_header_is_rejected(self):
        response = self.client.get("/api/v1/regulatory-sources/", HTTP_X_TENANT_ID=str(self.beta.pk))
        self.assertEqual(response.status_code, 404)

    def test_authorized_source_creation_is_pending_and_audited(self):
        response = self.client.post("/api/v1/regulatory-sources/", {"title": "New source"}, format="json")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["legal_status"], LegalSourceStatus.SOURCE_PENDING)
        self.assertTrue(AuditEvent.objects.filter(tenant=self.alpha, object_id=response.data["id"]).exists())

    def test_authenticated_user_can_read_openapi_contract(self):
        response = self.client.get("/api/v1/openapi/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("openapi", response.content.decode())


