import base64
import json
from datetime import date

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient
from django_otp.plugins.otp_totp.models import TOTPDevice
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apps.auditlog.models import AuditEvent
from apps.tenancy.models import Membership, Tenant
from apps.tenancy.rls import set_rls_context

from .models import (
    ControlDefinition, EvidenceRequirement, LegalSourceStatus, MappingReview, Obligation,
    ObligationControlMapping, Regulation, RegulatoryReview, RegulatorySource,
    RegulatoryVersion, SubClause, TestProcedure, TrustedSigningKey,
)
from .services import MAX_MANIFEST_BYTES, canonical_manifest, compare_versions, coverage_report, create_mapping, import_pack, review_mapping, review_version


class RegulatoryIntegrityTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="legal", password="a-secure-test-password")
        self.tenant = Tenant.objects.create(name="Alpha", slug="alpha")
        set_rls_context(user_id=self.user.pk, tenant_id=self.tenant.pk)

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
            verification_completed_at=timezone.now(),
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
        source_title = queryset.first().version.source.title.upper()
        self.assertNotIn("PTA", source_title)
        self.assertNotIn("CTDISR", source_title)


class TenantIsolationApiTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.alpha_user = user_model.objects.create_user(username="alpha-user", password="a-secure-test-password")
        self.alpha = Tenant.objects.create(name="Alpha", slug="alpha")
        self.beta = Tenant.objects.create(name="Beta", slug="beta")
        Membership.objects.create(user=self.alpha_user, tenant=self.alpha, role=Membership.Role.LEGAL_REVIEWER)
        set_rls_context(user_id=self.alpha_user.pk, tenant_id=self.alpha.pk)
        self.alpha_source = RegulatorySource.objects.create(tenant=self.alpha, title="Alpha source")
        set_rls_context(user_id=self.alpha_user.pk, tenant_id=self.beta.pk)
        self.beta_source = RegulatorySource.objects.create(tenant=self.beta, title="Beta secret source")
        set_rls_context(user_id=self.alpha_user.pk, tenant_id=self.alpha.pk)
        self.client = APIClient()
        device = TOTPDevice.objects.create(user=self.alpha_user, name="test", confirmed=True)
        self.client.force_login(self.alpha_user)
        session = self.client.session
        session["otp_device_id"] = device.persistent_id
        session.save()

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

    @override_settings(PRODUCT_NAME="Private Assurance Desk")
    def test_customer_pages_use_configured_neutral_branding(self):
        for path in ["/", "/regulatory/", "/regulatory/mappings/", "/accounts/login/"]:
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            content = response.content.decode().upper()
            self.assertIn("PRIVATE ASSURANCE DESK", content)
            self.assertNotIn("PTA", content)
            self.assertNotIn("CTDISR", content)


class RegulatoryPackWorkflowTests(TestCase):
    def setUp(self):
        users = get_user_model().objects
        self.importer = users.create_user(username="importer", password="test-password")
        self.legal = users.create_user(username="legal-reviewer", password="test-password")
        self.compliance = users.create_user(username="compliance-reviewer", password="test-password")
        self.tenant = Tenant.objects.create(name="Pack tenant", slug="pack-tenant")
        Membership.objects.create(user=self.importer, tenant=self.tenant, role=Membership.Role.OWNER)
        Membership.objects.create(user=self.legal, tenant=self.tenant, role=Membership.Role.LEGAL_REVIEWER)
        Membership.objects.create(user=self.compliance, tenant=self.tenant, role=Membership.Role.COMPLIANCE_LEAD)
        set_rls_context(user_id=self.importer.pk, tenant_id=self.tenant.pk)
        self.private_key = Ed25519PrivateKey.generate()
        public_raw = self.private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key = TrustedSigningKey.objects.create(tenant=self.tenant, name="Test publisher", public_key_base64=base64.b64encode(public_raw).decode())

    def manifest(self, label="2025.1", paraphrase="An authenticated test-only paraphrase"):
        return {
            "schema_version": 1,
            "source": {"title": "Test Gazette", "authority_url": "https://example.gov.pk/gazette.pdf", "gazette_identifier": "TEST-GAZETTE-1", "sha256": "a" * 64},
            "version": {"label": label, "effective_date": "2025-01-01"},
            "regulations": [{"number": 1, "title": "Test-only regulation", "source_page": "1", "subclauses": [{
                "path": "1.1", "parent_path": None, "title": "Test-only clause", "source_page": "1",
                "obligations": [{"key": "TEST-1", "paraphrase": paraphrase, "requirement_type": "TEST", "evidence_specification": "Test artifact", "control_reference": "CTRL-1", "test_procedure_reference": "PROC-1"}],
            }]}],
        }

    def signed(self, data):
        body = json.dumps(data, indent=2).encode()
        return body, self.private_key.sign(canonical_manifest(data))

    def do_import(self, data=None):
        body, signature = self.signed(data or self.manifest())
        return import_pack(tenant=self.tenant, actor=self.importer, signing_key=self.key, manifest_bytes=body, signature_bytes=signature)

    def test_signed_import_is_atomic_and_source_pending(self):
        version = self.do_import()
        self.assertEqual(version.approval_status, RegulatoryVersion.ApprovalStatus.UNDER_REVIEW)
        self.assertEqual(version.source.legal_status, LegalSourceStatus.SOURCE_PENDING)
        self.assertEqual(Obligation.objects.filter(subclause__regulation__version=version).count(), 1)

    def test_invalid_signature_creates_nothing(self):
        body, _ = self.signed(self.manifest())
        with self.assertRaises(ValidationError):
            import_pack(tenant=self.tenant, actor=self.importer, signing_key=self.key, manifest_bytes=body, signature_bytes=b"x" * 64)
        self.assertEqual(RegulatoryVersion.objects.count(), 0)

    def test_oversized_manifest_creates_nothing(self):
        with self.assertRaises(ValidationError):
            import_pack(
                tenant=self.tenant, actor=self.importer, signing_key=self.key,
                manifest_bytes=b"x" * (MAX_MANIFEST_BYTES + 1), signature_bytes=b"x" * 64,
            )
        self.assertEqual(RegulatoryVersion.objects.count(), 0)

    def test_duplicate_clause_path_creates_nothing(self):
        data = self.manifest()
        data["regulations"][0]["subclauses"].append(dict(data["regulations"][0]["subclauses"][0]))
        body, signature = self.signed(data)
        with self.assertRaises(ValidationError):
            import_pack(tenant=self.tenant, actor=self.importer, signing_key=self.key, manifest_bytes=body, signature_bytes=signature)
        self.assertEqual(RegulatoryVersion.objects.count(), 0)

    def test_two_distinct_authorized_reviews_verify_content_but_not_coverage(self):
        version = self.do_import()
        review_version(version=version, reviewer=self.legal, kind=RegulatoryReview.Kind.LEGAL, decision=RegulatoryReview.Decision.APPROVED)
        review_version(version=version, reviewer=self.compliance, kind=RegulatoryReview.Kind.COMPLIANCE, decision=RegulatoryReview.Decision.APPROVED)
        version.refresh_from_db()
        self.assertEqual(version.approval_status, RegulatoryVersion.ApprovalStatus.APPROVED)
        self.assertEqual(version.source.legal_status, LegalSourceStatus.VERIFIED)
        self.assertFalse(coverage_report(version)["ready"])
        self.assertIn("NUMBERED_REGULATION_COVERAGE_INCOMPLETE", coverage_report(version)["issues"])

    def test_same_person_cannot_complete_both_reviews_after_role_change(self):
        version = self.do_import()
        review_version(version=version, reviewer=self.legal, kind=RegulatoryReview.Kind.LEGAL, decision=RegulatoryReview.Decision.APPROVED)
        Membership.objects.filter(user=self.legal, tenant=self.tenant).update(role=Membership.Role.COMPLIANCE_LEAD)
        with self.assertRaises(ValidationError):
            review_version(version=version, reviewer=self.legal, kind=RegulatoryReview.Kind.COMPLIANCE, decision=RegulatoryReview.Decision.APPROVED)

    def test_version_diff_is_deterministic(self):
        first = self.do_import()
        second = self.do_import(self.manifest(label="2025.2", paraphrase="Changed test-only paraphrase"))
        self.assertEqual(compare_versions(first, second), {"added": [], "removed": [], "changed": ["R01/1.1/TEST-1"]})

    def test_api_rejects_cross_tenant_signing_key(self):
        other = Tenant.objects.create(name="Other", slug="other-pack")
        set_rls_context(user_id=self.importer.pk, tenant_id=other.pk)
        other_key = TrustedSigningKey.objects.create(tenant=other, name="Other", public_key_base64=self.key.public_key_base64)
        set_rls_context(user_id=self.importer.pk, tenant_id=self.tenant.pk)
        client = APIClient()
        device = TOTPDevice.objects.create(user=self.importer, name="pack-test", confirmed=True)
        client.force_login(self.importer)
        session = client.session
        session["otp_device_id"] = device.persistent_id
        session.save()
        body, signature = self.signed(self.manifest())
        from django.core.files.uploadedfile import SimpleUploadedFile
        response = client.post("/api/v1/regulatory-versions/import/", {
            "signing_key": str(other_key.pk), "manifest": SimpleUploadedFile("pack.json", body),
            "signature": SimpleUploadedFile("pack.sig", signature),
        }, format="multipart")
        self.assertEqual(response.status_code, 400)
        self.assertTrue(AuditEvent.objects.filter(tenant=self.tenant, action="regulatory_pack.import_denied").exists())


class ObligationMappingWorkflowTests(TestCase):
    def setUp(self):
        users = get_user_model().objects
        self.author = users.create_user(username="mapping-author", password="test-password")
        self.legal = users.create_user(username="mapping-legal", password="test-password")
        self.compliance = users.create_user(username="mapping-compliance", password="test-password")
        self.tenant = Tenant.objects.create(name="Mapping tenant", slug="mapping-tenant")
        Membership.objects.create(user=self.author, tenant=self.tenant, role=Membership.Role.OWNER)
        Membership.objects.create(user=self.legal, tenant=self.tenant, role=Membership.Role.LEGAL_REVIEWER)
        Membership.objects.create(user=self.compliance, tenant=self.tenant, role=Membership.Role.COMPLIANCE_LEAD)
        set_rls_context(user_id=self.author.pk, tenant_id=self.tenant.pk)
        now = timezone.now()
        source = RegulatorySource.objects.create(
            tenant=self.tenant, title="Verified test source", authority_url="https://example.gov.pk/test.pdf",
            gazette_identifier="MAPPING-TEST", sha256="b" * 64, legal_status=LegalSourceStatus.VERIFIED,
            reviewed_by=self.legal, reviewed_at=now, verification_completed_at=now,
        )
        self.version = RegulatoryVersion.objects.create(source=source, version_label="mapping-test", approval_status=RegulatoryVersion.ApprovalStatus.APPROVED)
        regulation = Regulation.objects.create(version=self.version, number=1, title="Verified test regulation", source_page="1", legal_status=LegalSourceStatus.VERIFIED)
        clause = SubClause.objects.create(regulation=regulation, clause_path="1.1", title="Verified test clause", source_page="1", legal_status=LegalSourceStatus.VERIFIED)
        self.obligation = Obligation.objects.create(subclause=clause, obligation_key="OBL-1", paraphrase="Test only", requirement_type="TEST", legal_status=LegalSourceStatus.VERIFIED)
        self.control = ControlDefinition.objects.create(tenant=self.tenant, control_key="CTRL-1", version=1, title="Test control", description="Test", created_by=self.author)
        self.procedure = TestProcedure.objects.create(tenant=self.tenant, control=self.control, procedure_key="PROC-1", version=1, title="Test procedure", procedure="Read-only inspection", expected_result="Documented result", created_by=self.author)
        self.requirement = EvidenceRequirement.objects.create(tenant=self.tenant, test_procedure=self.procedure, requirement_key="EVID-1", version=1, title="Test evidence", description="Test artifact", created_by=self.author)

    def mapping(self):
        return create_mapping(
            tenant=self.tenant, actor=self.author, obligation=self.obligation, control=self.control,
            test_procedure=self.procedure, evidence_requirement=self.requirement, rationale="Exact test mapping",
        )

    def test_unverified_obligation_cannot_be_mapped(self):
        self.obligation.legal_status = LegalSourceStatus.SOURCE_PENDING
        self.obligation.save()
        with self.assertRaises(ValidationError):
            self.mapping()
        self.assertEqual(ObligationControlMapping.objects.count(), 0)

    def test_mismatched_control_test_chain_is_rejected(self):
        other = ControlDefinition.objects.create(tenant=self.tenant, control_key="CTRL-2", version=1, title="Other", description="Other", created_by=self.author)
        with self.assertRaises(ValidationError):
            create_mapping(
                tenant=self.tenant, actor=self.author, obligation=self.obligation, control=other,
                test_procedure=self.procedure, evidence_requirement=self.requirement, rationale="Invalid chain",
            )

    def test_author_cannot_review_own_mapping(self):
        mapping = self.mapping()
        Membership.objects.filter(user=self.author, tenant=self.tenant).update(role=Membership.Role.COMPLIANCE_LEAD)
        with self.assertRaises(ValidationError):
            review_mapping(mapping=mapping, reviewer=self.author, kind=MappingReview.Kind.COMPLIANCE, decision=MappingReview.Decision.APPROVED)

    def test_dual_review_finalizes_mapping_and_updates_coverage(self):
        mapping = self.mapping()
        review_mapping(mapping=mapping, reviewer=self.legal, kind=MappingReview.Kind.LEGAL, decision=MappingReview.Decision.APPROVED)
        report = coverage_report(self.version)
        self.assertIn("CONTROL_MAPPING_MISSING", report["issues"])
        review_mapping(mapping=mapping, reviewer=self.compliance, kind=MappingReview.Kind.COMPLIANCE, decision=MappingReview.Decision.APPROVED)
        mapping.refresh_from_db()
        report = coverage_report(self.version)
        self.assertEqual(mapping.status, ObligationControlMapping.Status.APPROVED)
        self.assertEqual(report["approved_mappings"], 1)
        self.assertNotIn("CONTROL_MAPPING_MISSING", report["issues"])
        self.assertNotIn("TEST_PROCEDURE_MISSING", report["issues"])
        self.assertNotIn("EVIDENCE_SPECIFICATION_MISSING", report["issues"])

    def test_finalized_mapping_and_reviews_are_immutable(self):
        mapping = self.mapping()
        review = review_mapping(mapping=mapping, reviewer=self.legal, kind=MappingReview.Kind.LEGAL, decision=MappingReview.Decision.REJECTED)
        mapping.refresh_from_db()
        mapping.rationale = "Mutated"
        with self.assertRaises(ValidationError):
            mapping.save()
        review.note = "Mutated"
        with self.assertRaises(ValidationError):
            review.save()
        with self.assertRaises(ValidationError):
            review.delete()

    def test_api_cross_tenant_mapping_reference_is_denied_and_audited(self):
        other = Tenant.objects.create(name="Other mapping", slug="other-mapping")
        Membership.objects.create(user=self.author, tenant=other, role=Membership.Role.OWNER)
        set_rls_context(user_id=self.author.pk, tenant_id=other.pk)
        foreign_control = ControlDefinition.objects.create(tenant=other, control_key="FOREIGN", version=1, title="Foreign", description="Foreign", created_by=self.author)
        set_rls_context(user_id=self.author.pk, tenant_id=self.tenant.pk)
        client = APIClient()
        device = TOTPDevice.objects.create(user=self.author, name="mapping-api", confirmed=True)
        client.force_login(self.author)
        session = client.session
        session["otp_device_id"] = device.persistent_id
        session.save()
        response = client.post("/api/v1/obligation-mappings/", {
            "obligation": str(self.obligation.pk), "control": str(foreign_control.pk),
            "test_procedure": str(self.procedure.pk), "evidence_requirement": str(self.requirement.pk),
            "rationale": "Cross tenant attempt",
        }, format="json")
        self.assertEqual(response.status_code, 400)
        self.assertTrue(AuditEvent.objects.filter(tenant=self.tenant, action="obligation_mapping.denied").exists())

    def test_mapping_center_renders_for_authenticated_member(self):
        client = APIClient()
        device = TOTPDevice.objects.create(user=self.author, name="mapping-ui", confirmed=True)
        client.force_login(self.author)
        session = client.session
        session["otp_device_id"] = device.persistent_id
        session.save()
        response = client.get("/regulatory/mappings/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Control, test and evidence mappings")


