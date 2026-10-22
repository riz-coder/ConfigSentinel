import json
from pathlib import Path
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone
from django_otp.plugins.otp_totp.models import TOTPDevice
from rest_framework.test import APIClient

from apps.auditlog.models import AuditEvent
from apps.inventory.models import Asset, CriticalService
from apps.tenancy.models import Membership, Tenant
from apps.tenancy.rls import set_rls_context

from .models import CollectionJob, CollectorAgent, CommandDefinition, CommandProfile, CredentialReference, Device, ScopeGrant
from .services import CISCO_IOS_XE_READ_ONLY_COMMANDS, approve_command_profile, approve_scope, approve_telnet_device, install_cisco_ios_xe_profile, register_device, request_collection


class CollectorBoundaryTests(TestCase):
    def setUp(self):
        users = get_user_model().objects
        self.owner = users.create_user(username="collector-owner", password="test-password")
        self.reviewer = users.create_user(username="collector-reviewer", password="test-password")
        self.tenant = Tenant.objects.create(name="Collector tenant", slug="collector-tenant")
        Membership.objects.create(user=self.owner, tenant=self.tenant, role=Membership.Role.OWNER)
        Membership.objects.create(user=self.reviewer, tenant=self.tenant, role=Membership.Role.COMPLIANCE_LEAD)
        set_rls_context(user_id=self.owner.pk, tenant_id=self.tenant.pk)
        self.asset = Asset.objects.create(tenant=self.tenant, asset_tag="NET-01", name="Synthetic edge asset", kind=Asset.Kind.NETWORK_DEVICE, owner=self.owner, custodian=self.owner, criticality=CriticalService.Criticality.CRITICAL, created_by=self.owner)
        self.device = Device.objects.create(tenant=self.tenant, name="Synthetic edge", vendor=Device.Vendor.CISCO, platform="NX-OS", management_address="192.0.2.10", pinned_host_key_sha256="SHA256:synthetic-fingerprint-not-secret", created_by=self.owner)
        self.credential = CredentialReference.objects.create(tenant=self.tenant, name="Read only reference", provider="TEST_VAULT", secret_reference="vault://synthetic/reference", created_by=self.owner)
        self.agent = CollectorAgent.objects.create(tenant=self.tenant, name="Synthetic agent", identity_fingerprint="SHA256:synthetic-agent-identity", status=CollectorAgent.Status.ACTIVE, registered_by=self.owner)
        self.profile = CommandProfile.objects.create(tenant=self.tenant, name="Reviewed synthetic profile", vendor=Device.Vendor.CISCO, platform="NX-OS", version=1, manifest_sha256="a" * 64, command_count=2, status=CommandProfile.Status.APPROVED, created_by=self.owner, approved_by=self.reviewer, approved_at=timezone.now())
        now = timezone.now()
        self.grant = ScopeGrant.objects.create(tenant=self.tenant, device=self.device, agent=self.agent, credential=self.credential, authorization_reference="AUTH-SYNTHETIC-001", purpose="Synthetic boundary test", valid_from=now - timedelta(minutes=1), valid_until=now + timedelta(hours=1), max_commands=5, max_runtime_seconds=60, max_output_bytes=4096, requested_by=self.owner)
        approve_scope(grant=self.grant, actor=self.reviewer)
        self.grant.refresh_from_db()

    def api_client(self, user):
        client = APIClient()
        otp = TOTPDevice.objects.create(user=user, name=f"collector-{user.pk}", confirmed=True)
        client.force_login(user)
        session = client.session
        session["otp_device_id"] = otp.persistent_id
        session.save()
        return client

    def request_job(self, **overrides):
        values = dict(tenant=self.tenant, actor=self.owner, device=self.device, agent=self.agent, scope_grant=self.grant, command_profile=self.profile, observed_host_key_sha256=self.device.pinned_host_key_sha256)
        values.update(overrides)
        return request_collection(**values)

    def test_safe_job_copies_authorized_budgets_and_defaults_unknown(self):
        job = self.request_job()
        self.assertEqual((job.max_commands, job.max_runtime_seconds, job.max_output_bytes), (5, 60, 4096))
        self.assertEqual(job.technical_result, CollectionJob.Result.UNKNOWN)

    def test_host_key_mismatch_fails_closed(self):
        with self.assertRaisesMessage(ValidationError, "Host-key verification failed"):
            self.request_job(observed_host_key_sha256="SHA256:wrong")
        self.assertFalse(CollectionJob.objects.exists())

    def test_expired_scope_fails_closed(self):
        now = timezone.now()
        expired = ScopeGrant.objects.create(
            tenant=self.tenant, device=self.device, agent=self.agent, credential=self.credential,
            authorization_reference="AUTH-EXPIRED", purpose="Expired authorization test",
            valid_from=now - timedelta(hours=2), valid_until=now - timedelta(hours=1),
            max_commands=1, max_runtime_seconds=30, max_output_bytes=1024,
            requested_by=self.owner,
        )
        approve_scope(grant=expired, actor=self.reviewer)
        expired.refresh_from_db()
        with self.assertRaisesMessage(ValidationError, "current approved"):
            self.request_job(scope_grant=expired)

    def test_one_active_job_per_device(self):
        self.request_job()
        with self.assertRaises(ValidationError):
            self.request_job()

    def test_self_approval_is_rejected(self):
        now = timezone.now()
        grant = ScopeGrant.objects.create(
            tenant=self.tenant, device=self.device, agent=self.agent, credential=self.credential,
            authorization_reference="AUTH-SELF-REVIEW", purpose="Self-review rejection test",
            valid_from=now, valid_until=now + timedelta(hours=1), max_commands=1,
            max_runtime_seconds=30, max_output_bytes=1024, requested_by=self.reviewer,
        )
        with self.assertRaisesMessage(ValidationError, "different authorized reviewer"):
            approve_scope(grant=grant, actor=self.reviewer)

    def test_secret_reference_never_returned(self):
        response = self.api_client(self.owner).get("/api/v1/credential-references/", HTTP_X_TENANT_ID=str(self.tenant.id))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "vault://")

    def test_cross_tenant_job_references_are_denied_and_audited(self):
        other = Tenant.objects.create(name="Other", slug="collector-other")
        Membership.objects.create(user=self.owner, tenant=other, role=Membership.Role.OWNER)
        response = self.api_client(self.owner).post("/api/v1/collection-jobs/", {"device": self.device.id, "agent": self.agent.id, "scope_grant": self.grant.id, "command_profile": self.profile.id, "observed_host_key_sha256": self.device.pinned_host_key_sha256}, format="json", HTTP_X_TENANT_ID=str(other.id))
        self.assertEqual(response.status_code, 400)
        self.assertTrue(AuditEvent.objects.filter(tenant=other, action="collector.job_denied").exists())

    def test_ui_explains_input_and_does_not_render_secret(self):
        response = self.api_client(self.owner).get("/collector/", HTTP_X_TENANT_ID=str(self.tenant.id))
        self.assertContains(response, "Network assurance collector")
        self.assertContains(response, "Live device execution remains blocked")
        self.assertContains(response, "Automatic device-aware assessment flow")
        self.assertNotContains(response, "Install Cisco IOS/IOS-XE draft profile")
        self.assertNotContains(response, self.credential.secret_reference)

    def test_cisco_profile_requires_exact_manifest_and_independent_approval(self):
        profile, created = install_cisco_ios_xe_profile(tenant=self.tenant, actor=self.owner)
        self.assertTrue(created)
        self.assertEqual(profile.commands.count(), 22)
        self.assertTrue(profile.commands.filter(command_text="show cdp neighbors detail", purpose=CommandDefinition.Purpose.TOPOLOGY).exists())
        with self.assertRaisesMessage(ValidationError, "different authorized reviewer"):
            approve_command_profile(profile=profile, actor=self.owner, approval_reference="NET-REVIEW-1")
        with self.assertRaisesMessage(ValidationError, "signoff reference"):
            approve_command_profile(profile=profile, actor=self.reviewer, approval_reference="")
        approve_command_profile(profile=profile, actor=self.reviewer, approval_reference="NET-REVIEW-1")
        profile.refresh_from_db()
        self.assertEqual(profile.status, CommandProfile.Status.APPROVED)

    def test_cisco_profile_matches_review_fixture(self):
        fixture_path = Path(__file__).with_name("fixtures") / "cisco_ios_xe_v1_manifest.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        expected = [list(item) for item in CISCO_IOS_XE_READ_ONLY_COMMANDS]
        self.assertEqual(fixture["commands"], expected)

    def test_tampered_command_profile_cannot_be_approved(self):
        profile, _ = install_cisco_ios_xe_profile(tenant=self.tenant, actor=self.owner)
        command = profile.commands.get(key="platform_version")
        command.command_text = "configure terminal"
        command.save(update_fields=["command_text"])
        with self.assertRaisesMessage(ValidationError, "exactly match"):
            approve_command_profile(profile=profile, actor=self.reviewer, approval_reference="NET-REVIEW-2")

    def test_telnet_requires_risk_record_and_independent_approval(self):
        device = register_device(tenant=self.tenant, actor=self.owner, asset=self.asset, name="Legacy edge", vendor=Device.Vendor.CISCO, platform="IOS", management_address="192.0.2.20", transport=Device.Transport.TELNET, port=23, telnet_exception_reference="CHANGE-123", telnet_risk_acknowledgement="Clear-text transport risk accepted only on an isolated management network.")
        self.assertFalse(device.is_active)
        with self.assertRaisesMessage(ValidationError, "different authorized reviewer"):
            approve_telnet_device(device=device, actor=self.owner)
        approve_telnet_device(device=device, actor=self.reviewer)
        device.refresh_from_db()
        self.assertTrue(device.is_active)
        self.assertEqual(device.telnet_approved_by, self.reviewer)

    def test_cross_tenant_asset_cannot_be_bound_to_device(self):
        other = Tenant.objects.create(name="Foreign asset tenant", slug="foreign-asset")
        Membership.objects.create(user=self.owner, tenant=other, role=Membership.Role.OWNER)
        foreign_asset = Asset.objects.create(tenant=other, asset_tag="FOREIGN", name="Foreign", kind=Asset.Kind.NETWORK_DEVICE, owner=self.owner, custodian=self.owner, criticality=CriticalService.Criticality.HIGH, created_by=self.owner)
        with self.assertRaisesMessage(ValidationError, "same tenant"):
            register_device(tenant=self.tenant, actor=self.owner, asset=foreign_asset, name="Bad binding", vendor=Device.Vendor.CISCO, platform="IOS", management_address="192.0.2.30", transport=Device.Transport.SSH, port=22, pinned_host_key_sha256="SHA256:synthetic-foreign-host-key")
