import base64
import json
import secrets
import tempfile
from unittest.mock import patch
from pathlib import Path
from datetime import timedelta
from types import SimpleNamespace

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings
from django.utils import timezone
from django_otp.plugins.otp_totp.models import TOTPDevice
from rest_framework.test import APIClient

from apps.auditlog.models import AuditEvent
from apps.inventory.models import Asset, CriticalService
from apps.tenancy.models import Membership, Tenant
from apps.tenancy.rls import set_rls_context

from apps.evidence.vault import LocalEncryptedObjectStore
from .agent import CollectorExecutionError, parse_cisco_show_version, run_collection_job
from .assessment import _deep_operational_rules
from .dispatcher import dispatch_local_job
from .models import CollectionJob, CollectorAgent, CommandDefinition, CommandExecution, CommandProfile, CredentialReference, Device, DeviceAssessment, RawSnapshot, ScopeGrant, TechnicalFinding
from .secretstore import CollectorSecretError, LocalAgentSecretStore
from .services import CISCO_IOS_XE_DEEP_COMMANDS, CISCO_IOS_XE_READ_ONLY_COMMANDS, CISCO_NXOS_DEEP_COMMANDS, CISCO_NXOS_READ_ONLY_COMMANDS, activate_agent, approve_command_profile, approve_scope, approve_telnet_device, create_scope_grant, install_cisco_ios_xe_deep_profile, install_cisco_ios_xe_profile, install_cisco_nxos_deep_profile, register_agent, register_device, request_collection


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

    @patch("apps.collector.dispatcher.subprocess.Popen")
    def test_ui_dispatch_uses_fixed_detached_worker_without_shell(self, popen):
        job = self.request_job()
        dispatch_local_job(job=job, actor=self.owner)
        command = popen.call_args.args[0]
        options = popen.call_args.kwargs
        self.assertEqual(command[-3:], ["run_collector_agent", "--job", str(job.id)])
        self.assertFalse(options["shell"])
        self.assertIs(options["stdin"], __import__("subprocess").DEVNULL)
        self.assertTrue(AuditEvent.objects.filter(action="collector.job_dispatched", object_id=str(job.id)).exists())

    @patch("apps.collector.dispatcher.subprocess.Popen")
    def test_repeat_dispatch_is_idempotent(self, popen):
        job = self.request_job()
        job.state = CollectionJob.State.PREFLIGHT
        job.save(update_fields=["state"])
        dispatch_local_job(job=job, actor=self.owner)
        popen.assert_not_called()

    def test_host_key_mismatch_fails_closed(self):
        with self.assertRaisesMessage(ValidationError, "Host-key verification failed"):
            self.request_job(observed_host_key_sha256="SHA256:wrong")
        self.assertFalse(CollectionJob.objects.exists())

    def test_approved_telnet_job_does_not_require_ssh_host_key(self):
        device = register_device(tenant=self.tenant, actor=self.owner, asset=self.asset, name="Legacy Nexus", vendor=Device.Vendor.CISCO, platform="NXOS", management_address="192.0.2.11", transport=Device.Transport.TELNET, port=23, telnet_exception_reference="TELNET-TEST-1", telnet_risk_acknowledgement="Synthetic isolated clear-text transport risk acknowledgement for testing.")
        approve_telnet_device(device=device, actor=self.reviewer)
        device.refresh_from_db()
        now = timezone.now()
        grant = create_scope_grant(tenant=self.tenant, actor=self.owner, device=device, agent=self.agent, credential=self.credential, authorization_reference="AUTH-TELNET-001", purpose="Synthetic approved Telnet test", valid_from=now - timedelta(minutes=1), valid_until=now + timedelta(hours=1), max_commands=5, max_runtime_seconds=60, max_output_bytes=4096)
        approve_scope(grant=grant, actor=self.reviewer); grant.refresh_from_db()
        job = request_collection(tenant=self.tenant, actor=self.owner, device=device, agent=self.agent, scope_grant=grant, command_profile=self.profile, observed_host_key_sha256="")
        self.assertEqual(job.observed_host_key_sha256, "")
        self.assertEqual(job.state, CollectionJob.State.QUEUED)

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
        self.assertContains(response, "separate background worker")
        self.assertContains(response, "scan-run-form")
        self.assertContains(response, "Starting…")
        self.assertContains(response, "Automatic device-aware assessment flow")
        self.assertNotContains(response, "Install Cisco IOS/IOS-XE draft profile")
        self.assertNotContains(response, self.credential.secret_reference)

    def test_ui_provisions_credential_only_in_local_encrypted_store(self):
        key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        with tempfile.TemporaryDirectory() as directory, override_settings(COLLECTOR_SECRET_KEY=key, COLLECTOR_SECRET_ROOT=directory):
            client = self.api_client(self.owner)
            response = client.post("/collector/", {"operation": "provision_credential", "credential_id": self.credential.id, "username": "readonly", "password": "synthetic-device-secret", "password_confirmation": "synthetic-device-secret"}, HTTP_X_TENANT_ID=str(self.tenant.id))
            self.assertEqual(response.status_code, 302)
            value = LocalAgentSecretStore().retrieve(self.credential.secret_reference)
            self.assertEqual(value["username"], "readonly")
            stored = next(Path(directory).rglob("*.json")).read_text(encoding="utf-8")
            self.assertNotIn("readonly", stored)
            self.assertNotIn("synthetic-device-secret", stored)

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

    def test_deep_profiles_are_versioned_immutable_drafts_with_30_commands(self):
        ios, ios_created = install_cisco_ios_xe_deep_profile(tenant=self.tenant, actor=self.owner)
        nxos, nxos_created = install_cisco_nxos_deep_profile(tenant=self.tenant, actor=self.owner)
        self.assertTrue(ios_created)
        self.assertTrue(nxos_created)
        self.assertEqual((ios.version, ios.status, ios.command_count), (2, CommandProfile.Status.DRAFT, 30))
        self.assertEqual((nxos.version, nxos.status, nxos.command_count), (2, CommandProfile.Status.DRAFT, 30))
        self.assertEqual(tuple(ios.commands.values_list("key", "command_text", "purpose", "contains_sensitive_output")), CISCO_IOS_XE_DEEP_COMMANDS)
        self.assertEqual(tuple(nxos.commands.values_list("key", "command_text", "purpose", "contains_sensitive_output")), CISCO_NXOS_DEEP_COMMANDS)
        approve_command_profile(profile=nxos, actor=self.reviewer, approval_reference="NET-DEEP-REVIEW-1")
        nxos.refresh_from_db()
        self.assertEqual(nxos.status, CommandProfile.Status.APPROVED)

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

    def test_nxos_device_installs_separate_exact_profile(self):
        device = register_device(tenant=self.tenant, actor=self.owner, asset=self.asset, name="Synthetic Nexus", vendor=Device.Vendor.CISCO, platform="NXOS", management_address="192.0.2.31", transport=Device.Transport.SSH, port=22, pinned_host_key_sha256="SHA256:synthetic-nxos-host-key")
        profile = CommandProfile.objects.get(tenant=self.tenant, name="Cisco NX-OS baseline")
        self.assertEqual(profile.platform, "NX-OS")
        self.assertEqual(tuple(profile.commands.values_list("key", "command_text", "purpose", "contains_sensitive_output")), CISCO_NXOS_READ_ONLY_COMMANDS)
        self.assertEqual(device.platform, "NXOS")


class CollectorAgentExecutionTests(TestCase):
    def setUp(self):
        users = get_user_model().objects
        self.owner = users.create_user(username="agent-owner", password="test-password")
        self.reviewer = users.create_user(username="agent-reviewer", password="test-password")
        self.tenant = Tenant.objects.create(name="Agent tenant", slug="agent-tenant")
        Membership.objects.create(user=self.owner, tenant=self.tenant, role=Membership.Role.OWNER)
        Membership.objects.create(user=self.reviewer, tenant=self.tenant, role=Membership.Role.COMPLIANCE_LEAD)
        set_rls_context(user_id=self.owner.pk, tenant_id=self.tenant.pk)
        self.asset = Asset.objects.create(tenant=self.tenant, asset_tag="RTR-LAB-01", name="Lab router", kind=Asset.Kind.NETWORK_DEVICE, owner=self.owner, custodian=self.owner, criticality=CriticalService.Criticality.HIGH, created_by=self.owner)
        self.device = register_device(tenant=self.tenant, actor=self.owner, asset=self.asset, name="Lab edge", vendor=Device.Vendor.CISCO, platform="IOS-XE", management_address="192.0.2.50", transport=Device.Transport.SSH, port=22, pinned_host_key_sha256="SHA256:synthetic-lab-host-key")
        self.profile = CommandProfile.objects.get(tenant=self.tenant, name="Cisco IOS/IOS-XE baseline")
        approve_command_profile(profile=self.profile, actor=self.reviewer, approval_reference="LAB-NET-REVIEW-01")
        self.profile.refresh_from_db()
        self.credential = CredentialReference.objects.create(tenant=self.tenant, name="Lab credential", provider="LOCAL_AGENT", secret_reference="agent-vault://lab/read-only", created_by=self.owner)
        self.agent = register_agent(tenant=self.tenant, actor=self.owner, name="Lab agent", identity_fingerprint="SHA256:synthetic-agent-fingerprint")
        activate_agent(agent=self.agent, actor=self.reviewer); self.agent.refresh_from_db()
        now = timezone.now()
        self.grant = create_scope_grant(tenant=self.tenant, actor=self.owner, device=self.device, agent=self.agent, credential=self.credential, authorization_reference="LAB-AUTH-01", purpose="Authorized synthetic collector test", valid_from=now - timedelta(minutes=1), valid_until=now + timedelta(hours=1), max_commands=30, max_runtime_seconds=120, max_output_bytes=1024 * 1024)
        approve_scope(grant=self.grant, actor=self.reviewer); self.grant.refresh_from_db()
        self.version_output = (Path(__file__).with_name("fixtures") / "cisco_ios_xe_show_version_17_9.txt").read_text(encoding="utf-8")
        self.secret_key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")

    def make_job(self):
        return request_collection(tenant=self.tenant, actor=self.owner, device=self.device, agent=self.agent, scope_grant=self.grant, command_profile=self.profile, observed_host_key_sha256=self.device.pinned_host_key_sha256)

    def test_show_version_fixture_is_parsed_deterministically(self):
        identity = parse_cisco_show_version(self.version_output)
        self.assertEqual((identity.vendor, identity.platform, identity.model, identity.release), (Device.Vendor.CISCO, "IOS-XE", "C9300-24T", "17.09.04a"))

    def test_nxos_show_version_fixture_is_parsed_deterministically(self):
        output = (Path(__file__).with_name("fixtures") / "cisco_nxos_show_version_10_3.txt").read_text(encoding="utf-8")
        identity = parse_cisco_show_version(output)
        self.assertEqual((identity.vendor, identity.platform, identity.model, identity.release), (Device.Vendor.CISCO, "NX-OS", "Nexus9000", "10.3(4a)"))

    def test_deep_parser_reports_vpc_and_interface_health_without_guessing(self):
        evidence = SimpleNamespace(state=CommandExecution.State.SUCCEEDED)
        outputs = {
            "vpc": (evidence, "Peer status : peer adjacency formed ok\nvPC keep-alive status : peer is alive\nConfiguration consistency status: success"),
            "interface_errors": (evidence, "Port Align-Err FCS-Err Xmit-Err Rcv-Err\nEth1/1 0 2 0 0"),
            "stp_inconsistent": (evidence, "Number of inconsistent ports (segments) in the system : 0"),
        }
        findings, facts = _deep_operational_rules(outputs, {})
        results = {item["rule_id"]: item["result"] for item in findings}
        self.assertEqual(results["CISCO.VPC.HEALTH"], "PASS")
        self.assertEqual(results["CISCO.INTERFACE.ERROR_COUNTERS"], "WARNING")
        self.assertEqual(results["CISCO.STP.INCONSISTENT_PORTS"], "PASS")
        self.assertEqual(facts["interfaces_with_nonzero_error_counters"], 1)

    def test_agent_secret_store_encrypts_and_authenticates(self):
        with tempfile.TemporaryDirectory() as directory, override_settings(COLLECTOR_SECRET_KEY=self.secret_key, COLLECTOR_SECRET_ROOT=directory):
            store = LocalAgentSecretStore(); store.store(reference=self.credential.secret_reference, username="readonly", password="synthetic-password")
            stored_bytes = next(Path(directory).rglob("*.json")).read_bytes()
            self.assertNotIn(b"readonly", stored_bytes); self.assertNotIn(b"synthetic-password", stored_bytes)
            self.assertEqual(store.retrieve(self.credential.secret_reference)["username"], "readonly")
            path = next(Path(directory).rglob("*.json")); payload = json.loads(path.read_text(encoding="utf-8")); payload["ciphertext"] = ("A" if payload["ciphertext"][0] != "A" else "B") + payload["ciphertext"][1:]; path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(CollectorSecretError):
                store.retrieve(self.credential.secret_reference)

    def test_mocked_live_collection_creates_encrypted_lineage(self):
        job = self.make_job(); version_output = self.version_output

        class SecretStore:
            def retrieve(self, reference): return {"username": "readonly", "password": "not-logged"}

        class Session:
            def __init__(self, **kwargs): self.closed = False
            def send(self, command, timeout): return version_output if command == "show version" else "Synthetic supported read-only output"
            def close(self): self.closed = True

        with tempfile.TemporaryDirectory() as directory, override_settings(EVIDENCE_MASTER_KEY=self.secret_key, EVIDENCE_STORAGE_ROOT=directory):
            result = run_collection_job(job.id, secret_store=SecretStore(), evidence_store=LocalEncryptedObjectStore(directory), connector_factory=Session, host_key_probe=lambda host, port: (self.device.pinned_host_key_sha256, object()))
            self.assertEqual(result.state, CollectionJob.State.COMPLETE)
            self.assertEqual(result.discovered_model, "C9300-24T")
            self.assertEqual(CommandExecution.objects.filter(job=job).count(), 22)
            self.assertEqual(CommandExecution.objects.filter(job=job, state=CommandExecution.State.NOT_APPLICABLE).count(), 6)
            self.assertEqual(RawSnapshot.objects.filter(execution__job=job).count(), 16)
            assessment = DeviceAssessment.objects.get(job=job)
            self.assertEqual(assessment.result, "FAIL")
            self.assertTrue(TechnicalFinding.objects.filter(assessment=assessment, rule_id="CISCO.PSIRT.CORRELATION", result=TechnicalFinding.Result.UNKNOWN).exists())
            self.assertTrue(TechnicalFinding.objects.filter(assessment=assessment, evidence_execution__isnull=False).exists())
            snapshot = RawSnapshot.objects.filter(execution__job=job).first()
            self.assertTrue(LocalEncryptedObjectStore(directory).retrieve_and_verify(snapshot))

    def test_host_key_mismatch_fails_without_opening_authenticated_session(self):
        job = self.make_job(); opened = []
        class SecretStore:
            def retrieve(self, reference): return {"username": "readonly", "password": "not-logged"}
        class Session:
            def __init__(self, **kwargs): opened.append(True)
        with self.assertRaisesMessage(CollectorExecutionError, "SSH_HOST_KEY_MISMATCH"):
            run_collection_job(job.id, secret_store=SecretStore(), connector_factory=Session, host_key_probe=lambda host, port: ("SHA256:wrong", object()))
        job.refresh_from_db(); self.assertEqual(job.state, CollectionJob.State.FAILED); self.assertFalse(opened)

    def test_unsupported_command_makes_collection_partial_not_pass(self):
        job = self.make_job(); version_output = self.version_output
        class SecretStore:
            def retrieve(self, reference): return {"username": "readonly", "password": "not-logged"}
        class Session:
            def __init__(self, **kwargs): pass
            def send(self, command, timeout):
                if command == "show version": return version_output
                if command == "show running-config": return "router bgp 65000\n"
                return "% Invalid input detected" if command == "show ip bgp summary" else "Synthetic output"
            def close(self): pass
        with tempfile.TemporaryDirectory() as directory, override_settings(EVIDENCE_MASTER_KEY=self.secret_key, EVIDENCE_STORAGE_ROOT=directory):
            result = run_collection_job(job.id, secret_store=SecretStore(), evidence_store=LocalEncryptedObjectStore(directory), connector_factory=Session, host_key_probe=lambda host, port: (self.device.pinned_host_key_sha256, object()))
        self.assertEqual(result.state, CollectionJob.State.PARTIAL)
        self.assertEqual(result.technical_result, CollectionJob.Result.UNKNOWN)
        self.assertTrue(CommandExecution.objects.filter(job=job, state=CommandExecution.State.UNSUPPORTED).exists())
