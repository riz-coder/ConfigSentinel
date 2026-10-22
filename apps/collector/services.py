import hashlib
import json

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from apps.auditlog.models import AuditEvent
from apps.tenancy.models import Membership

from .models import CollectionJob, CollectorAgent, CommandDefinition, CommandProfile, CredentialReference, Device, ScopeGrant


CISCO_IOS_XE_READ_ONLY_COMMANDS = (
    ("platform_version", "show version", CommandDefinition.Purpose.DISCOVERY, False),
    ("running_config", "show running-config", CommandDefinition.Purpose.CONFIGURATION, True),
    ("interfaces_brief", "show ip interface brief", CommandDefinition.Purpose.DISCOVERY, False),
    ("interfaces_detail", "show interfaces", CommandDefinition.Purpose.OPERATIONS, False),
    ("interfaces_status", "show interfaces status", CommandDefinition.Purpose.OPERATIONS, False),
    ("cdp_topology", "show cdp neighbors detail", CommandDefinition.Purpose.TOPOLOGY, False),
    ("lldp_topology", "show lldp neighbors detail", CommandDefinition.Purpose.TOPOLOGY, False),
    ("vlans", "show vlan brief", CommandDefinition.Purpose.CONFIGURATION, False),
    ("spanning_tree", "show spanning-tree summary", CommandDefinition.Purpose.CONFIGURATION, False),
    ("etherchannel", "show etherchannel summary", CommandDefinition.Purpose.CONFIGURATION, False),
    ("routes", "show ip route", CommandDefinition.Purpose.OPERATIONS, False),
    ("routing_protocols", "show ip protocols", CommandDefinition.Purpose.CONFIGURATION, False),
    ("ospf_neighbors", "show ip ospf neighbor", CommandDefinition.Purpose.OPERATIONS, False),
    ("bgp_summary", "show ip bgp summary", CommandDefinition.Purpose.OPERATIONS, False),
    ("aaa_servers", "show aaa servers", CommandDefinition.Purpose.SECURITY, False),
    ("ssh_posture", "show ip ssh", CommandDefinition.Purpose.SECURITY, False),
    ("logging_posture", "show logging", CommandDefinition.Purpose.SECURITY, True),
    ("time_sync", "show ntp associations", CommandDefinition.Purpose.SECURITY, False),
    ("snmp_posture", "show snmp", CommandDefinition.Purpose.SECURITY, True),
    ("access_lists", "show access-lists", CommandDefinition.Purpose.SECURITY, True),
    ("cpu", "show processes cpu sorted 5sec", CommandDefinition.Purpose.OPERATIONS, False),
    ("memory", "show processes memory sorted", CommandDefinition.Purpose.OPERATIONS, False),
)


def _profile_manifest(commands):
    payload = [{"key": key, "command": command, "purpose": purpose, "sensitive": sensitive} for key, command, purpose, sensitive in commands]
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _operator(user, tenant):
    membership = Membership.objects.filter(user=user, tenant=tenant, is_active=True).first()
    if membership is None or membership.role not in {Membership.Role.OWNER, Membership.Role.COMPLIANCE_LEAD}:
        raise PermissionDenied("Tenant owner or compliance lead authorization is required.")
    return membership


@transaction.atomic
def register_device(*, tenant, actor, asset, name, vendor, platform, management_address, transport, port, pinned_host_key_sha256="", telnet_exception_reference="", telnet_risk_acknowledgement=""):
    _operator(actor, tenant)
    device = Device(
        tenant=tenant, asset=asset, name=name, vendor=vendor, platform=platform,
        management_address=management_address, transport=transport, ssh_port=port,
        pinned_host_key_sha256=pinned_host_key_sha256,
        telnet_exception_reference=telnet_exception_reference,
        telnet_risk_acknowledgement=telnet_risk_acknowledgement,
        is_active=transport != Device.Transport.TELNET, created_by=actor,
    )
    device.full_clean(); device.save()
    AuditEvent.objects.create(tenant=tenant, actor=actor, action="collector.device_created", object_type="Device", object_id=str(device.id), metadata={"transport": device.transport, "asset_id": str(asset.id) if asset else None})
    if device.vendor == Device.Vendor.CISCO and device.platform.upper().replace(" ", "-") in {"IOS", "IOS-XE", "IOS_IOS_XE"}:
        install_cisco_ios_xe_profile(tenant=tenant, actor=actor)
    return device


@transaction.atomic
def register_credential_reference(*, tenant, actor, name, provider, secret_reference):
    _operator(actor, tenant)
    reference = CredentialReference(tenant=tenant, name=name, provider=provider, secret_reference=secret_reference, created_by=actor)
    reference.full_clean(); reference.save()
    AuditEvent.objects.create(tenant=tenant, actor=actor, action="collector.credentialreference_created", object_type="CredentialReference", object_id=str(reference.id), metadata={"provider": provider})
    return reference


@transaction.atomic
def register_agent(*, tenant, actor, name, identity_fingerprint):
    _operator(actor, tenant)
    if not identity_fingerprint.startswith("SHA256:") or len(identity_fingerprint) < 20:
        raise ValidationError("A SHA256 agent identity fingerprint is required.")
    agent = CollectorAgent(tenant=tenant, name=name, identity_fingerprint=identity_fingerprint, registered_by=actor)
    agent.full_clean(); agent.save()
    AuditEvent.objects.create(tenant=tenant, actor=actor, action="collector.agent_registered", object_type="CollectorAgent", object_id=str(agent.id), metadata={})
    return agent


@transaction.atomic
def activate_agent(*, agent, actor):
    _operator(actor, agent.tenant)
    agent = CollectorAgent.objects.select_for_update().get(pk=agent.pk)
    if agent.status != CollectorAgent.Status.PENDING or agent.registered_by_id == actor.pk:
        raise ValidationError("Agent activation requires a different authorized reviewer and a pending agent.")
    agent.status = CollectorAgent.Status.ACTIVE; agent.activated_by = actor; agent.activated_at = timezone.now()
    agent.save(update_fields=["status", "activated_by", "activated_at"])
    AuditEvent.objects.create(tenant=agent.tenant, actor=actor, action="collector.agent_activated", object_type="CollectorAgent", object_id=str(agent.id), metadata={})
    return agent


@transaction.atomic
def create_scope_grant(*, tenant, actor, device, agent, credential, authorization_reference, purpose, valid_from, valid_until, max_commands, max_runtime_seconds, max_output_bytes):
    _operator(actor, tenant)
    grant = ScopeGrant(tenant=tenant, device=device, agent=agent, credential=credential, authorization_reference=authorization_reference, purpose=purpose, valid_from=valid_from, valid_until=valid_until, max_commands=max_commands, max_runtime_seconds=max_runtime_seconds, max_output_bytes=max_output_bytes, requested_by=actor)
    grant.full_clean(); grant.save()
    AuditEvent.objects.create(tenant=tenant, actor=actor, action="collector.scope_requested", object_type="ScopeGrant", object_id=str(grant.id), metadata={"authorization_reference": authorization_reference})
    return grant


@transaction.atomic
def approve_scope(*, grant, actor):
    _operator(actor, grant.tenant)
    grant = ScopeGrant.objects.select_for_update().get(pk=grant.pk)
    if grant.status != ScopeGrant.Status.DRAFT or grant.requested_by_id == actor.pk:
        raise ValidationError("Scope approval requires a different authorized reviewer and a draft grant.")
    grant.full_clean()
    grant.status = ScopeGrant.Status.APPROVED
    grant.approved_by = actor
    grant.approved_at = timezone.now()
    grant.save(update_fields=["status", "approved_by", "approved_at"])
    AuditEvent.objects.create(tenant=grant.tenant, actor=actor, action="collector.scope_approved", object_type="ScopeGrant", object_id=str(grant.id), metadata={"authorization_reference": grant.authorization_reference})
    return grant


@transaction.atomic
def install_cisco_ios_xe_profile(*, tenant, actor):
    _operator(actor, tenant)
    version = 1
    profile, created = CommandProfile.objects.get_or_create(
        tenant=tenant, name="Cisco IOS/IOS-XE baseline", version=version,
        defaults={"vendor": Device.Vendor.CISCO, "platform": "IOS_IOS_XE", "manifest_sha256": _profile_manifest(CISCO_IOS_XE_READ_ONLY_COMMANDS), "command_count": len(CISCO_IOS_XE_READ_ONLY_COMMANDS), "created_by": actor},
    )
    if created:
        CommandDefinition.objects.bulk_create([
            CommandDefinition(tenant=tenant, profile=profile, key=key, command_text=command, purpose=purpose, sequence=index, contains_sensitive_output=sensitive)
            for index, (key, command, purpose, sensitive) in enumerate(CISCO_IOS_XE_READ_ONLY_COMMANDS, start=1)
        ])
        AuditEvent.objects.create(tenant=tenant, actor=actor, action="collector.profile_installed", object_type="CommandProfile", object_id=str(profile.id), metadata={"manifest_sha256": profile.manifest_sha256, "command_count": profile.command_count})
    return profile, created


@transaction.atomic
def approve_command_profile(*, profile, actor, approval_reference):
    _operator(actor, profile.tenant)
    profile = CommandProfile.objects.select_for_update().get(pk=profile.pk)
    if profile.status != CommandProfile.Status.DRAFT or profile.created_by_id == actor.pk:
        raise ValidationError("Command-profile approval requires a different authorized reviewer and a draft profile.")
    approval_reference = str(approval_reference or "").strip()
    if len(approval_reference) < 5:
        raise ValidationError("A network-engineering/code-review signoff reference is required.")
    commands = list(profile.commands.order_by("sequence"))
    actual = tuple((item.key, item.command_text, item.purpose, item.contains_sensitive_output) for item in commands)
    if profile.vendor != Device.Vendor.CISCO or profile.platform != "IOS_IOS_XE" or actual != CISCO_IOS_XE_READ_ONLY_COMMANDS:
        raise ValidationError("Profile commands do not exactly match the reviewed Cisco IOS/IOS-XE read-only allowlist.")
    if profile.command_count != len(actual) or profile.manifest_sha256 != _profile_manifest(actual):
        raise ValidationError("Command-profile count or manifest integrity check failed.")
    profile.status = CommandProfile.Status.APPROVED
    profile.approved_by = actor
    profile.approved_at = timezone.now()
    profile.approval_reference = approval_reference
    profile.save(update_fields=["status", "approved_by", "approved_at", "approval_reference"])
    AuditEvent.objects.create(tenant=profile.tenant, actor=actor, action="collector.profile_approved", object_type="CommandProfile", object_id=str(profile.id), metadata={"manifest_sha256": profile.manifest_sha256, "approval_reference": approval_reference})
    return profile


@transaction.atomic
def approve_telnet_device(*, device, actor, approval_reference=None):
    _operator(actor, device.tenant)
    device = Device.objects.select_for_update().get(pk=device.pk)
    if device.transport != Device.Transport.TELNET or device.created_by_id == actor.pk:
        raise ValidationError("Telnet approval requires a different authorized reviewer and a Telnet device.")
    if approval_reference:
        device.telnet_exception_reference = approval_reference
    if device.telnet_exception_reference == "PENDING_INDEPENDENT_APPROVAL":
        raise ValidationError("Enter the authorized Telnet exception/change reference before approval.")
    device.full_clean()
    device.telnet_approved_by = actor
    device.telnet_approved_at = timezone.now()
    device.is_active = True
    device.save(update_fields=["telnet_exception_reference", "telnet_approved_by", "telnet_approved_at", "is_active"])
    AuditEvent.objects.create(tenant=device.tenant, actor=actor, action="collector.telnet_exception_approved", object_type="Device", object_id=str(device.id), metadata={"exception_reference": device.telnet_exception_reference})
    return device


@transaction.atomic
def request_collection(*, tenant, actor, device, agent, scope_grant, command_profile, observed_host_key_sha256):
    _operator(actor, tenant)
    now = timezone.now()
    objects = [device, agent, scope_grant, command_profile]
    if any(item.tenant_id != tenant.id for item in objects):
        raise ValidationError("Every collection object must belong to the active tenant.")
    if not device.is_active or agent.status != CollectorAgent.Status.ACTIVE:
        raise ValidationError("The device and collector agent must be active.")
    if scope_grant.device_id != device.id or scope_grant.agent_id != agent.id:
        raise ValidationError("The authorization does not cover this exact device and agent.")
    if scope_grant.status != ScopeGrant.Status.APPROVED or not (scope_grant.valid_from <= now < scope_grant.valid_until):
        raise ValidationError("A current approved written authorization is required.")
    if command_profile.status != CommandProfile.Status.APPROVED or command_profile.command_count < 1:
        raise ValidationError("A separately reviewed, non-empty command profile is required.")
    if command_profile.command_count > scope_grant.max_commands:
        raise ValidationError("The approved scope command budget is smaller than this command profile.")
    supported_platform = command_profile.platform == device.platform or (command_profile.platform == "IOS_IOS_XE" and device.platform.upper() in {"IOS", "IOS-XE", "IOS XE", "IOS_IOS_XE"})
    if command_profile.vendor != device.vendor or not supported_platform:
        raise ValidationError("The command profile does not support this device platform.")
    if device.transport == Device.Transport.TELNET and not device.telnet_approved_at:
        raise ValidationError("Telnet transport has not received independent exception approval.")
    if device.transport == Device.Transport.SSH and observed_host_key_sha256 != device.pinned_host_key_sha256:
        raise ValidationError("Host-key verification failed; collection was not queued.")
    job = CollectionJob(
        tenant=tenant, device=device, agent=agent, scope_grant=scope_grant,
        command_profile=command_profile, observed_host_key_sha256=observed_host_key_sha256,
        max_commands=scope_grant.max_commands, max_runtime_seconds=scope_grant.max_runtime_seconds,
        max_output_bytes=scope_grant.max_output_bytes, requested_by=actor,
    )
    job.full_clean()
    job.save()
    AuditEvent.objects.create(tenant=tenant, actor=actor, action="collector.job_queued", object_type="CollectionJob", object_id=str(job.id), metadata={"device_id": str(device.id), "profile_id": str(command_profile.id)})
    return job
