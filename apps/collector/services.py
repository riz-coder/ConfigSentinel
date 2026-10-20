from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from apps.auditlog.models import AuditEvent
from apps.tenancy.models import Membership

from .models import CollectionJob, CollectorAgent, CommandProfile, ScopeGrant


def _operator(user, tenant):
    membership = Membership.objects.filter(user=user, tenant=tenant, is_active=True).first()
    if membership is None or membership.role not in {Membership.Role.OWNER, Membership.Role.COMPLIANCE_LEAD}:
        raise PermissionDenied("Tenant owner or compliance lead authorization is required.")
    return membership


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
    if command_profile.vendor != device.vendor or command_profile.platform != device.platform:
        raise ValidationError("The command profile does not support this device platform.")
    if observed_host_key_sha256 != device.pinned_host_key_sha256:
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
