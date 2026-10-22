from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction

from apps.auditlog.models import AuditEvent

from .models import Membership


def _locked_owner(*, tenant, actor):
    membership = Membership.objects.select_for_update().filter(
        tenant=tenant, user=actor, role=Membership.Role.OWNER, is_active=True
    ).first()
    if membership is None:
        raise PermissionDenied("Only the active tenant owner can manage users.")
    return membership


@transaction.atomic
def create_tenant_user(*, tenant, actor, username, email, role, temporary_password):
    _locked_owner(tenant=tenant, actor=actor)
    if role == Membership.Role.OWNER:
        raise ValidationError("Use ownership transfer to assign the owner role.")
    if role not in Membership.Role.values:
        raise ValidationError("Select a valid tenant role.")
    user_model = get_user_model()
    candidate = user_model(username=username.strip(), email=email.strip())
    validate_password(temporary_password, user=candidate)
    if user_model.objects.filter(username__iexact=candidate.username).exists():
        raise ValidationError("That username is already in use.")
    candidate.set_password(temporary_password)
    candidate.save()
    membership = Membership.objects.create(tenant=tenant, user=candidate, role=role)
    AuditEvent.objects.create(tenant=tenant, actor=actor, action="tenant.user_created", object_type="Membership", object_id=str(membership.pk), metadata={"username": candidate.username, "role": role})
    return membership


@transaction.atomic
def disable_tenant_user(*, membership, actor):
    _locked_owner(tenant=membership.tenant, actor=actor)
    membership = Membership.objects.select_for_update().select_related("user", "tenant").get(pk=membership.pk)
    if membership.user_id == actor.pk or membership.role == Membership.Role.OWNER:
        raise ValidationError("The active owner cannot be disabled; transfer ownership first.")
    membership.is_active = False
    membership.save(update_fields=["is_active"])
    if not membership.user.tenant_memberships.filter(is_active=True).exists():
        membership.user.is_active = False
        membership.user.save(update_fields=["is_active"])
    AuditEvent.objects.create(tenant=membership.tenant, actor=actor, action="tenant.user_disabled", object_type="Membership", object_id=str(membership.pk), metadata={"username": membership.user.username})
    return membership


@transaction.atomic
def reset_tenant_user_password(*, membership, actor, temporary_password):
    _locked_owner(tenant=membership.tenant, actor=actor)
    membership = Membership.objects.select_for_update().select_related("user", "tenant").get(pk=membership.pk)
    if not membership.is_active:
        raise ValidationError("Enable the membership before resetting its password.")
    validate_password(temporary_password, user=membership.user)
    membership.user.set_password(temporary_password)
    membership.user.save(update_fields=["password"])
    AuditEvent.objects.create(tenant=membership.tenant, actor=actor, action="tenant.password_reset", object_type="Membership", object_id=str(membership.pk), metadata={"username": membership.user.username})


@transaction.atomic
def transfer_tenant_ownership(*, tenant, actor, target_membership, current_password):
    current = _locked_owner(tenant=tenant, actor=actor)
    target = Membership.objects.select_for_update().select_related("user").get(pk=target_membership.pk, tenant=tenant)
    if not actor.check_password(current_password):
        raise ValidationError("Current owner password is incorrect.")
    if not target.is_active or not target.user.is_active or target.user_id == actor.pk:
        raise ValidationError("Select a different active tenant user.")
    previous_role = target.role
    current.role = Membership.Role.COMPLIANCE_LEAD
    target.role = Membership.Role.OWNER
    current.save(update_fields=["role"])
    target.save(update_fields=["role"])
    AuditEvent.objects.create(tenant=tenant, actor=actor, action="tenant.ownership_transferred", object_type="Membership", object_id=str(target.pk), metadata={"new_owner": target.user.username, "previous_target_role": previous_role})
    return target
