import hashlib
import hmac

from django.conf import settings
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver

from apps.auditlog.models import AuditEvent
from apps.tenancy.models import Membership
from apps.tenancy.rls import set_rls_context


def _first_tenant(user):
    if not getattr(user, "is_authenticated", False):
        return None
    membership = Membership.objects.filter(user=user, is_active=True).select_related("tenant").first()
    return membership.tenant if membership else None


def _fingerprint(value):
    return hmac.new(settings.SECRET_KEY.encode(), str(value or "").encode(), hashlib.sha256).hexdigest()


@receiver(user_logged_in)
def record_login(sender, request, user, **kwargs):
    tenant = _first_tenant(user)
    set_rls_context(user_id=user.pk, tenant_id=getattr(tenant, "pk", None))
    AuditEvent.objects.create(
        tenant=tenant, actor=user, action="authentication.password_succeeded",
        object_type="User", object_id=str(user.pk), metadata={},
    )


@receiver(user_logged_out)
def record_logout(sender, request, user, **kwargs):
    if user and getattr(user, "pk", None):
        tenant = _first_tenant(user)
        set_rls_context(user_id=user.pk, tenant_id=getattr(tenant, "pk", None))
        AuditEvent.objects.create(
            tenant=tenant, actor=user, action="authentication.logged_out",
            object_type="User", object_id=str(user.pk), metadata={},
        )


@receiver(user_login_failed)
def record_login_failure(sender, credentials, request, **kwargs):
    AuditEvent.objects.create(
        tenant=None, actor=None, action="authentication.password_failed",
        object_type="AuthenticationAttempt", object_id=_fingerprint(credentials.get("username")),
        metadata={"identifier_fingerprinted": True},
    )

