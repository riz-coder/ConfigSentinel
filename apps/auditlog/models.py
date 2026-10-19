import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from apps.tenancy.models import Tenant


class ImmutableAuditQuerySet(models.QuerySet):
    def delete(self):
        raise ValidationError("Audit events are append-only and cannot be deleted.")

    def update(self, **kwargs):
        raise ValidationError("Audit events are append-only and cannot be updated.")


class AuditEvent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="audit_events")
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="audit_events")
    action = models.CharField(max_length=120)
    object_type = models.CharField(max_length=120)
    object_id = models.CharField(max_length=120)
    request_id = models.UUIDField(default=uuid.uuid4, editable=False)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = ImmutableAuditQuerySet.as_manager()

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["tenant", "created_at"])]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError("Audit events are append-only and cannot be updated.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Audit events are append-only and cannot be deleted.")

