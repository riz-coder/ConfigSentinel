import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from apps.regulatory.models import EvidenceRequirement, ObligationControlMapping
from apps.tenancy.models import Tenant


class EvidenceStatus(models.TextChoices):
    UNDER_REVIEW = "UNDER_REVIEW", "Under review"
    ACCEPTED = "ACCEPTED", "Accepted"
    REJECTED = "REJECTED", "Rejected"
    STALE = "STALE", "Stale"
    MISSING = "MISSING", "Missing"


class EvidenceArtifact(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="evidence_artifacts")
    mapping = models.ForeignKey(ObligationControlMapping, on_delete=models.PROTECT, related_name="evidence_artifacts")
    requirement = models.ForeignKey(EvidenceRequirement, on_delete=models.PROTECT, related_name="evidence_artifacts")
    title = models.CharField(max_length=255)
    original_filename = models.CharField(max_length=255)
    media_type = models.CharField(max_length=120)
    size_bytes = models.PositiveBigIntegerField()
    plaintext_sha256 = models.CharField(max_length=64)
    ciphertext_sha256 = models.CharField(max_length=64)
    storage_key = models.CharField(max_length=255, unique=True)
    wrapped_dek = models.TextField()
    wrap_nonce = models.CharField(max_length=24)
    content_nonce = models.CharField(max_length=24)
    crypto_version = models.PositiveSmallIntegerField(default=1)
    status = models.CharField(max_length=20, choices=EvidenceStatus.choices, default=EvidenceStatus.UNDER_REVIEW)
    period_start = models.DateField(null=True, blank=True)
    period_end = models.DateField(null=True, blank=True)
    collected_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    retain_until = models.DateTimeField(null=True, blank=True)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="uploaded_evidence")
    created_at = models.DateTimeField(auto_now_add=True)
    finalized_at = models.DateTimeField(null=True, blank=True)
    purged_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["tenant", "status", "expires_at"])]

    def clean(self):
        if self.mapping_id and self.requirement_id:
            if self.mapping.tenant_id != self.tenant_id:
                raise ValidationError("Artifact and mapping must belong to the same tenant.")
            if self.mapping.evidence_requirement_id != self.requirement_id:
                raise ValidationError({"requirement": "Requirement must be the mapping's approved exact version."})
            if self.mapping.status != ObligationControlMapping.Status.APPROVED:
                raise ValidationError({"mapping": "Evidence can only be uploaded against an approved mapping."})
        if self.period_start and self.period_end and self.period_start > self.period_end:
            raise ValidationError("Evidence period start cannot be after period end.")
        if self.status == EvidenceStatus.MISSING:
            raise ValidationError("MISSING describes an absent artifact and cannot be assigned to an uploaded artifact.")

    @property
    def effective_status(self):
        if self.status == EvidenceStatus.ACCEPTED and self.expires_at and self.expires_at <= timezone.now():
            return EvidenceStatus.STALE
        return self.status

    @property
    def has_active_hold(self):
        return self.retention_holds.filter(released_at__isnull=True).exists()

    def save(self, *args, **kwargs):
        if not self._state.adding:
            previous = type(self).objects.filter(pk=self.pk).values().first()
            if previous:
                mutable = {"status", "finalized_at", "purged_at"}
                for field in self._meta.concrete_fields:
                    if field.name not in mutable and previous[field.attname] != getattr(self, field.attname):
                        raise ValidationError("Evidence manifests are immutable; upload a new artifact version.")
        self.full_clean()
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Evidence manifests are retained; use governed ciphertext purge.")


class EvidenceReview(models.Model):
    class Decision(models.TextChoices):
        ACCEPTED = "ACCEPTED", "Accepted"
        REJECTED = "REJECTED", "Rejected"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    artifact = models.OneToOneField(EvidenceArtifact, on_delete=models.PROTECT, related_name="review")
    reviewer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="evidence_reviews")
    decision = models.CharField(max_length=20, choices=Decision.choices)
    note = models.TextField()
    integrity_verified_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError("Evidence reviews are append-only.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Evidence reviews are append-only.")


class RetentionHold(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    artifact = models.ForeignKey(EvidenceArtifact, on_delete=models.PROTECT, related_name="retention_holds")
    reason = models.TextField()
    applied_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="applied_evidence_holds")
    applied_at = models.DateTimeField(auto_now_add=True)
    released_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="released_evidence_holds")
    released_at = models.DateTimeField(null=True, blank=True)
    release_reason = models.TextField(blank=True)

    def save(self, *args, **kwargs):
        if not self._state.adding:
            previous = type(self).objects.filter(pk=self.pk).first()
            if previous and previous.released_at:
                raise ValidationError("Released retention holds are immutable.")
            if previous and any([
                previous.artifact_id != self.artifact_id,
                previous.reason != self.reason,
                previous.applied_by_id != self.applied_by_id,
            ]):
                raise ValidationError("Applied hold details are immutable.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Retention holds cannot be deleted.")


class CustodyEvent(models.Model):
    class Kind(models.TextChoices):
        UPLOADED = "UPLOADED", "Uploaded"
        INTEGRITY_VERIFIED = "INTEGRITY_VERIFIED", "Integrity verified"
        DOWNLOADED = "DOWNLOADED", "Downloaded"
        REVIEWED = "REVIEWED", "Reviewed"
        HOLD_APPLIED = "HOLD_APPLIED", "Hold applied"
        HOLD_RELEASED = "HOLD_RELEASED", "Hold released"
        PURGED = "PURGED", "Ciphertext purged"
        STALE_MARKED = "STALE_MARKED", "Marked stale"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    artifact = models.ForeignKey(EvidenceArtifact, on_delete=models.PROTECT, related_name="custody_events")
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.PROTECT, related_name="evidence_custody_events")
    kind = models.CharField(max_length=30, choices=Kind.choices)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError("Custody events are append-only.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Custody events are append-only.")
