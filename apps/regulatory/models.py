import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from apps.tenancy.models import Tenant


class LegalSourceStatus(models.TextChoices):
    SOURCE_PENDING = "SOURCE_PENDING", "Source pending"
    VERIFIED = "VERIFIED", "Verified"
    SUPERSEDED = "SUPERSEDED", "Superseded"


class RegulatorySource(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="regulatory_sources")
    title = models.CharField(max_length=255)
    authority_url = models.URLField(blank=True)
    gazette_identifier = models.CharField(max_length=120, blank=True)
    sha256 = models.CharField(max_length=64, blank=True)
    legal_status = models.CharField(max_length=20, choices=LegalSourceStatus.choices, default=LegalSourceStatus.SOURCE_PENDING)
    reviewed_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="reviewed_regulatory_sources")
    reviewed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["title"]
        constraints = [
            models.UniqueConstraint(
                fields=["tenant", "gazette_identifier"],
                condition=~models.Q(gazette_identifier=""),
                name="unique_nonempty_tenant_gazette_identifier",
            )
        ]

    def clean(self):
        if self.legal_status == LegalSourceStatus.VERIFIED:
            missing = not all([self.authority_url, self.gazette_identifier, self.sha256, self.reviewed_by_id, self.reviewed_at])
            if missing:
                raise ValidationError("Verified sources require authority URL, gazette identifier, SHA-256, reviewer, and review time.")
        if self.sha256 and (len(self.sha256) != 64 or any(c not in "0123456789abcdefABCDEF" for c in self.sha256)):
            raise ValidationError({"sha256": "Enter a valid 64-character SHA-256 digest."})

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)

    def __str__(self):
        return self.title


class RegulatoryVersion(models.Model):
    class ApprovalStatus(models.TextChoices):
        DRAFT = "DRAFT", "Draft"
        UNDER_REVIEW = "UNDER_REVIEW", "Under review"
        APPROVED = "APPROVED", "Approved"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source = models.ForeignKey(RegulatorySource, on_delete=models.PROTECT, related_name="versions")
    version_label = models.CharField(max_length=80)
    approval_status = models.CharField(max_length=20, choices=ApprovalStatus.choices, default=ApprovalStatus.DRAFT)
    effective_date = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["source", "version_label"], name="unique_source_version")]

    def clean(self):
        if self.approval_status == self.ApprovalStatus.APPROVED and self.source.legal_status != LegalSourceStatus.VERIFIED:
            raise ValidationError("A version cannot be approved until its source is verified.")

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)


class Regulation(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    version = models.ForeignKey(RegulatoryVersion, on_delete=models.PROTECT, related_name="regulations")
    number = models.PositiveSmallIntegerField()
    title = models.CharField(max_length=255, default="SOURCE_PENDING — no verified clause text")
    legal_status = models.CharField(max_length=20, choices=LegalSourceStatus.choices, default=LegalSourceStatus.SOURCE_PENDING)
    source_page = models.CharField(max_length=40, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["number"]
        constraints = [
            models.UniqueConstraint(fields=["version", "number"], name="unique_version_regulation_number"),
            models.CheckConstraint(condition=models.Q(number__gte=1, number__lte=84), name="regulation_number_1_to_84"),
        ]

    def clean(self):
        if self.legal_status == LegalSourceStatus.VERIFIED:
            if self.version.approval_status != RegulatoryVersion.ApprovalStatus.APPROVED:
                raise ValidationError("A regulation cannot be verified under an unapproved source version.")
            if not self.source_page:
                raise ValidationError({"source_page": "A verified regulation requires a source page reference."})

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)

