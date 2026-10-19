import base64
import hashlib
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
    verification_completed_at = models.DateTimeField(null=True, blank=True)
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
            missing = not all([self.authority_url, self.gazette_identifier, self.sha256, self.reviewed_by_id, self.reviewed_at, self.verification_completed_at])
            if missing:
                raise ValidationError("Verified sources require integrity metadata and completed dual review.")
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


class TrustedSigningKey(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="regulatory_signing_keys")
    name = models.CharField(max_length=120)
    public_key_base64 = models.CharField(max_length=44)
    fingerprint = models.CharField(max_length=64, editable=False)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["tenant", "fingerprint"], name="unique_tenant_signing_key")]

    def clean(self):
        try:
            raw = base64.b64decode(self.public_key_base64, validate=True)
        except Exception as exc:
            raise ValidationError({"public_key_base64": "Enter valid base64."}) from exc
        if len(raw) != 32:
            raise ValidationError({"public_key_base64": "Ed25519 public key must be exactly 32 bytes."})
        self.fingerprint = hashlib.sha256(raw).hexdigest()

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)


class RegulatoryImportBatch(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="regulatory_imports")
    version = models.OneToOneField(RegulatoryVersion, on_delete=models.PROTECT, related_name="import_batch")
    signing_key = models.ForeignKey(TrustedSigningKey, on_delete=models.PROTECT, related_name="imports")
    manifest_sha256 = models.CharField(max_length=64)
    signature_base64 = models.TextField()
    imported_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="regulatory_imports")
    imported_at = models.DateTimeField(auto_now_add=True)


class SubClause(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    regulation = models.ForeignKey(Regulation, on_delete=models.PROTECT, related_name="subclauses")
    parent = models.ForeignKey("self", null=True, blank=True, on_delete=models.PROTECT, related_name="children")
    clause_path = models.CharField(max_length=120)
    title = models.CharField(max_length=500)
    source_page = models.CharField(max_length=40)
    legal_status = models.CharField(max_length=20, choices=LegalSourceStatus.choices, default=LegalSourceStatus.SOURCE_PENDING)

    class Meta:
        ordering = ["clause_path"]
        constraints = [models.UniqueConstraint(fields=["regulation", "clause_path"], name="unique_regulation_clause_path")]

    def clean(self):
        if self.parent_id and self.parent.regulation_id != self.regulation_id:
            raise ValidationError({"parent": "Parent must belong to the same regulation."})
        if self.legal_status == LegalSourceStatus.VERIFIED and self.regulation.legal_status != LegalSourceStatus.VERIFIED:
            raise ValidationError("A subclause cannot be verified under an unverified regulation.")

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)


class Obligation(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    subclause = models.ForeignKey(SubClause, on_delete=models.PROTECT, related_name="obligations")
    obligation_key = models.CharField(max_length=120)
    paraphrase = models.TextField()
    requirement_type = models.CharField(max_length=80)
    evidence_specification = models.TextField(blank=True)
    control_reference = models.CharField(max_length=120, blank=True)
    test_procedure_reference = models.CharField(max_length=120, blank=True)
    legal_status = models.CharField(max_length=20, choices=LegalSourceStatus.choices, default=LegalSourceStatus.SOURCE_PENDING)

    class Meta:
        ordering = ["obligation_key"]
        constraints = [models.UniqueConstraint(fields=["subclause", "obligation_key"], name="unique_subclause_obligation")]

    def clean(self):
        if self.legal_status == LegalSourceStatus.VERIFIED and self.subclause.legal_status != LegalSourceStatus.VERIFIED:
            raise ValidationError("An obligation cannot be verified under an unverified subclause.")

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)


class RegulatoryReview(models.Model):
    class Kind(models.TextChoices):
        LEGAL = "LEGAL", "Legal review"
        COMPLIANCE = "COMPLIANCE", "Compliance review"

    class Decision(models.TextChoices):
        APPROVED = "APPROVED", "Approved"
        REJECTED = "REJECTED", "Rejected"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    version = models.ForeignKey(RegulatoryVersion, on_delete=models.PROTECT, related_name="reviews")
    reviewer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="regulatory_reviews")
    kind = models.CharField(max_length=20, choices=Kind.choices)
    decision = models.CharField(max_length=20, choices=Decision.choices)
    note = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["version", "kind"], name="one_review_per_kind")]

