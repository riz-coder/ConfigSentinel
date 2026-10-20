from datetime import timedelta

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.text import get_valid_filename

from apps.auditlog.models import AuditEvent
from apps.regulatory.models import ObligationControlMapping
from apps.tenancy.models import Membership

from .models import CustodyEvent, EvidenceArtifact, EvidenceReview, EvidenceStatus, RetentionHold
from .vault import LocalEncryptedObjectStore, VaultError


ALLOWED_MEDIA_TYPES = {
    "application/pdf",
    "application/json",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "image/jpeg",
    "image/png",
    "text/csv",
    "text/plain",
}


def _membership(user, tenant):
    return Membership.objects.filter(user=user, tenant=tenant, is_active=True).first()


@transaction.atomic
def upload_evidence(*, tenant, actor, mapping, title, filename, media_type, content, period_start=None, period_end=None, collected_at=None, store=None):
    membership = _membership(actor, tenant)
    if membership is None or membership.role not in {Membership.Role.OWNER, Membership.Role.COMPLIANCE_LEAD}:
        raise PermissionDenied("Only tenant owners or compliance leads may upload evidence.")
    if mapping.tenant_id != tenant.id or mapping.status != ObligationControlMapping.Status.APPROVED:
        raise ValidationError("Evidence requires an approved mapping from the active tenant.")
    if not content:
        raise ValidationError("Evidence file cannot be empty.")
    if media_type not in ALLOWED_MEDIA_TYPES:
        raise ValidationError("This evidence media type is not allowed.")
    safe_name = get_valid_filename(filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1])[:255]
    if not safe_name:
        raise ValidationError("Evidence filename is invalid.")
    requirement = mapping.evidence_requirement
    now = timezone.now()
    expires_at = now + timedelta(days=requirement.freshness_days) if requirement.freshness_days else None
    retain_until = now + timedelta(days=requirement.retention_days) if requirement.retention_days else None
    artifact = EvidenceArtifact(
        tenant=tenant, mapping=mapping, requirement=requirement, title=title,
        original_filename=safe_name, media_type=media_type, size_bytes=len(content),
        plaintext_sha256="0" * 64, ciphertext_sha256="0" * 64, storage_key=f"pending/{timezone.now().timestamp()}",
        wrapped_dek="pending", wrap_nonce="pending", content_nonce="pending", uploaded_by=actor,
        period_start=period_start, period_end=period_end, collected_at=collected_at,
        expires_at=expires_at, retain_until=retain_until,
    )
    artifact.clean()
    store = store or LocalEncryptedObjectStore()
    encrypted = store.encrypt_and_store(tenant_id=tenant.id, artifact_id=artifact.id, plaintext=content)
    try:
        artifact.storage_key = encrypted.storage_key
        artifact.wrapped_dek = encrypted.wrapped_dek
        artifact.wrap_nonce = encrypted.wrap_nonce
        artifact.content_nonce = encrypted.content_nonce
        artifact.plaintext_sha256 = encrypted.plaintext_sha256
        artifact.ciphertext_sha256 = encrypted.ciphertext_sha256
        artifact.size_bytes = encrypted.size_bytes
        artifact.save()
        CustodyEvent.objects.create(artifact=artifact, actor=actor, kind=CustodyEvent.Kind.UPLOADED, metadata={"size_bytes": artifact.size_bytes})
        AuditEvent.objects.create(
            tenant=tenant, actor=actor, action="evidence.uploaded", object_type="EvidenceArtifact",
            object_id=str(artifact.id), metadata={"media_type": media_type, "size_bytes": artifact.size_bytes},
        )
    except Exception:
        try:
            store.purge(encrypted.storage_key)
        except VaultError:
            pass
        raise
    return artifact


@transaction.atomic
def retrieve_evidence(*, artifact, actor, store=None, custody_kind=CustodyEvent.Kind.DOWNLOADED):
    membership = _membership(actor, artifact.tenant)
    if membership is None:
        raise PermissionDenied("Active tenant membership is required.")
    store = store or LocalEncryptedObjectStore()
    plaintext = store.retrieve_and_verify(artifact)
    CustodyEvent.objects.create(artifact=artifact, actor=actor, kind=custody_kind, metadata={})
    AuditEvent.objects.create(
        tenant=artifact.tenant, actor=actor, action="evidence.integrity_accessed",
        object_type="EvidenceArtifact", object_id=str(artifact.id), metadata={"purpose": custody_kind},
    )
    return plaintext


@transaction.atomic
def review_evidence(*, artifact, reviewer, decision, note, store=None):
    artifact = EvidenceArtifact.objects.select_for_update().select_related("tenant", "uploaded_by").get(pk=artifact.pk)
    if artifact.status != EvidenceStatus.UNDER_REVIEW or hasattr(artifact, "review"):
        raise ValidationError("Only unreviewed evidence can receive a decision.")
    membership = _membership(reviewer, artifact.tenant)
    if membership is None or membership.role not in {Membership.Role.COMPLIANCE_LEAD, Membership.Role.AUDITOR}:
        raise PermissionDenied("Compliance lead or auditor membership is required for evidence review.")
    if artifact.uploaded_by_id == reviewer.pk:
        raise ValidationError("Evidence uploaders cannot review their own artifact.")
    if decision not in EvidenceReview.Decision.values:
        raise ValidationError("A valid evidence review decision is required.")
    retrieve_evidence(artifact=artifact, actor=reviewer, store=store, custody_kind=CustodyEvent.Kind.INTEGRITY_VERIFIED)
    review = EvidenceReview.objects.create(
        artifact=artifact, reviewer=reviewer, decision=decision, note=note,
        integrity_verified_at=timezone.now(),
    )
    artifact.status = EvidenceStatus.ACCEPTED if decision == EvidenceReview.Decision.ACCEPTED else EvidenceStatus.REJECTED
    artifact.finalized_at = timezone.now()
    artifact.save(update_fields=["status", "finalized_at"])
    CustodyEvent.objects.create(artifact=artifact, actor=reviewer, kind=CustodyEvent.Kind.REVIEWED, metadata={"decision": decision})
    AuditEvent.objects.create(
        tenant=artifact.tenant, actor=reviewer, action="evidence.reviewed", object_type="EvidenceArtifact",
        object_id=str(artifact.id), metadata={"decision": decision},
    )
    return review


@transaction.atomic
def apply_hold(*, artifact, actor, reason):
    membership = _membership(actor, artifact.tenant)
    if membership is None or membership.role not in {Membership.Role.OWNER, Membership.Role.COMPLIANCE_LEAD, Membership.Role.AUDITOR}:
        raise PermissionDenied("Owner, compliance lead, or auditor membership is required for a retention hold.")
    if not reason.strip():
        raise ValidationError("A retention-hold reason is required.")
    hold = RetentionHold.objects.create(artifact=artifact, reason=reason, applied_by=actor)
    CustodyEvent.objects.create(artifact=artifact, actor=actor, kind=CustodyEvent.Kind.HOLD_APPLIED, metadata={"hold_id": str(hold.id)})
    return hold


@transaction.atomic
def release_hold(*, hold, actor, reason):
    membership = _membership(actor, hold.artifact.tenant)
    if membership is None or membership.role not in {Membership.Role.OWNER, Membership.Role.COMPLIANCE_LEAD}:
        raise PermissionDenied("Owner or compliance lead membership is required to release a retention hold.")
    if hold.released_at:
        raise ValidationError("Retention hold is already released.")
    if not reason.strip():
        raise ValidationError("A hold-release reason is required.")
    hold.released_by = actor
    hold.released_at = timezone.now()
    hold.release_reason = reason
    hold.save(update_fields=["released_by", "released_at", "release_reason"])
    CustodyEvent.objects.create(artifact=hold.artifact, actor=actor, kind=CustodyEvent.Kind.HOLD_RELEASED, metadata={"hold_id": str(hold.id)})
    return hold


@transaction.atomic
def purge_ciphertext(*, artifact, actor, store=None, now=None):
    artifact = EvidenceArtifact.objects.select_for_update().get(pk=artifact.pk)
    membership = _membership(actor, artifact.tenant)
    if membership is None or membership.role != Membership.Role.OWNER:
        raise PermissionDenied("Tenant owner membership is required for evidence purge.")
    now = now or timezone.now()
    if artifact.purged_at:
        raise ValidationError("Evidence ciphertext was already purged.")
    if artifact.retain_until is None or now < artifact.retain_until:
        raise ValidationError("Evidence cannot be purged before an approved retention period ends.")
    if artifact.has_active_hold:
        raise ValidationError("Evidence cannot be purged while a retention hold is active.")
    (store or LocalEncryptedObjectStore()).purge(artifact.storage_key)
    artifact.purged_at = now
    artifact.save(update_fields=["purged_at"])
    CustodyEvent.objects.create(artifact=artifact, actor=actor, kind=CustodyEvent.Kind.PURGED, metadata={})
    AuditEvent.objects.create(
        tenant=artifact.tenant, actor=actor, action="evidence.ciphertext_purged",
        object_type="EvidenceArtifact", object_id=str(artifact.id), metadata={},
    )
    return artifact
