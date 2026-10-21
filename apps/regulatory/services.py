import base64
import hashlib
import json
import os
import re
import zipfile
from io import BytesIO
from threading import Lock

from pypdf import PdfReader

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import models, transaction
from django.utils import timezone
from django.utils.text import get_valid_filename
from jsonschema import Draft202012Validator, FormatChecker

from apps.auditlog.models import AuditEvent
from apps.tenancy.models import Membership

from .models import (
    LegalSourceStatus,
    ClauseEvidence,
    ClauseEvidenceReview,
    ClauseAuditAssessment,
    AuditorReport,
    AuditorReportImport,
    AuditorReportImportRow,
    ClauseAIAnalysis,
    MappingReview,
    Obligation,
    ObligationControlMapping,
    Regulation,
    RegulatoryImportBatch,
    RegulatoryReview,
    RegulatorySource,
    RegulatoryVersion,
    SourceDocument,
    SubClause,
    TrustedSigningKey,
)
from apps.evidence.vault import LocalEncryptedObjectStore
from .ai import analyze_clause

_OCR_ENGINE = None
_OCR_LOCK = Lock()


@transaction.atomic
def create_auditor_account(*, tenant, actor, username, email, password):
    membership = Membership.objects.filter(user=actor, tenant=tenant, is_active=True).first()
    if membership is None or membership.role != Membership.Role.OWNER:
        raise PermissionDenied("Only the tenant owner may create an auditor account.")
    username = username.strip()
    if not username:
        raise ValidationError("Auditor username is required.")
    user_model = get_user_model()
    if user_model.objects.filter(username__iexact=username).exists():
        raise ValidationError("That username is already in use.")
    candidate = user_model(username=username, email=email.strip())
    validate_password(password, user=candidate)
    candidate.set_password(password)
    candidate.save()
    Membership.objects.create(user=candidate, tenant=tenant, role=Membership.Role.AUDITOR)
    AuditEvent.objects.create(
        tenant=tenant, actor=actor, action="auditor.account_created",
        object_type="User", object_id=str(candidate.pk), metadata={"username": candidate.username},
    )
    return candidate


@transaction.atomic
def upload_auditor_report(*, tenant, actor, title, filename, content):
    membership = Membership.objects.filter(user=actor, tenant=tenant, is_active=True).first()
    if membership is None or membership.role != Membership.Role.AUDITOR:
        raise PermissionDenied("Only an assigned auditor may upload an auditor report.")
    if not title.strip():
        raise ValidationError("Report title is required.")
    if not filename.lower().endswith(".pdf") or not content.startswith(b"%PDF"):
        raise ValidationError("Only a valid PDF auditor report may be uploaded.")
    if not content or len(content) > settings.EVIDENCE_MAX_UPLOAD_BYTES:
        raise ValidationError("Auditor report is empty or exceeds the configured upload limit.")
    safe_name = get_valid_filename(filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1])[:255]
    report = AuditorReport(
        tenant=tenant, title=title.strip(), original_filename=safe_name, size_bytes=len(content),
        plaintext_sha256="0" * 64, ciphertext_sha256="0" * 64, storage_key="pending",
        wrapped_dek="pending", wrap_nonce="pending", content_nonce="pending", uploaded_by=actor,
    )
    encrypted = LocalEncryptedObjectStore().encrypt_and_store(
        tenant_id=tenant.id, artifact_id=report.id, plaintext=content,
    )
    report.storage_key = encrypted.storage_key
    report.wrapped_dek = encrypted.wrapped_dek
    report.wrap_nonce = encrypted.wrap_nonce
    report.content_nonce = encrypted.content_nonce
    report.plaintext_sha256 = encrypted.plaintext_sha256
    report.ciphertext_sha256 = encrypted.ciphertext_sha256
    report.size_bytes = encrypted.size_bytes
    try:
        report.save()
    except Exception:
        LocalEncryptedObjectStore().purge(encrypted.storage_key)
        raise
    AuditEvent.objects.create(
        tenant=tenant, actor=actor, action="auditor.report_uploaded",
        object_type="AuditorReport", object_id=str(report.id),
        metadata={"sha256": report.plaintext_sha256, "size_bytes": report.size_bytes},
    )
    return report


def retrieve_auditor_report(*, report, actor):
    membership = Membership.objects.filter(user=actor, tenant=report.tenant, is_active=True).first()
    if membership is None or membership.role not in {
        Membership.Role.OWNER, Membership.Role.LEGAL_REVIEWER,
        Membership.Role.COMPLIANCE_LEAD, Membership.Role.AUDITOR,
    }:
        raise PermissionDenied("Your role cannot download auditor reports.")
    content = LocalEncryptedObjectStore().retrieve_and_verify(report)
    AuditEvent.objects.create(
        tenant=report.tenant, actor=actor, action="auditor.report_downloaded",
        object_type="AuditorReport", object_id=str(report.id),
        metadata={"sha256": report.plaintext_sha256},
    )
    return content


_AUDITOR_ROW = re.compile(
    r"^\s*(?:clause|regulation|reg\.?|r)?\s*(?P<clause>\d+(?:[.][\w()-]+)*)\s*"
    r"(?:[|:;\-–—]\s*|\s+)"
    r"(?P<status>not\s+applicable|n\s*/?\s*a|non[\s-]*compliant|partially?\s+compliant|partial|compliant)"
    r"(?:\s*[|:;\-–—]\s*|\s+)(?P<remarks>.+?)\s*$",
    re.IGNORECASE,
)
_AUDITOR_BLOCK = re.compile(
    r"(?:^|\n)\s*(?:clause|regulation|reg\.?|r)\s*(?P<clause>\d+(?:[.][\w()-]+)*)\s*"
    r"(?:[|:;\-–—]\s*|\s+)"
    r"(?P<status>not\s+applicable|n\s*/?\s*a|non[\s-]*compliant|partially?\s+compliant|partial|compliant)"
    r"(?:\s*[|:;\-–—]\s*|\s+)(?P<remarks>.*?)"
    r"(?=\n\s*(?:clause|regulation|reg\.?|r)\s*\d+(?:[.][\w()-]+)*\b|\Z)",
    re.IGNORECASE | re.DOTALL,
)


def _normalized_report_status(value):
    normalized = re.sub(r"[\s-]+", " ", value.strip().lower())
    if normalized in {"not applicable", "n / a", "n/a", "na"}:
        return AuditorReportImportRow.ReportedStatus.NOT_APPLICABLE
    if normalized == "compliant":
        return AuditorReportImportRow.ReportedStatus.COMPLIANT
    if normalized in {"partial", "partially compliant", "partial compliant"}:
        return AuditorReportImportRow.ReportedStatus.PARTIAL
    return AuditorReportImportRow.ReportedStatus.NON_COMPLIANT


def _extract_auditor_rows(pdf_bytes):
    try:
        reader = PdfReader(BytesIO(pdf_bytes))
        if reader.is_encrypted:
            raise ValidationError("The auditor PDF is encrypted and cannot be extracted.")
        lines = []
        for page in reader.pages:
            lines.extend((page.extract_text() or "").splitlines())
    except ValidationError:
        raise
    except Exception as exc:
        raise ValidationError("The auditor PDF text could not be extracted.") from exc
    rows = []
    for line in lines:
        match = _AUDITOR_ROW.match(" ".join(line.split()))
        if match:
            rows.append({
                "clause": match.group("clause"),
                "status": _normalized_report_status(match.group("status")),
                "remarks": match.group("remarks").strip(),
            })
    if not rows:
        text = "\n".join(lines)
        for match in _AUDITOR_BLOCK.finditer(text):
            remarks = " ".join(match.group("remarks").split())
            if remarks:
                rows.append({
                    "clause": match.group("clause"),
                    "status": _normalized_report_status(match.group("status")),
                    "remarks": remarks,
                })
    return rows


@transaction.atomic
def extract_auditor_report_decisions(*, report, actor):
    report = AuditorReport.objects.select_for_update().select_related("tenant", "uploaded_by").get(pk=report.pk)
    membership = Membership.objects.filter(user=actor, tenant=report.tenant, is_active=True).first()
    if membership is None or membership.role != Membership.Role.AUDITOR:
        raise PermissionDenied("Only an assigned auditor may extract their report decisions.")
    if hasattr(report, "decision_import"):
        raise ValidationError("This report already has a decision import draft.")
    extracted = _extract_auditor_rows(LocalEncryptedObjectStore().retrieve_and_verify(report))
    batch = AuditorReportImport.objects.create(
        report=report, created_by=actor,
        status=AuditorReportImport.Status.DRAFT if extracted else AuditorReportImport.Status.ERROR,
        extraction_note="" if extracted else "No supported clause/status/remarks rows were found. Upload a text-readable PDF using a supported row format.",
    )
    clauses = list(SubClause.objects.filter(regulation__version__source__tenant=report.tenant).select_related("regulation"))
    by_path = {}
    for clause in clauses:
        by_path.setdefault(clause.clause_path.strip().lower(), []).append(clause)
    seen = set()
    for number, item in enumerate(extracted, start=1):
        matches = by_path.get(item["clause"].strip().lower(), [])
        error = ""
        matched = matches[0] if len(matches) == 1 else None
        if not matches:
            error = "Clause reference was not found in this tenant framework."
        elif len(matches) > 1:
            error = "Clause reference is ambiguous across uploaded framework versions."
        elif matched.pk in seen:
            error = "Duplicate clause reference in the auditor report."
            matched = None
        if matched:
            seen.add(matched.pk)
        AuditorReportImportRow.objects.create(
            batch=batch, row_number=number, raw_clause_reference=item["clause"],
            reported_status=item["status"], remarks=item["remarks"],
            subclause=matched, validation_error=error,
        )
    if extracted and not batch.rows.filter(validation_error__gt="").exists():
        batch.status = AuditorReportImport.Status.READY
        batch.save(update_fields=["status"])
    AuditEvent.objects.create(
        tenant=report.tenant, actor=actor, action="auditor.report_decisions_extracted",
        object_type="AuditorReportImport", object_id=str(batch.id),
        metadata={"report_sha256": report.plaintext_sha256, "row_count": len(extracted), "status": batch.status},
    )
    return batch


@transaction.atomic
def update_auditor_import_row(*, row, actor, subclause, reported_status, remarks):
    row = AuditorReportImportRow.objects.select_for_update().select_related("batch__report__tenant").get(pk=row.pk)
    tenant = row.batch.report.tenant
    membership = Membership.objects.filter(user=actor, tenant=tenant, is_active=True).first()
    if membership is None or membership.role != Membership.Role.AUDITOR:
        raise PermissionDenied("Only an assigned auditor may correct report rows.")
    if row.batch.status == AuditorReportImport.Status.CONFIRMED:
        raise ValidationError("Confirmed report decisions cannot be changed.")
    if subclause.regulation.version.source.tenant_id != tenant.id:
        raise PermissionDenied("The selected clause is not available in this tenant.")
    if reported_status not in AuditorReportImportRow.ReportedStatus.values:
        raise ValidationError("Select a valid auditor-reported status.")
    if not remarks.strip():
        raise ValidationError("Auditor remarks are required.")
    duplicate = row.batch.rows.exclude(pk=row.pk).filter(subclause=subclause).exists()
    row.subclause = subclause
    row.raw_clause_reference = subclause.clause_path
    row.reported_status = reported_status
    row.remarks = remarks.strip()
    row.validation_error = "Duplicate clause selection." if duplicate else ""
    row.save()
    # Re-evaluate duplicate errors across the complete editable batch.
    for candidate in row.batch.rows.select_related("subclause"):
        if candidate.pk == row.pk:
            continue
        is_duplicate = candidate.subclause_id and row.batch.rows.exclude(pk=candidate.pk).filter(subclause_id=candidate.subclause_id).exists()
        expected = "Duplicate clause selection." if is_duplicate else ""
        if candidate.validation_error != expected:
            candidate.validation_error = expected
            candidate.save(update_fields=["validation_error"])
    ready = row.batch.rows.exists() and not row.batch.rows.filter(models.Q(subclause__isnull=True) | ~models.Q(validation_error="")).exists()
    row.batch.status = AuditorReportImport.Status.READY if ready else AuditorReportImport.Status.DRAFT
    row.batch.save(update_fields=["status"])
    return row


@transaction.atomic
def confirm_auditor_report_import(*, batch, actor):
    batch = AuditorReportImport.objects.select_for_update().select_related("report__tenant").get(pk=batch.pk)
    tenant = batch.report.tenant
    membership = Membership.objects.filter(user=actor, tenant=tenant, is_active=True).first()
    if membership is None or membership.role != Membership.Role.AUDITOR:
        raise PermissionDenied("Only an assigned auditor may confirm report decisions.")
    if batch.status == AuditorReportImport.Status.CONFIRMED:
        raise ValidationError("This auditor report import is already confirmed.")
    rows = list(batch.rows.select_related("subclause__regulation__version__source"))
    if not rows or any(not row.subclause_id or row.validation_error for row in rows):
        raise ValidationError("Resolve every unmatched, duplicate or invalid row before confirmation.")
    now = timezone.now()
    for row in rows:
        clause = row.subclause
        sequence = (clause.audit_assessments.aggregate(models.Max("sequence"))["sequence__max"] or 0) + 1
        if not clause_legal_ready(clause):
            compliance = ClauseAuditAssessment.ComplianceStatus.LEGAL_UNVERIFIED
        elif row.reported_status == AuditorReportImportRow.ReportedStatus.COMPLIANT:
            compliance = ClauseAuditAssessment.ComplianceStatus.READY
        elif row.reported_status == AuditorReportImportRow.ReportedStatus.NOT_APPLICABLE:
            compliance = ClauseAuditAssessment.ComplianceStatus.N_A
        else:
            compliance = ClauseAuditAssessment.ComplianceStatus.GAP
        decision = (
            ClauseAuditAssessment.Decision.ACCEPT
            if row.reported_status in {AuditorReportImportRow.ReportedStatus.COMPLIANT, AuditorReportImportRow.ReportedStatus.NOT_APPLICABLE}
            else ClauseAuditAssessment.Decision.REQUEST_UPDATE
            if row.reported_status == AuditorReportImportRow.ReportedStatus.PARTIAL
            else ClauseAuditAssessment.Decision.REJECT
        )
        active_evidence = list(ClauseEvidence.objects.filter(tenant=tenant, subclause=clause, withdrawn_at__isnull=True))
        snapshot = [
            {"id": str(item.id), "sha256": item.plaintext_sha256, "status": item.status, "filename": item.original_filename}
            for item in active_evidence
        ]
        snapshot.append({
            "auditor_report_id": str(batch.report_id), "sha256": batch.report.plaintext_sha256,
            "filename": batch.report.original_filename, "reported_status": row.reported_status,
            "import_row_id": str(row.id), "evidence_role": "ONSITE_AUDITOR_REPORT",
        })
        assessment = ClauseAuditAssessment.objects.create(
            tenant=tenant, subclause=clause, preliminary_analysis=clause.ai_analyses.first(),
            auditor_report=batch.report, reported_status=row.reported_status,
            sequence=sequence, decision=decision, compliance_status=compliance,
            note=row.remarks, gaps=row.remarks if decision != ClauseAuditAssessment.Decision.ACCEPT else "",
            evidence_snapshot=snapshot, reviewer=actor,
        )
        AuditorReportImportRow.objects.filter(pk=row.pk).update(confirmed_assessment=assessment)
    batch.status = AuditorReportImport.Status.CONFIRMED
    batch.confirmed_by = actor
    batch.confirmed_at = now
    batch.save(update_fields=["status", "confirmed_by", "confirmed_at"])
    AuditEvent.objects.create(
        tenant=tenant, actor=actor, action="auditor.report_import_confirmed",
        object_type="AuditorReportImport", object_id=str(batch.id),
        metadata={"report_sha256": batch.report.plaintext_sha256, "decision_count": len(rows)},
    )
    return batch


def clause_legal_ready(subclause):
    """Return whether this exact clause chain passed all legal/mapping gates."""
    version = subclause.regulation.version
    source = version.source
    obligations = list(subclause.obligations.all())
    return bool(
        source.legal_status == LegalSourceStatus.VERIFIED
        and version.approval_status == RegulatoryVersion.ApprovalStatus.APPROVED
        and subclause.regulation.legal_status == LegalSourceStatus.VERIFIED
        and subclause.legal_status == LegalSourceStatus.VERIFIED
        and obligations
        and all(
            obligation.legal_status == LegalSourceStatus.VERIFIED
            and obligation.control_mappings.filter(status=ObligationControlMapping.Status.APPROVED).exists()
            for obligation in obligations
        )
    )


@transaction.atomic
def review_clause_evidence(*, artifact, reviewer, decision, note):
    artifact = ClauseEvidence.objects.select_for_update().select_related("tenant", "uploaded_by").get(pk=artifact.pk)
    membership = Membership.objects.filter(user=reviewer, tenant=artifact.tenant, is_active=True).first()
    if membership is None or membership.role != Membership.Role.AUDITOR:
        raise PermissionDenied("An active auditor membership is required.")
    if artifact.withdrawn_at is not None or artifact.purged_at is not None:
        raise ValidationError("Withdrawn evidence cannot be reviewed.")
    if artifact.uploaded_by_id == reviewer.pk:
        raise ValidationError("Evidence uploaders cannot review their own file.")
    if hasattr(artifact, "independent_review"):
        raise ValidationError("This evidence file already has an immutable review decision.")
    if decision not in {ClauseEvidence.Status.ACCEPTED, ClauseEvidence.Status.REJECTED}:
        raise ValidationError("A valid evidence decision is required.")
    if not note.strip():
        raise ValidationError("A review note is required.")
    # Retrieval authenticates the encrypted object before a human decision is recorded.
    LocalEncryptedObjectStore().retrieve_and_verify(artifact)
    review = ClauseEvidenceReview.objects.create(
        artifact=artifact, reviewer=reviewer, decision=decision,
        note=note.strip(), integrity_sha256=artifact.plaintext_sha256,
    )
    artifact.status = decision
    artifact.reviewed_by = reviewer
    artifact.review_note = note.strip()
    artifact.reviewed_at = timezone.now()
    artifact.save(update_fields=["status", "reviewed_by", "review_note", "reviewed_at"])
    AuditEvent.objects.create(
        tenant=artifact.tenant, actor=reviewer, action="clause_evidence.independently_reviewed",
        object_type="ClauseEvidence", object_id=str(artifact.id),
        metadata={"decision": decision, "integrity_sha256": artifact.plaintext_sha256},
    )
    return review


@transaction.atomic
def assess_clause(*, subclause, reviewer, decision, note, gaps=""):
    subclause = SubClause.objects.select_for_update().select_related(
        "regulation__version__source"
    ).get(pk=subclause.pk)
    tenant = subclause.regulation.version.source.tenant
    membership = Membership.objects.filter(user=reviewer, tenant=tenant, is_active=True).first()
    if membership is None or membership.role != Membership.Role.AUDITOR:
        raise PermissionDenied("An active auditor membership is required.")
    if decision not in ClauseAuditAssessment.Decision.values:
        raise ValidationError("A valid clause assessment decision is required.")
    if not note.strip():
        raise ValidationError("An auditor conclusion is required.")
    active = list(ClauseEvidence.objects.filter(tenant=tenant, subclause=subclause, withdrawn_at__isnull=True).order_by("created_at"))
    if not active:
        raise ValidationError("The clause has no active evidence to assess.")
    if any(item.uploaded_by_id == reviewer.pk for item in active):
        raise ValidationError("Evidence uploaders cannot assess their own clause evidence set.")
    if decision == ClauseAuditAssessment.Decision.ACCEPT and any(item.status != ClauseEvidence.Status.ACCEPTED for item in active):
        raise ValidationError("Every active evidence file must be independently accepted before accepting the clause evidence set.")
    if decision == ClauseAuditAssessment.Decision.REQUEST_UPDATE and not gaps.strip():
        raise ValidationError("Requested evidence updates must identify the gaps.")

    legal_ready = clause_legal_ready(subclause)
    if not legal_ready:
        compliance_status = ClauseAuditAssessment.ComplianceStatus.LEGAL_UNVERIFIED
    elif decision == ClauseAuditAssessment.Decision.ACCEPT:
        compliance_status = ClauseAuditAssessment.ComplianceStatus.READY
    elif decision == ClauseAuditAssessment.Decision.REJECT:
        compliance_status = ClauseAuditAssessment.ComplianceStatus.GAP
    else:
        compliance_status = ClauseAuditAssessment.ComplianceStatus.INSUFFICIENT_EVIDENCE

    latest_analysis = subclause.ai_analyses.first()
    sequence = (subclause.audit_assessments.aggregate(models.Max("sequence"))["sequence__max"] or 0) + 1
    snapshot = [
        {"id": str(item.id), "sha256": item.plaintext_sha256, "status": item.status, "filename": item.original_filename}
        for item in active
    ]
    assessment = ClauseAuditAssessment.objects.create(
        tenant=tenant, subclause=subclause, preliminary_analysis=latest_analysis,
        sequence=sequence, decision=decision, compliance_status=compliance_status,
        note=note.strip(), gaps=gaps.strip(), evidence_snapshot=snapshot, reviewer=reviewer,
    )
    AuditEvent.objects.create(
        tenant=tenant, actor=reviewer, action="clause.audit_assessed",
        object_type="ClauseAuditAssessment", object_id=str(assessment.id),
        metadata={"clause": subclause.clause_path, "decision": decision,
                  "compliance_status": compliance_status, "sequence": sequence,
                  "evidence_count": len(snapshot), "legal_ready": legal_ready},
    )
    return assessment


def _local_ocr(image_bytes):
    """Extract visible text locally; evidence bytes never leave the process."""
    global _OCR_ENGINE
    try:
        from rapidocr_onnxruntime import RapidOCR
        with _OCR_LOCK:
            if _OCR_ENGINE is None:
                _OCR_ENGINE = RapidOCR()
            result, _ = _OCR_ENGINE(image_bytes)
    except Exception:
        return "", None
    lines = result or []
    text = "\n".join(str(line[1]) for line in lines if len(line) >= 3)
    confidence = round(sum(float(line[2]) for line in lines) / len(lines), 3) if lines else None
    return text, confidence


@transaction.atomic
def upload_source_pdf(*, tenant, actor, title, version_label, filename, content):
    membership = Membership.objects.filter(user=actor, tenant=tenant, is_active=True).first()
    if membership is None or membership.role not in {Membership.Role.OWNER, Membership.Role.LEGAL_REVIEWER}:
        raise PermissionDenied("Tenant owner or legal reviewer authorization is required.")
    if not filename.lower().endswith(".pdf") or not content.startswith(b"%PDF"):
        raise ValidationError("Only a valid PDF source document may be uploaded.")
    source = RegulatorySource.objects.create(tenant=tenant, title=title, sha256=hashlib.sha256(content).hexdigest())
    version = RegulatoryVersion.objects.create(source=source, version_label=version_label, approval_status=RegulatoryVersion.ApprovalStatus.UNDER_REVIEW)
    document = SourceDocument(source=source, original_filename=get_valid_filename(filename)[:255], size_bytes=len(content), plaintext_sha256="0" * 64, ciphertext_sha256="0" * 64, storage_key="pending", wrapped_dek="pending", wrap_nonce="pending", content_nonce="pending", uploaded_by=actor)
    encrypted = LocalEncryptedObjectStore().encrypt_and_store(tenant_id=tenant.id, artifact_id=document.id, plaintext=content)
    document.storage_key = encrypted.storage_key
    document.wrapped_dek = encrypted.wrapped_dek
    document.wrap_nonce = encrypted.wrap_nonce
    document.content_nonce = encrypted.content_nonce
    document.plaintext_sha256 = encrypted.plaintext_sha256
    document.ciphertext_sha256 = encrypted.ciphertext_sha256
    document.size_bytes = encrypted.size_bytes
    try:
        document.save()
    except Exception:
        LocalEncryptedObjectStore().purge(encrypted.storage_key)
        raise
    AuditEvent.objects.create(tenant=tenant, actor=actor, action="regulatory_source.pdf_uploaded", object_type="SourceDocument", object_id=str(document.id), metadata={"sha256": document.plaintext_sha256, "size_bytes": document.size_bytes})
    return source, version


def _source_regulations(pdf_bytes):
    """Return exact, display-only regulation chunks from a supplied PDF.

    Extraction is intentionally conservative: it finds only numbered headings
    which carry a first subparagraph ``(1)``.  It does not create obligations,
    infer evidence, or change any legal status.
    """
    try:
        reader = PdfReader(BytesIO(pdf_bytes))
        if reader.is_encrypted:
            raise ValidationError("The PDF is encrypted and cannot be reviewed in this workspace.")
        pages = [page.extract_text() or "" for page in reader.pages]
    except ValidationError:
        raise
    except Exception as exc:
        raise ValidationError("The PDF text could not be extracted. Upload a text-readable source PDF.") from exc

    text = "\n\n".join(f"[Source page {index}]\n{page}" for index, page in enumerate(pages, start=1))
    heading = re.compile(
        r"^(?P<number>\d{1,3})\.\s+(?P<title>.+?)\.\s*(?:[^\n]*\(\s*1\s*\)|[^\n]*\n\s*\(\s*1\s*\))",
        re.MULTILINE,
    )
    matches = list(heading.finditer(text))
    extracted = []
    for index, match in enumerate(matches):
        number = int(match.group("number"))
        # Definitions also include numbered explanatory lists; only regulation
        # headings begin a source page or follow a normal text paragraph.
        title = " ".join(match.group("title").split())
        if not title or number > 250:
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        chunk = text[match.start():end].strip()
        page = next((str(page_number) for page_number in range(len(pages), 0, -1)
                     if f"[Source page {page_number}]" in text[:match.start()]), "")
        extracted.append({"number": number, "title": title, "page": page, "excerpt": chunk})
    # Do not silently accept malformed duplicate coordinates.
    numbers = [item["number"] for item in extracted]
    if not extracted or len(numbers) != len(set(numbers)):
        raise ValidationError("No unambiguous numbered regulation headings were found in this PDF.")
    return extracted


@transaction.atomic
def extract_source_regulations(*, version, actor):
    """Create pending-review clause cards from an encrypted tenant source."""
    version = RegulatoryVersion.objects.select_for_update().select_related("source", "source__document").get(pk=version.pk)
    membership = Membership.objects.filter(user=actor, tenant=version.source.tenant, is_active=True).first()
    if membership is None or membership.role not in {Membership.Role.OWNER, Membership.Role.LEGAL_REVIEWER}:
        raise PermissionDenied("Tenant owner or legal reviewer authorization is required.")
    if Regulation.objects.filter(version=version).exists():
        raise ValidationError("This version already has clause cards; extraction never overwrites an existing register.")
    try:
        document = version.source.document
    except SourceDocument.DoesNotExist as exc:
        raise ValidationError("This source has no encrypted PDF to extract.") from exc
    extracted = _source_regulations(LocalEncryptedObjectStore().retrieve_and_verify(document))
    for item in extracted:
        regulation = Regulation.objects.create(
            version=version, number=item["number"], title=item["title"],
            source_page=item["page"], source_excerpt=item["excerpt"],
            legal_status=LegalSourceStatus.SOURCE_PENDING,
        )
        SubClause.objects.create(
            regulation=regulation, clause_path=str(item["number"]), title=item["title"],
            source_page=item["page"], legal_status=LegalSourceStatus.SOURCE_PENDING,
        )
    AuditEvent.objects.create(
        tenant=version.source.tenant, actor=actor, action="regulatory_source.headings_extracted",
        object_type="RegulatoryVersion", object_id=str(version.id),
        metadata={"count": len(extracted), "first": extracted[0]["number"], "last": extracted[-1]["number"]},
    )
    return extracted


@transaction.atomic
def upload_clause_evidence(*, tenant, actor, subclause, title, filename, content):
    membership = Membership.objects.filter(user=actor, tenant=tenant, is_active=True).first()
    if membership is None or membership.role not in {Membership.Role.OWNER, Membership.Role.COMPLIANCE_LEAD}:
        raise PermissionDenied("Only tenant owners or compliance leads may submit clause evidence.")
    if subclause.regulation.version.source.tenant_id != tenant.id:
        raise PermissionDenied("Clause is not available in this tenant.")
    if not content or len(content) > settings.EVIDENCE_MAX_UPLOAD_BYTES:
        raise ValidationError("Evidence file is empty or exceeds the configured upload limit.")
    safe_name = get_valid_filename(filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1])[:255]
    if not safe_name:
        raise ValidationError("Evidence filename is invalid.")
    artifact = ClauseEvidence(tenant=tenant, subclause=subclause, title=title, original_filename=safe_name,
        size_bytes=len(content), plaintext_sha256="0" * 64, ciphertext_sha256="0" * 64,
        storage_key="pending", wrapped_dek="pending", wrap_nonce="pending", content_nonce="pending", uploaded_by=actor)
    artifact.clean()
    encrypted = LocalEncryptedObjectStore().encrypt_and_store(tenant_id=tenant.id, artifact_id=artifact.id, plaintext=content)
    try:
        artifact.storage_key, artifact.wrapped_dek = encrypted.storage_key, encrypted.wrapped_dek
        artifact.wrap_nonce, artifact.content_nonce = encrypted.wrap_nonce, encrypted.content_nonce
        artifact.plaintext_sha256, artifact.ciphertext_sha256, artifact.size_bytes = encrypted.plaintext_sha256, encrypted.ciphertext_sha256, encrypted.size_bytes
        artifact.save()
    except Exception:
        LocalEncryptedObjectStore().purge(encrypted.storage_key)
        raise
    AuditEvent.objects.create(tenant=tenant, actor=actor, action="clause_evidence.submitted", object_type="ClauseEvidence", object_id=str(artifact.id), metadata={"size_bytes": artifact.size_bytes})
    return artifact


@transaction.atomic
def analyze_clause_evidence(*, tenant, actor, subclause):
    if subclause.regulation.version.source.tenant_id != tenant.id:
        raise PermissionDenied("Clause is not available in this tenant.")
    evidence = list(ClauseEvidence.objects.filter(tenant=tenant, subclause=subclause, withdrawn_at__isnull=True))
    documents = []
    for item in evidence:
        raw = LocalEncryptedObjectStore().retrieve_and_verify(item)
        text = ""
        embedded_images = 0
        ocr_used = False
        ocr_confidence = None
        if item.original_filename.lower().endswith((".txt", ".csv")):
            text = raw.decode("utf-8", errors="replace")
        elif item.original_filename.lower().endswith(".pdf"):
            text = "\n".join(page.extract_text() or "" for page in PdfReader(BytesIO(raw)).pages)
        elif item.original_filename.lower().endswith(".docx"):
            try:
                with zipfile.ZipFile(BytesIO(raw)) as archive:
                    xml = archive.read("word/document.xml").decode("utf-8", errors="replace")
                    media = [name for name in archive.namelist() if name.startswith("word/media/")][:10]
                    embedded_images = len(media)
                    text = re.sub(r"<[^>]+>", " ", xml).replace("&amp;", "&")
                    if len(text.strip()) < 40 and media:
                        ocr_parts, confidences = [], []
                        for name in media:
                            extracted, confidence = _local_ocr(archive.read(name))
                            if extracted:
                                ocr_parts.append(extracted)
                            if confidence is not None:
                                confidences.append(confidence)
                        text = "\n".join(ocr_parts)
                        ocr_used = True
                        ocr_confidence = round(sum(confidences) / len(confidences), 3) if confidences else None
            except (KeyError, zipfile.BadZipFile):
                pass
        elif item.original_filename.lower().endswith(".xlsx"):
            try:
                with zipfile.ZipFile(BytesIO(raw)) as archive:
                    parts = []
                    for name in archive.namelist():
                        if name == "xl/sharedStrings.xml" or name.startswith("xl/worksheets/sheet"):
                            parts.append(re.sub(r"<[^>]+>", " ", archive.read(name).decode("utf-8", errors="replace")))
                    text = " ".join(parts)
            except zipfile.BadZipFile:
                pass
        elif item.original_filename.lower().endswith((".jpg", ".jpeg", ".png")):
            text, ocr_confidence = _local_ocr(raw)
            ocr_used = True
        documents.append({"filename": item.original_filename, "text": text, "embedded_images": embedded_images, "size_bytes": item.size_bytes, "ocr_used": ocr_used, "ocr_confidence": ocr_confidence})
    obligations = list(subclause.obligations.all())
    legal_mapping_verified = bool(obligations) and (
        subclause.regulation.version.source.legal_status == LegalSourceStatus.VERIFIED
        and subclause.regulation.version.approval_status == RegulatoryVersion.ApprovalStatus.APPROVED
        and subclause.regulation.legal_status == LegalSourceStatus.VERIFIED
        and subclause.legal_status == LegalSourceStatus.VERIFIED
        and all(obligation.legal_status == LegalSourceStatus.VERIFIED and obligation.control_mappings.filter(status=ObligationControlMapping.Status.APPROVED).exists() for obligation in obligations)
    )
    result = analyze_clause(
        clause_text=subclause.regulation.source_excerpt,
        evidence_documents=documents,
        legal_mapping_verified=legal_mapping_verified,
    )
    return ClauseAIAnalysis.objects.create(subclause=subclause, status=result["status"], result=result,
        evidence_hashes=[item.plaintext_sha256 for item in evidence], model_name=result.get("engine", "LOCAL_RULES_V2"), created_by=actor)


@transaction.atomic
def withdraw_clause_evidence(*, tenant, actor, artifact):
    membership = Membership.objects.filter(user=actor, tenant=tenant, is_active=True).first()
    if membership is None or membership.role not in {Membership.Role.OWNER, Membership.Role.COMPLIANCE_LEAD}:
        raise PermissionDenied("Only an owner or compliance lead can withdraw evidence.")
    if artifact.tenant_id != tenant.id or artifact.withdrawn_at is not None:
        raise ValidationError("Evidence is unavailable or already withdrawn.")
    LocalEncryptedObjectStore().purge(artifact.storage_key)
    now = timezone.now()
    artifact.withdrawn_at = now
    artifact.withdrawn_by = actor
    artifact.purged_at = now
    artifact.wrapped_dek = ""
    artifact.wrap_nonce = ""
    artifact.content_nonce = ""
    artifact.save(update_fields=["withdrawn_at", "withdrawn_by", "purged_at", "wrapped_dek", "wrap_nonce", "content_nonce"])
    AuditEvent.objects.create(
        tenant=tenant, actor=actor, action="clause_evidence.withdrawn_and_purged",
        object_type="ClauseEvidence", object_id=str(artifact.id),
        metadata={"plaintext_sha256": artifact.plaintext_sha256},
    )
    return artifact

MAX_MANIFEST_BYTES = 2 * 1024 * 1024
PACK_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "source", "version", "regulations"],
    "properties": {
        "schema_version": {"const": 1},
        "source": {
            "type": "object", "additionalProperties": False,
            "required": ["title", "authority_url", "gazette_identifier", "sha256"],
            "properties": {
                "title": {"type": "string", "minLength": 1, "maxLength": 255},
                "authority_url": {"type": "string", "format": "uri", "maxLength": 500},
                "gazette_identifier": {"type": "string", "minLength": 1, "maxLength": 120},
                "sha256": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
            },
        },
        "version": {
            "type": "object", "additionalProperties": False,
            "required": ["label"],
            "properties": {"label": {"type": "string", "minLength": 1, "maxLength": 80}, "effective_date": {"type": ["string", "null"], "format": "date"}},
        },
        "regulations": {
            "type": "array", "minItems": 1, "maxItems": 84,
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["number", "title", "source_page", "subclauses"],
                "properties": {
                    "number": {"type": "integer", "minimum": 1, "maximum": 84},
                    "title": {"type": "string", "minLength": 1, "maxLength": 255},
                    "source_page": {"type": "string", "minLength": 1, "maxLength": 40},
                    "subclauses": {"type": "array", "maxItems": 1000, "items": {"$ref": "#/$defs/subclause"}},
                },
            },
        },
    },
    "$defs": {
        "subclause": {
            "type": "object", "additionalProperties": False,
            "required": ["path", "title", "source_page", "obligations"],
            "properties": {
                "path": {"type": "string", "minLength": 1, "maxLength": 120},
                "parent_path": {"type": ["string", "null"], "maxLength": 120},
                "title": {"type": "string", "minLength": 1, "maxLength": 500},
                "source_page": {"type": "string", "minLength": 1, "maxLength": 40},
                "obligations": {"type": "array", "maxItems": 1000, "items": {"$ref": "#/$defs/obligation"}},
            },
        },
        "obligation": {
            "type": "object", "additionalProperties": False,
            "required": ["key", "paraphrase", "requirement_type"],
            "properties": {
                "key": {"type": "string", "minLength": 1, "maxLength": 120},
                "paraphrase": {"type": "string", "minLength": 1, "maxLength": 10000},
                "requirement_type": {"type": "string", "minLength": 1, "maxLength": 80},
                "evidence_specification": {"type": "string", "maxLength": 10000},
                "control_reference": {"type": "string", "maxLength": 120},
                "test_procedure_reference": {"type": "string", "maxLength": 120},
            },
        },
    },
}


def canonical_manifest(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def parse_and_verify(manifest_bytes, signature_bytes, signing_key):
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise ValidationError("Manifest exceeds the 2 MiB limit.")
    try:
        data = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("Manifest must be valid UTF-8 JSON.") from exc
    errors = sorted(
        Draft202012Validator(PACK_SCHEMA, format_checker=FormatChecker()).iter_errors(data),
        key=lambda item: list(item.path),
    )
    if errors:
        error = errors[0]
        raise ValidationError(f"Manifest schema error at {list(error.path)}: {error.message}")
    canonical = canonical_manifest(data)
    try:
        public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(signing_key.public_key_base64, validate=True))
        public_key.verify(signature_bytes, canonical)
    except (InvalidSignature, ValueError) as exc:
        raise ValidationError("Regulatory pack signature is invalid.") from exc
    return data, canonical


def _validate_uniqueness(data):
    numbers = [item["number"] for item in data["regulations"]]
    if len(numbers) != len(set(numbers)):
        raise ValidationError("Regulation numbers must be unique within a pack.")
    for regulation in data["regulations"]:
        paths = [item["path"] for item in regulation["subclauses"]]
        if len(paths) != len(set(paths)):
            raise ValidationError(f"Duplicate subclause path in regulation {regulation['number']}.")
        path_set = set(paths)
        parents = {item["path"]: item.get("parent_path") for item in regulation["subclauses"]}
        for clause in regulation["subclauses"]:
            if clause.get("parent_path") and clause["parent_path"] not in path_set:
                raise ValidationError(f"Unknown parent path {clause['parent_path']}.")
            keys = [item["key"] for item in clause["obligations"]]
            if len(keys) != len(set(keys)):
                raise ValidationError(f"Duplicate obligation key under {clause['path']}.")
        for path in paths:
            visited, cursor = set(), path
            while parents.get(cursor):
                if cursor in visited:
                    raise ValidationError(f"Cyclic subclause hierarchy in regulation {regulation['number']}.")
                visited.add(cursor)
                cursor = parents[cursor]


@transaction.atomic
def import_pack(*, tenant, actor, signing_key, manifest_bytes, signature_bytes):
    if signing_key.tenant_id != tenant.id or not signing_key.is_active:
        raise PermissionDenied("Signing key is not active for this tenant.")
    data, canonical = parse_and_verify(manifest_bytes, signature_bytes, signing_key)
    _validate_uniqueness(data)
    source_data = data["source"]
    source, created = RegulatorySource.objects.get_or_create(
        tenant=tenant, gazette_identifier=source_data["gazette_identifier"],
        defaults={"title": source_data["title"], "authority_url": source_data["authority_url"], "sha256": source_data["sha256"].lower()},
    )
    if source.sha256 and source.sha256.lower() != source_data["sha256"].lower():
        raise ValidationError("Gazette identifier already exists with a different source hash.")
    if not created:
        source.title = source_data["title"]
        source.authority_url = source_data["authority_url"]
        source.sha256 = source_data["sha256"].lower()
        source.save(update_fields=["title", "authority_url", "sha256"])
    version_data = data["version"]
    if RegulatoryVersion.objects.filter(source=source, version_label=version_data["label"]).exists():
        raise ValidationError("This source version has already been imported.")
    version = RegulatoryVersion.objects.create(
        source=source, version_label=version_data["label"], effective_date=version_data.get("effective_date"),
        approval_status=RegulatoryVersion.ApprovalStatus.UNDER_REVIEW,
    )
    for regulation_data in data["regulations"]:
        regulation = Regulation.objects.create(
            version=version, number=regulation_data["number"], title=regulation_data["title"], source_page=regulation_data["source_page"],
        )
        clauses = {}
        for clause_data in regulation_data["subclauses"]:
            clauses[clause_data["path"]] = SubClause.objects.create(
                regulation=regulation, clause_path=clause_data["path"], title=clause_data["title"], source_page=clause_data["source_page"],
            )
        for clause_data in regulation_data["subclauses"]:
            clause = clauses[clause_data["path"]]
            if clause_data.get("parent_path"):
                clause.parent = clauses[clause_data["parent_path"]]
                clause.save(update_fields=["parent"])
            for obligation_data in clause_data["obligations"]:
                Obligation.objects.create(
                    subclause=clause, obligation_key=obligation_data["key"], paraphrase=obligation_data["paraphrase"],
                    requirement_type=obligation_data["requirement_type"], evidence_specification=obligation_data.get("evidence_specification", ""),
                    control_reference=obligation_data.get("control_reference", ""), test_procedure_reference=obligation_data.get("test_procedure_reference", ""),
                )
    batch = RegulatoryImportBatch.objects.create(
        tenant=tenant, version=version, signing_key=signing_key, manifest_sha256=hashlib.sha256(canonical).hexdigest(),
        signature_base64=base64.b64encode(signature_bytes).decode(), imported_by=actor,
    )
    AuditEvent.objects.create(tenant=tenant, actor=actor, action="regulatory_pack.imported", object_type="RegulatoryImportBatch", object_id=str(batch.id), metadata={"manifest_sha256": batch.manifest_sha256})
    return version


@transaction.atomic
def review_version(*, version, reviewer, kind, decision, note=""):
    if kind not in RegulatoryReview.Kind.values or decision not in RegulatoryReview.Decision.values:
        raise ValidationError("Valid review kind and decision are required.")
    if version.approval_status != RegulatoryVersion.ApprovalStatus.UNDER_REVIEW:
        raise ValidationError("Only versions under review can receive a decision.")
    blockers = version_review_blockers(version)
    if decision == RegulatoryReview.Decision.APPROVED and blockers:
        raise ValidationError("Regulatory version is not review-ready: " + ", ".join(blockers))
    membership = Membership.objects.filter(user=reviewer, tenant=version.source.tenant, is_active=True).first()
    required_role = Membership.Role.LEGAL_REVIEWER if kind == RegulatoryReview.Kind.LEGAL else Membership.Role.COMPLIANCE_LEAD
    if membership is None or membership.role != required_role:
        raise PermissionDenied(f"{required_role} membership is required for this review.")
    if version.reviews.filter(reviewer=reviewer).exists():
        raise ValidationError("The same person cannot perform both regulatory reviews.")
    review = RegulatoryReview.objects.create(version=version, reviewer=reviewer, kind=kind, decision=decision, note=note)
    approvals = version.reviews.filter(decision=RegulatoryReview.Decision.APPROVED)
    if decision == RegulatoryReview.Decision.REJECTED:
        version.approval_status = RegulatoryVersion.ApprovalStatus.DRAFT
        version.save(update_fields=["approval_status"])
    elif approvals.filter(kind=RegulatoryReview.Kind.LEGAL).exists() and approvals.filter(kind=RegulatoryReview.Kind.COMPLIANCE).exists():
        now = timezone.now()
        source = version.source
        source.legal_status = LegalSourceStatus.VERIFIED
        source.reviewed_by = reviewer
        source.reviewed_at = now
        source.verification_completed_at = now
        source.save()
        version.approval_status = RegulatoryVersion.ApprovalStatus.APPROVED
        version.save(update_fields=["approval_status"])
        version.regulations.update(legal_status=LegalSourceStatus.VERIFIED)
        SubClause.objects.filter(regulation__version=version).update(legal_status=LegalSourceStatus.VERIFIED)
        Obligation.objects.filter(subclause__regulation__version=version).update(legal_status=LegalSourceStatus.VERIFIED)
    AuditEvent.objects.create(tenant=version.source.tenant, actor=reviewer, action="regulatory_version.reviewed", object_type="RegulatoryVersion", object_id=str(version.id), metadata={"kind": kind, "decision": decision})
    return review


def version_review_blockers(version):
    source = version.source
    blockers = []
    if not source.authority_url:
        blockers.append("SOURCE_AUTHORITY_URL_MISSING")
    if not source.gazette_identifier:
        blockers.append("GAZETTE_IDENTIFIER_MISSING")
    if not source.sha256:
        blockers.append("SOURCE_HASH_MISSING")
    try:
        document = source.document
    except SourceDocument.DoesNotExist:
        document = None
    if document and document.plaintext_sha256 != source.sha256:
        blockers.append("SOURCE_DOCUMENT_HASH_MISMATCH")
    regulations = version.regulations.all()
    if not regulations.exists():
        blockers.append("NO_REGULATIONS")
    elif regulations.filter(source_page="").exists():
        blockers.append("REGULATION_SOURCE_PAGE_MISSING")
    if document and regulations.filter(source_excerpt="").exists():
        blockers.append("REGULATION_SOURCE_TEXT_MISSING")
    subclauses = SubClause.objects.filter(regulation__version=version)
    if not subclauses.exists():
        blockers.append("NO_SUBCLAUSES")
    elif subclauses.filter(source_page="").exists():
        blockers.append("SUBCLAUSE_SOURCE_PAGE_MISSING")
    if subclauses.filter(obligations__isnull=True).exists():
        blockers.append("OBLIGATIONS_MISSING")
    return blockers


@transaction.atomic
def update_source_metadata(*, version, actor, authority_url, gazette_identifier, effective_date=None):
    membership = Membership.objects.filter(user=actor, tenant=version.source.tenant, is_active=True).first()
    if membership is None or membership.role not in {Membership.Role.OWNER, Membership.Role.LEGAL_REVIEWER}:
        raise PermissionDenied("Only a tenant owner or legal reviewer may update source metadata.")
    if version.approval_status == RegulatoryVersion.ApprovalStatus.APPROVED:
        raise ValidationError("Approved source metadata is immutable; import a new version.")
    source = version.source
    source.authority_url = authority_url.strip()
    source.gazette_identifier = gazette_identifier.strip()
    source.save(update_fields=["authority_url", "gazette_identifier"])
    if effective_date:
        version.effective_date = effective_date
        version.save(update_fields=["effective_date"])
    AuditEvent.objects.create(
        tenant=source.tenant, actor=actor, action="regulatory_source.metadata_updated",
        object_type="RegulatoryVersion", object_id=str(version.id),
        metadata={"gazette_identifier": source.gazette_identifier},
    )
    return version


@transaction.atomic
def create_obligation(*, subclause, actor, obligation_key, paraphrase, requirement_type, evidence_specification=""):
    tenant = subclause.regulation.version.source.tenant
    membership = Membership.objects.filter(user=actor, tenant=tenant, is_active=True).first()
    if membership is None or membership.role not in {Membership.Role.OWNER, Membership.Role.LEGAL_REVIEWER}:
        raise PermissionDenied("Only a tenant owner or legal reviewer may register source obligations.")
    if subclause.regulation.version.approval_status == RegulatoryVersion.ApprovalStatus.APPROVED:
        raise ValidationError("Approved obligations are immutable; import a new source version.")
    item = Obligation.objects.create(
        subclause=subclause, obligation_key=obligation_key.strip(), paraphrase=paraphrase.strip(),
        requirement_type=requirement_type.strip(), evidence_specification=evidence_specification.strip(),
    )
    AuditEvent.objects.create(
        tenant=tenant, actor=actor, action="regulatory_obligation.registered",
        object_type="Obligation", object_id=str(item.id), metadata={"obligation_key": item.obligation_key},
    )
    return item


def coverage_report(version):
    from apps.evidence.models import EvidenceArtifact, EvidenceStatus

    obligations = Obligation.objects.filter(subclause__regulation__version=version)
    issues = []
    if version.source.legal_status != LegalSourceStatus.VERIFIED:
        issues.append("LEGAL_SOURCE_UNVERIFIED")
    if version.approval_status != RegulatoryVersion.ApprovalStatus.APPROVED:
        issues.append("DUAL_REVIEW_INCOMPLETE")
    if version.regulations.count() != 84:
        issues.append("NUMBERED_REGULATION_COVERAGE_INCOMPLETE")
    if not obligations.exists():
        issues.append("NO_OBLIGATIONS_IMPORTED")
    unmapped = obligations.exclude(control_mappings__status=ObligationControlMapping.Status.APPROVED)
    if unmapped.exists():
        issues.append("CONTROL_MAPPING_MISSING")
    if unmapped.exists():
        issues.append("TEST_PROCEDURE_MISSING")
    if unmapped.exists():
        issues.append("EVIDENCE_SPECIFICATION_MISSING")
    approved_mapping_ids = ObligationControlMapping.objects.filter(
        obligation__subclause__regulation__version=version,
        status=ObligationControlMapping.Status.APPROVED,
    ).values_list("id", flat=True)
    accepted = EvidenceArtifact.objects.filter(
        mapping_id__in=approved_mapping_ids, status=EvidenceStatus.ACCEPTED, purged_at__isnull=True,
    )
    current_accepted = accepted.filter(models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=timezone.now()))
    mapped_obligation_ids = set(
        ObligationControlMapping.objects.filter(id__in=approved_mapping_ids).values_list("obligation_id", flat=True)
    )
    evidenced_obligation_ids = set(current_accepted.values_list("mapping__obligation_id", flat=True))
    if mapped_obligation_ids - evidenced_obligation_ids:
        issues.append("EVIDENCE_MISSING_OR_UNACCEPTED")
    if accepted.filter(expires_at__isnull=False, expires_at__lte=timezone.now()).exists():
        issues.append("EVIDENCE_STALE")
    return {
        "ready": not issues, "issues": issues, "regulations": version.regulations.count(),
        "obligations": obligations.count(),
        "approved_mappings": ObligationControlMapping.objects.filter(
            obligation__subclause__regulation__version=version,
            status=ObligationControlMapping.Status.APPROVED,
        ).count(),
    }


def compare_versions(base, target):
    def snapshot(version):
        result = {}
        for regulation in version.regulations.prefetch_related("subclauses__obligations"):
            result[f"R{regulation.number:02d}"] = {"title": regulation.title, "page": regulation.source_page}
            for clause in regulation.subclauses.all():
                result[f"R{regulation.number:02d}/{clause.clause_path}"] = {"title": clause.title, "page": clause.source_page}
                for obligation in clause.obligations.all():
                    result[f"R{regulation.number:02d}/{clause.clause_path}/{obligation.obligation_key}"] = {"paraphrase": obligation.paraphrase, "type": obligation.requirement_type}
        return result
    before, after = snapshot(base), snapshot(target)
    return {
        "added": sorted(after.keys() - before.keys()),
        "removed": sorted(before.keys() - after.keys()),
        "changed": sorted(key for key in before.keys() & after.keys() if before[key] != after[key]),
    }


@transaction.atomic
def create_mapping(*, tenant, actor, obligation, control, test_procedure, evidence_requirement, rationale):
    membership = Membership.objects.filter(user=actor, tenant=tenant, is_active=True).first()
    if membership is None or membership.role not in {Membership.Role.OWNER, Membership.Role.COMPLIANCE_LEAD}:
        raise PermissionDenied("Only tenant owners or compliance leads may submit mappings.")
    mapping = ObligationControlMapping(
        tenant=tenant, obligation=obligation, control=control, test_procedure=test_procedure,
        evidence_requirement=evidence_requirement, rationale=rationale, created_by=actor,
    )
    mapping.save()
    AuditEvent.objects.create(
        tenant=tenant, actor=actor, action="obligation_mapping.submitted",
        object_type="ObligationControlMapping", object_id=str(mapping.id), metadata={"status": mapping.status},
    )
    return mapping


@transaction.atomic
def review_mapping(*, mapping, reviewer, kind, decision, note=""):
    mapping = ObligationControlMapping.objects.select_for_update().select_related("tenant").get(pk=mapping.pk)
    if kind not in MappingReview.Kind.values or decision not in MappingReview.Decision.values:
        raise ValidationError("Valid mapping review kind and decision are required.")
    if mapping.status != ObligationControlMapping.Status.UNDER_REVIEW:
        raise ValidationError("Only mappings under review can receive a decision.")
    membership = Membership.objects.filter(user=reviewer, tenant=mapping.tenant, is_active=True).first()
    required_role = Membership.Role.LEGAL_REVIEWER if kind == MappingReview.Kind.LEGAL else Membership.Role.COMPLIANCE_LEAD
    if membership is None or membership.role != required_role:
        raise PermissionDenied(f"{required_role} membership is required for this mapping review.")
    if mapping.created_by_id == reviewer.pk:
        raise ValidationError("A mapping author cannot approve or reject their own mapping.")
    if mapping.reviews.filter(reviewer=reviewer).exists():
        raise ValidationError("The same person cannot perform both mapping reviews.")
    review = MappingReview.objects.create(mapping=mapping, reviewer=reviewer, kind=kind, decision=decision, note=note)
    if decision == MappingReview.Decision.REJECTED:
        mapping.status = ObligationControlMapping.Status.REJECTED
        mapping.finalized_at = timezone.now()
        mapping.save(update_fields=["status", "finalized_at"])
    else:
        approvals = mapping.reviews.filter(decision=MappingReview.Decision.APPROVED)
        if approvals.filter(kind=MappingReview.Kind.LEGAL).exists() and approvals.filter(kind=MappingReview.Kind.COMPLIANCE).exists():
            mapping.status = ObligationControlMapping.Status.APPROVED
            mapping.finalized_at = timezone.now()
            mapping.save(update_fields=["status", "finalized_at"])
    AuditEvent.objects.create(
        tenant=mapping.tenant, actor=reviewer, action="obligation_mapping.reviewed",
        object_type="ObligationControlMapping", object_id=str(mapping.id), metadata={"kind": kind, "decision": decision},
    )
    return review
