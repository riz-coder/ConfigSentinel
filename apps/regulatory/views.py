from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import close_old_connections
from django.db.models import OuterRef, Subquery
from django.utils import timezone
from django.shortcuts import get_object_or_404, redirect, render
from django.http import HttpResponse
import csv
from threading import Thread

from apps.tenancy.access import tenant_for_request

from apps.tenancy.models import Membership

from apps.auditlog.models import AuditEvent

from .models import (
    ControlDefinition, EvidenceRequirement, LegalSourceStatus, MappingReview, Obligation,
    ObligationControlMapping, Regulation, RegulatoryReview, RegulatorySource, ClauseEvidence,
    RegulatoryVersion, SubClause, TestProcedure, TrustedSigningKey, ClauseAIAnalysis, ClauseAnalysisJob,
    ClauseAuditAssessment,
)
from .services import analyze_clause_evidence, assess_clause, clause_legal_ready, coverage_report, create_mapping, create_obligation, extract_source_regulations, import_pack, review_clause_evidence, review_mapping, review_version, update_source_metadata, upload_clause_evidence, upload_source_pdf, version_review_blockers, withdraw_clause_evidence
from .ai import preliminary_evidence_coverage


@login_required
def dashboard(request):
    tenant = tenant_for_request(request)
    # A legacy seed source is intentionally excluded: it has no uploaded PDF
    # and must not distort a customer's operational dashboard.
    sources = RegulatorySource.objects.filter(tenant=tenant).exclude(title__startswith="Framework source")
    regulations = Regulation.objects.filter(version__source__in=sources)
    evidence = ClauseEvidence.objects.filter(tenant=tenant, subclause__regulation__version__source__in=sources, withdrawn_at__isnull=True)
    clause_count = regulations.count()
    submitted_clause_count = evidence.values("subclause_id").distinct().count()
    accepted_clause_count = evidence.filter(status=ClauseEvidence.Status.ACCEPTED).values("subclause_id").distinct().count()
    evidence_coverage = round((submitted_clause_count / clause_count) * 100) if clause_count else 0
    jobs = ClauseAnalysisJob.objects.filter(tenant=tenant)
    latest_status = ClauseAIAnalysis.objects.filter(subclause=OuterRef("pk")).order_by("-created_at").values("status")[:1]
    clauses = SubClause.objects.filter(regulation__version__source__in=sources).annotate(latest_status=Subquery(latest_status))
    submitted_ids = set(evidence.values_list("subclause_id", flat=True))
    counts = {status: 0 for status in ("COMPLIANT", "PARTIAL", "NON_COMPLIANT", "INSUFFICIENT_EVIDENCE")}
    awaiting_count = 0
    for clause in clauses:
        if clause.pk not in submitted_ids:
            continue
        if clause.latest_status in counts:
            counts[clause.latest_status] += 1
        else:
            awaiting_count += 1
    no_evidence_count = max(clause_count - len(submitted_ids), 0)
    total = clause_count or 1
    values = [counts["COMPLIANT"], counts["PARTIAL"], counts["NON_COMPLIANT"], counts["INSUFFICIENT_EVIDENCE"], awaiting_count, no_evidence_count]
    cumulative, stops = 0.0, []
    colors = ["#22c55e", "#f59e0b", "#ef4444", "#8b5cf6", "#3b82f6", "#cbd5e1"]
    for color, value in zip(colors, values):
        start, cumulative = cumulative, cumulative + (value * 100 / total)
        stops.append(f"{color} {start:.2f}% {cumulative:.2f}%")
    return render(
        request,
        "dashboard.html",
        {
            "tenant": tenant,
            "source_count": sources.count(), "clause_count": clause_count,
            "submitted_clause_count": submitted_clause_count, "accepted_clause_count": accepted_clause_count,
            "under_review_count": evidence.filter(status=ClauseEvidence.Status.UNDER_REVIEW).count(),
            "rejected_count": evidence.filter(status=ClauseEvidence.Status.REJECTED).count(),
            "legal_unverified_count": regulations.filter(legal_status=LegalSourceStatus.SOURCE_PENDING).count(),
            "evidence_coverage": evidence_coverage,
            "analysis_running_count": jobs.filter(status__in=[ClauseAnalysisJob.Status.QUEUED, ClauseAnalysisJob.Status.RUNNING]).count(),
            "analysis_error_count": jobs.filter(status=ClauseAnalysisJob.Status.ERROR).count(),
            "analysis_completed_count": sum(counts.values()),
            "compliant_count": counts["COMPLIANT"], "partial_count": counts["PARTIAL"],
            "non_compliant_count": counts["NON_COMPLIANT"], "insufficient_count": counts["INSUFFICIENT_EVIDENCE"],
            "awaiting_analysis_count": awaiting_count, "no_evidence_count": no_evidence_count,
            "pie_gradient": ", ".join(stops),
            "running_jobs": jobs.filter(status__in=[ClauseAnalysisJob.Status.QUEUED, ClauseAnalysisJob.Status.RUNNING]).select_related("subclause__regulation")[:10],
            "completed_jobs": jobs.filter(status=ClauseAnalysisJob.Status.COMPLETED).select_related("subclause__regulation")[:10],
            "sources": sources[:10],
        },
    )


@login_required
def regulatory_center(request):
    tenant = tenant_for_request(request)
    membership = request.tenant_membership
    if request.method == "POST":
        try:
            operation = request.POST.get("operation")
            if operation == "upload_pdf":
                source, version = upload_source_pdf(
                    tenant=tenant, actor=request.user, title=request.POST["title"],
                    version_label=request.POST["version_label"], filename=request.FILES["pdf"].name,
                    content=request.FILES["pdf"].read(),
                )
                try:
                    cards = extract_source_regulations(version=version, actor=request.user)
                    messages.success(request, f"Encrypted PDF saved. {len(cards)} source clause cards were extracted for human review.")
                except ValidationError as extraction_error:
                    messages.warning(request, f"PDF saved, but headings could not be extracted: {'; '.join(extraction_error.messages)}")
            elif operation == "extract":
                version = get_object_or_404(RegulatoryVersion, pk=request.POST.get("version"), source__tenant=tenant)
                cards = extract_source_regulations(version=version, actor=request.user)
                messages.success(request, f"{len(cards)} source clause cards were extracted for human review.")
            elif operation == "submit_evidence":
                clause = get_object_or_404(SubClause, pk=request.POST.get("clause"), regulation__version__source__tenant=tenant)
                uploads = request.FILES.getlist("evidence")
                if not uploads:
                    raise ValidationError("Select at least one evidence file.")
                allowed_extensions = {".pdf", ".docx", ".xlsx", ".csv", ".jpg", ".jpeg", ".png", ".txt"}
                for upload in uploads:
                    if not any(upload.name.lower().endswith(extension) for extension in allowed_extensions):
                        raise ValidationError("Allowed formats: PDF, DOCX, XLSX, CSV, JPG, PNG, or TXT.")
                    upload_clause_evidence(tenant=tenant, actor=request.user, subclause=clause, title=request.POST["title"], filename=upload.name, content=upload.read())
                messages.success(request, f"{len(uploads)} evidence file(s) encrypted and submitted for independent review.")
            elif operation == "analyze":
                clause = get_object_or_404(SubClause, pk=request.POST.get("clause"), regulation__version__source__tenant=tenant)
                job = ClauseAnalysisJob.objects.create(tenant=tenant, subclause=clause, requested_by=request.user)
                tenant_id, clause_id, actor_id = str(tenant.id), str(clause.id), request.user.id
                def run_analysis():
                    close_old_connections()
                    try:
                        queued_job = ClauseAnalysisJob.objects.get(pk=job.pk)
                        queued_job.status = ClauseAnalysisJob.Status.RUNNING
                        queued_job.save(update_fields=["status"])
                        queued_tenant = tenant.__class__.objects.get(pk=tenant_id)
                        queued_clause = SubClause.objects.get(pk=clause_id)
                        actor = get_user_model().objects.get(pk=actor_id)
                        analyze_clause_evidence(tenant=queued_tenant, actor=actor, subclause=queued_clause)
                    except Exception:
                        ClauseAnalysisJob.objects.filter(pk=job.pk).update(status=ClauseAnalysisJob.Status.ERROR, completed_at=timezone.now())
                    else:
                        ClauseAnalysisJob.objects.filter(pk=job.pk).update(status=ClauseAnalysisJob.Status.COMPLETED, completed_at=timezone.now())
                    finally:
                        close_old_connections()
                Thread(target=run_analysis, daemon=True).start()
                messages.success(request, "Evidence received. AI analysis is running in the background; refresh this card shortly for the updated finding.")
            elif operation == "withdraw_evidence":
                item = get_object_or_404(ClauseEvidence, pk=request.POST.get("evidence"), tenant=tenant, subclause__regulation__version__source__tenant=tenant)
                clause = item.subclause
                withdraw_clause_evidence(tenant=tenant, actor=request.user, artifact=item)
                analyze_clause_evidence(tenant=tenant, actor=request.user, subclause=clause)
                messages.success(request, "Evidence file removed and its content excluded. The preliminary finding was recalculated from active evidence only.")
            elif operation == "clause":
                if membership.role not in {Membership.Role.OWNER, Membership.Role.LEGAL_REVIEWER}:
                    raise PermissionDenied("Your role cannot register source clauses.")
                version = get_object_or_404(RegulatoryVersion, pk=request.POST["version"], source__tenant=tenant)
                number = int(request.POST["regulation_number"])
                regulation, _ = Regulation.objects.get_or_create(version=version, number=number, defaults={"source_page": request.POST["source_page"]})
                SubClause.objects.get_or_create(regulation=regulation, clause_path=request.POST["clause_path"], defaults={"title": request.POST["title"], "source_page": request.POST["source_page"]})
                messages.success(request, "Clause saved as SOURCE_PENDING; it still requires legal review.")
            elif operation == "import":
                if membership.role not in {Membership.Role.OWNER, Membership.Role.LEGAL_REVIEWER}:
                    raise PermissionDenied("Your role cannot import regulatory packs.")
                key = get_object_or_404(TrustedSigningKey, pk=request.POST.get("signing_key"), tenant=tenant, is_active=True)
                manifest, signature = request.FILES["manifest"], request.FILES["signature"]
                import_pack(tenant=tenant, actor=request.user, signing_key=key, manifest_bytes=manifest.read(), signature_bytes=signature.read())
                messages.success(request, "Signed pack imported as SOURCE_PENDING and sent for dual review.")
            elif operation == "review":
                version = get_object_or_404(RegulatoryVersion, pk=request.POST.get("version"), source__tenant=tenant)
                review_version(
                    version=version, reviewer=request.user, kind=request.POST.get("kind"),
                    decision=request.POST.get("decision"), note=request.POST.get("note", ""),
                )
                messages.success(request, "Review decision recorded.")
            elif operation == "source_metadata":
                version = get_object_or_404(RegulatoryVersion, pk=request.POST.get("version"), source__tenant=tenant)
                update_source_metadata(
                    version=version, actor=request.user,
                    authority_url=request.POST.get("authority_url", ""),
                    gazette_identifier=request.POST.get("gazette_identifier", ""),
                    effective_date=request.POST.get("effective_date") or None,
                )
                messages.success(request, "Authoritative source metadata saved; review blockers were recalculated.")
            elif operation == "obligation":
                clause = get_object_or_404(SubClause, pk=request.POST.get("clause"), regulation__version__source__tenant=tenant)
                create_obligation(
                    subclause=clause, actor=request.user,
                    obligation_key=request.POST.get("obligation_key", ""),
                    paraphrase=request.POST.get("paraphrase", ""),
                    requirement_type=request.POST.get("requirement_type", ""),
                    evidence_specification=request.POST.get("evidence_specification", ""),
                )
                messages.success(request, "Clause obligation saved as SOURCE_PENDING for independent review.")
        except (KeyError, ValidationError, PermissionDenied) as exc:
            messages.error(request, "; ".join(exc.messages) if isinstance(exc, ValidationError) else str(exc))
        return redirect("regulatory-center")
    versions = list(
        RegulatoryVersion.objects.filter(source__tenant=tenant)
        .select_related("source").prefetch_related("reviews__reviewer").order_by("-created_at")
    )
    for version in versions:
        version.coverage = coverage_report(version)
        version.review_blockers = version_review_blockers(version)
        version.clause_cards = list(version.regulations.all().prefetch_related("subclauses", "subclauses__obligations", "subclauses__submitted_evidence", "subclauses__ai_analyses"))
        for regulation in version.clause_cards:
            for clause in regulation.subclauses.all():
                clause.active_evidence = [item for item in clause.submitted_evidence.all() if item.withdrawn_at is None]
                for analysis in clause.ai_analyses.all():
                    # Render a non-persistent fallback for legacy immutable findings.
                    analysis.display_coverage = preliminary_evidence_coverage(analysis.result)
    return render(request, "regulatory/center.html", {
        "tenant": tenant, "membership": membership, "versions": versions,
        "signing_keys": TrustedSigningKey.objects.filter(tenant=tenant, is_active=True).order_by("name"),
        "can_import": membership.role in {Membership.Role.OWNER, Membership.Role.LEGAL_REVIEWER},
        "can_register_clauses": membership.role in {Membership.Role.OWNER, Membership.Role.LEGAL_REVIEWER},
        "can_author_source": membership.role in {Membership.Role.OWNER, Membership.Role.LEGAL_REVIEWER},
        "review_kind": RegulatoryReview.Kind.LEGAL if membership.role == Membership.Role.LEGAL_REVIEWER else RegulatoryReview.Kind.COMPLIANCE if membership.role == Membership.Role.COMPLIANCE_LEAD else "",
    })


@login_required
def mapping_center(request):
    tenant = tenant_for_request(request)
    membership = request.tenant_membership
    can_author = membership.role in {Membership.Role.OWNER, Membership.Role.COMPLIANCE_LEAD}
    if request.method == "POST":
        try:
            operation = request.POST.get("operation")
            if operation in {"control", "test", "evidence", "mapping"} and not can_author:
                raise PermissionDenied("Only tenant owners or compliance leads may author mapping records.")
            if operation == "control":
                item = ControlDefinition.objects.create(
                    tenant=tenant, control_key=request.POST["key"], version=request.POST["version"],
                    title=request.POST["title"], description=request.POST["description"], created_by=request.user,
                )
            elif operation == "test":
                control = get_object_or_404(ControlDefinition, pk=request.POST.get("control"), tenant=tenant)
                item = TestProcedure.objects.create(
                    tenant=tenant, control=control, procedure_key=request.POST["key"], version=request.POST["version"],
                    title=request.POST["title"], procedure=request.POST["procedure"],
                    expected_result=request.POST["expected_result"], created_by=request.user,
                )
            elif operation == "evidence":
                procedure = get_object_or_404(TestProcedure, pk=request.POST.get("test_procedure"), tenant=tenant)
                item = EvidenceRequirement.objects.create(
                    tenant=tenant, test_procedure=procedure, requirement_key=request.POST["key"],
                    version=request.POST["version"], title=request.POST["title"], description=request.POST["description"],
                    recurrence=request.POST.get("recurrence", ""), created_by=request.user,
                )
            elif operation == "mapping":
                obligation = get_object_or_404(Obligation, pk=request.POST.get("obligation"), subclause__regulation__version__source__tenant=tenant)
                control = get_object_or_404(ControlDefinition, pk=request.POST.get("control"), tenant=tenant)
                procedure = get_object_or_404(TestProcedure, pk=request.POST.get("test_procedure"), tenant=tenant)
                requirement = get_object_or_404(EvidenceRequirement, pk=request.POST.get("evidence_requirement"), tenant=tenant)
                create_mapping(
                    tenant=tenant, actor=request.user, obligation=obligation, control=control,
                    test_procedure=procedure, evidence_requirement=requirement, rationale=request.POST["rationale"],
                )
                item = None
            elif operation == "review":
                mapping = get_object_or_404(ObligationControlMapping, pk=request.POST.get("mapping"), tenant=tenant)
                review_mapping(
                    mapping=mapping, reviewer=request.user, kind=request.POST.get("kind"),
                    decision=request.POST.get("decision"), note=request.POST.get("note", ""),
                )
                item = None
            else:
                raise ValidationError("Unknown mapping operation.")
            if item is not None:
                AuditEvent.objects.create(
                    tenant=tenant, actor=request.user, action="mapping_catalogue.created",
                    object_type=type(item).__name__, object_id=str(item.id), metadata={"key": str(item)},
                )
            messages.success(request, "Mapping workflow record saved.")
        except (KeyError, ValueError, ValidationError, PermissionDenied) as exc:
            messages.error(request, "; ".join(exc.messages) if isinstance(exc, ValidationError) else str(exc))
        return redirect("mapping-center")
    controls = ControlDefinition.objects.filter(tenant=tenant)
    procedures = TestProcedure.objects.filter(tenant=tenant).select_related("control")
    requirements = EvidenceRequirement.objects.filter(tenant=tenant).select_related("test_procedure")
    return render(request, "regulatory/mappings.html", {
        "tenant": tenant, "membership": membership, "can_author": can_author,
        "controls": controls, "procedures": procedures, "requirements": requirements,
        "obligations": Obligation.objects.filter(
            subclause__regulation__version__source__tenant=tenant, legal_status=LegalSourceStatus.VERIFIED,
        ).select_related("subclause__regulation"),
        "mappings": ObligationControlMapping.objects.filter(tenant=tenant).select_related(
            "obligation", "control", "test_procedure", "evidence_requirement", "created_by",
        ).prefetch_related("reviews__reviewer"),
        "review_kind": MappingReview.Kind.LEGAL if membership.role == Membership.Role.LEGAL_REVIEWER else MappingReview.Kind.COMPLIANCE if membership.role == Membership.Role.COMPLIANCE_LEAD else "",
    })


def _audit_clauses(tenant):
    sources = RegulatorySource.objects.filter(tenant=tenant).exclude(title__startswith="Framework source")
    clauses = list(
        SubClause.objects.filter(regulation__version__source__in=sources)
        .select_related("regulation__version__source")
        .prefetch_related("obligations__control_mappings", "submitted_evidence__uploaded_by", "submitted_evidence__independent_review__reviewer", "ai_analyses", "audit_assessments__reviewer")
        .order_by("regulation__number", "clause_path")
    )
    for clause in clauses:
        clause.active_evidence = [item for item in clause.submitted_evidence.all() if item.withdrawn_at is None]
        clause.latest_assessment = clause.audit_assessments.all()[0] if clause.audit_assessments.all() else None
        clause.legal_ready = clause_legal_ready(clause)
        current_hashes = sorted(item.plaintext_sha256 for item in clause.active_evidence)
        recorded_hashes = sorted(item["sha256"] for item in (clause.latest_assessment.evidence_snapshot if clause.latest_assessment else []))
        clause.assessment_stale = bool(clause.latest_assessment and current_hashes != recorded_hashes)
    return clauses


@login_required
def auditor_room(request):
    tenant = tenant_for_request(request)
    membership = request.tenant_membership
    if request.method == "POST":
        try:
            if membership.role != Membership.Role.AUDITOR:
                raise PermissionDenied("Only an assigned auditor may record independent decisions.")
            operation = request.POST.get("operation")
            if operation == "review_file":
                artifact = get_object_or_404(ClauseEvidence, pk=request.POST.get("evidence"), tenant=tenant)
                review_clause_evidence(
                    artifact=artifact, reviewer=request.user,
                    decision=request.POST.get("decision"), note=request.POST.get("note", ""),
                )
                messages.success(request, "Immutable evidence-file review recorded.")
            elif operation == "assess_clause":
                clause = get_object_or_404(SubClause, pk=request.POST.get("clause"), regulation__version__source__tenant=tenant)
                assessment = assess_clause(
                    subclause=clause, reviewer=request.user, decision=request.POST.get("decision"),
                    note=request.POST.get("note", ""), gaps=request.POST.get("gaps", ""),
                )
                messages.success(request, f"Clause assessment v{assessment.sequence} recorded as {assessment.compliance_status}.")
            else:
                raise ValidationError("Unknown auditor operation.")
        except (ValidationError, PermissionDenied) as exc:
            messages.error(request, "; ".join(exc.messages) if isinstance(exc, ValidationError) else str(exc))
        return redirect("auditor-room")
    return render(request, "regulatory/auditor_room.html", {
        "tenant": tenant, "membership": membership, "clauses": _audit_clauses(tenant),
        "can_review": membership.role == Membership.Role.AUDITOR,
        "evidence_decisions": [ClauseEvidence.Status.ACCEPTED, ClauseEvidence.Status.REJECTED],
        "assessment_decisions": ClauseAuditAssessment.Decision.choices,
    })


@login_required
def audit_report(request):
    tenant = tenant_for_request(request)
    clauses = _audit_clauses(tenant)
    if request.GET.get("format") == "csv":
        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = 'attachment; filename="assurance-review-report.csv"'
        writer = csv.writer(response)
        writer.writerow(["Clause", "Title", "Legal source", "Auditor status", "Decision", "Evidence files", "Conclusion", "Gaps", "Reviewed by", "Reviewed at", "Superseded by evidence change"])
        for clause in clauses:
            assessment = clause.latest_assessment
            writer.writerow([
                clause.clause_path, clause.title, clause.legal_status,
                assessment.compliance_status if assessment else "NOT_REVIEWED",
                assessment.decision if assessment else "", len(clause.active_evidence),
                assessment.note if assessment else "", assessment.gaps if assessment else "",
                assessment.reviewer.username if assessment else "",
                assessment.created_at.isoformat() if assessment else "", clause.assessment_stale,
            ])
        return response
    counts = {status: 0 for status in ClauseAuditAssessment.ComplianceStatus.values}
    not_reviewed = 0
    for clause in clauses:
        if clause.latest_assessment:
            counts[clause.latest_assessment.compliance_status] += 1
        else:
            not_reviewed += 1
    return render(request, "regulatory/audit_report.html", {
        "tenant": tenant, "clauses": clauses, "counts": counts, "not_reviewed": not_reviewed,
        "generated_at": timezone.now(),
    })

