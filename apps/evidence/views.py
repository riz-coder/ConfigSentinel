from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render

from apps.regulatory.models import ObligationControlMapping
from apps.tenancy.access import tenant_for_request
from apps.tenancy.models import Membership

from .models import EvidenceArtifact, EvidenceReview, RetentionHold
from .services import apply_hold, purge_ciphertext, release_hold, retrieve_evidence, review_evidence, upload_evidence
from .vault import EvidenceIntegrityError, VaultError


@login_required
def evidence_center(request):
    tenant = tenant_for_request(request)
    membership = request.tenant_membership
    if request.method == "POST":
        try:
            operation = request.POST.get("operation")
            if operation == "upload":
                uploaded = request.FILES["file"]
                mapping = get_object_or_404(ObligationControlMapping, pk=request.POST.get("mapping"), tenant=tenant)
                upload_evidence(
                    tenant=tenant, actor=request.user, mapping=mapping, title=request.POST["title"],
                    filename=uploaded.name, media_type=uploaded.content_type or "application/octet-stream",
                    content=uploaded.read(), period_start=request.POST.get("period_start") or None,
                    period_end=request.POST.get("period_end") or None,
                )
            elif operation == "review":
                artifact = get_object_or_404(EvidenceArtifact, pk=request.POST.get("artifact"), tenant=tenant)
                review_evidence(
                    artifact=artifact, reviewer=request.user, decision=request.POST.get("decision"),
                    note=request.POST.get("note", ""),
                )
            elif operation == "hold":
                artifact = get_object_or_404(EvidenceArtifact, pk=request.POST.get("artifact"), tenant=tenant)
                apply_hold(artifact=artifact, actor=request.user, reason=request.POST.get("reason", ""))
            elif operation == "release":
                hold = get_object_or_404(RetentionHold, pk=request.POST.get("hold"), artifact__tenant=tenant)
                release_hold(hold=hold, actor=request.user, reason=request.POST.get("reason", ""))
            elif operation == "purge":
                artifact = get_object_or_404(EvidenceArtifact, pk=request.POST.get("artifact"), tenant=tenant)
                purge_ciphertext(artifact=artifact, actor=request.user)
            else:
                raise ValidationError("Unknown evidence operation.")
            messages.success(request, "Evidence workflow action completed.")
        except (KeyError, ValidationError, PermissionDenied, VaultError) as exc:
            messages.error(request, "; ".join(exc.messages) if isinstance(exc, ValidationError) else str(exc))
        return redirect("evidence-center")
    artifacts = EvidenceArtifact.objects.filter(tenant=tenant).select_related(
        "mapping", "requirement", "uploaded_by", "review__reviewer",
    ).prefetch_related("retention_holds")
    return render(request, "evidence/center.html", {
        "tenant": tenant, "membership": membership, "artifacts": artifacts,
        "approved_mappings": ObligationControlMapping.objects.filter(tenant=tenant, status=ObligationControlMapping.Status.APPROVED),
        "can_upload": membership.role in {Membership.Role.OWNER, Membership.Role.COMPLIANCE_LEAD},
        "can_review": membership.role in {Membership.Role.COMPLIANCE_LEAD, Membership.Role.AUDITOR},
        "can_hold": membership.role in {Membership.Role.OWNER, Membership.Role.COMPLIANCE_LEAD, Membership.Role.AUDITOR},
    })


@login_required
def evidence_download(request, artifact_id):
    tenant = tenant_for_request(request)
    artifact = get_object_or_404(EvidenceArtifact, pk=artifact_id, tenant=tenant)
    try:
        content = retrieve_evidence(artifact=artifact, actor=request.user)
    except (PermissionDenied, EvidenceIntegrityError) as exc:
        messages.error(request, str(exc))
        return redirect("evidence-center")
    response = HttpResponse(content, content_type="application/octet-stream")
    response["Content-Disposition"] = f'attachment; filename="evidence-{artifact.id}"'
    response["X-Content-Type-Options"] = "nosniff"
    response["Cache-Control"] = "no-store"
    return response
