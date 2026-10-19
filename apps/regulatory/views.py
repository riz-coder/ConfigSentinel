from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.shortcuts import get_object_or_404, redirect, render

from apps.tenancy.access import tenant_for_request

from apps.tenancy.models import Membership

from .models import LegalSourceStatus, Regulation, RegulatoryReview, RegulatorySource, RegulatoryVersion, TrustedSigningKey
from .services import coverage_report, import_pack, review_version


@login_required
def dashboard(request):
    tenant = tenant_for_request(request)
    sources = RegulatorySource.objects.filter(tenant=tenant)
    regulations = Regulation.objects.filter(version__source__tenant=tenant)
    return render(
        request,
        "dashboard.html",
        {
            "tenant": tenant,
            "source_count": sources.count(),
            "verified_source_count": sources.filter(legal_status=LegalSourceStatus.VERIFIED).count(),
            "regulation_count": regulations.count(),
            "source_pending_count": regulations.filter(legal_status=LegalSourceStatus.SOURCE_PENDING).count(),
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
            if operation == "import":
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
        except (KeyError, ValidationError, PermissionDenied) as exc:
            messages.error(request, "; ".join(exc.messages) if isinstance(exc, ValidationError) else str(exc))
        return redirect("regulatory-center")
    versions = list(
        RegulatoryVersion.objects.filter(source__tenant=tenant)
        .select_related("source").prefetch_related("reviews__reviewer").order_by("-created_at")
    )
    for version in versions:
        version.coverage = coverage_report(version)
    return render(request, "regulatory/center.html", {
        "tenant": tenant, "membership": membership, "versions": versions,
        "signing_keys": TrustedSigningKey.objects.filter(tenant=tenant, is_active=True).order_by("name"),
        "can_import": membership.role in {Membership.Role.OWNER, Membership.Role.LEGAL_REVIEWER},
        "review_kind": RegulatoryReview.Kind.LEGAL if membership.role == Membership.Role.LEGAL_REVIEWER else RegulatoryReview.Kind.COMPLIANCE if membership.role == Membership.Role.COMPLIANCE_LEAD else "",
    })

