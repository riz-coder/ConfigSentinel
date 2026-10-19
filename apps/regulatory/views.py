from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from apps.tenancy.access import tenant_for_request

from .models import LegalSourceStatus, Regulation, RegulatorySource


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

