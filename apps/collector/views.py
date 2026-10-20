from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from apps.tenancy.access import tenant_for_request

from .models import CollectionJob, CollectorAgent, CommandProfile, CredentialReference, Device, ScopeGrant


@login_required
def collector_center(request):
    tenant = tenant_for_request(request)
    return render(request, "collector/center.html", {
        "tenant": tenant,
        "devices": Device.objects.filter(tenant=tenant),
        "agents": CollectorAgent.objects.filter(tenant=tenant),
        "credential_references": CredentialReference.objects.filter(tenant=tenant),
        "scope_grants": ScopeGrant.objects.filter(tenant=tenant).select_related("device", "agent"),
        "profiles": CommandProfile.objects.filter(tenant=tenant),
        "jobs": CollectionJob.objects.filter(tenant=tenant).select_related("device")[:25],
    })
