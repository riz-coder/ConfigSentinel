from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404

from .models import Membership, Tenant


def tenant_for_request(request) -> Tenant:
    tenant_id = request.headers.get("X-Tenant-ID") or request.GET.get("tenant")
    memberships = Membership.objects.select_related("tenant").filter(user=request.user, is_active=True, tenant__is_active=True)
    if tenant_id:
        membership = get_object_or_404(memberships, tenant_id=tenant_id)
    else:
        membership = memberships.order_by("tenant__name").first()
    if membership is None:
        raise PermissionDenied("No active tenant membership is available.")
    request.tenant_membership = membership
    return membership.tenant

