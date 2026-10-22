from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.shortcuts import redirect, render

from .access import tenant_for_request
from .models import Membership
from .services import create_tenant_user, disable_tenant_user, reset_tenant_user_password, transfer_tenant_ownership


@login_required
def user_management(request):
    tenant = tenant_for_request(request)
    if request.tenant_membership.role != Membership.Role.OWNER:
        raise PermissionDenied("Only the tenant owner can manage users.")
    if request.method == "POST":
        try:
            operation = request.POST.get("operation")
            if operation == "create":
                create_tenant_user(tenant=tenant, actor=request.user, username=request.POST["username"], email=request.POST.get("email", ""), role=request.POST["role"], temporary_password=request.POST["password"])
                messages.success(request, "User created. Share the temporary password through an approved private channel.")
            else:
                membership = Membership.objects.get(pk=request.POST["membership_id"], tenant=tenant)
                if operation == "disable":
                    disable_tenant_user(membership=membership, actor=request.user)
                    messages.success(request, "User access disabled; audit history was retained.")
                elif operation == "reset_password":
                    reset_tenant_user_password(membership=membership, actor=request.user, temporary_password=request.POST["password"])
                    messages.success(request, "Temporary password set; existing login sessions are invalidated by Django.")
                elif operation == "transfer_owner":
                    transfer_tenant_ownership(tenant=tenant, actor=request.user, target_membership=membership, current_password=request.POST["current_password"])
                    messages.success(request, "Ownership transferred. Your role is now Compliance Lead.")
                else:
                    raise ValidationError("Unknown user-management operation.")
            return redirect("user-management")
        except (ValidationError, PermissionDenied, Membership.DoesNotExist, KeyError) as exc:
            messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    memberships = Membership.objects.filter(tenant=tenant).select_related("user").order_by("user__username")
    return render(request, "tenancy/user_management.html", {"tenant": tenant, "memberships": memberships, "assignable_roles": [(value, label) for value, label in Membership.Role.choices if value != Membership.Role.OWNER]})
