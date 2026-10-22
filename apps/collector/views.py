from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.shortcuts import redirect, render

from apps.inventory.models import Asset
from apps.tenancy.access import tenant_for_request
from apps.tenancy.models import Membership

from .models import CollectionJob, CollectorAgent, CommandProfile, CredentialReference, Device, ScopeGrant
from .services import approve_command_profile, approve_telnet_device, register_credential_reference, register_device


@login_required
def collector_center(request):
    tenant = tenant_for_request(request)
    can_manage = request.tenant_membership.role in {Membership.Role.OWNER, Membership.Role.COMPLIANCE_LEAD}
    if request.method == "POST":
        try:
            operation = request.POST.get("operation")
            if operation == "device":
                asset = Asset.objects.get(tenant=tenant, pk=request.POST["asset"], is_active=True)
                register_device(
                    tenant=tenant, actor=request.user, asset=asset,
                    name=request.POST["name"].strip(), vendor=request.POST["vendor"],
                    platform=request.POST["platform"].strip(), management_address=request.POST["management_address"].strip(),
                    transport=request.POST["transport"], port=int(request.POST["port"]),
                    pinned_host_key_sha256=request.POST.get("pinned_host_key_sha256", "").strip(),
                    telnet_exception_reference=request.POST.get("telnet_exception_reference", "").strip(),
                    telnet_risk_acknowledgement=request.POST.get("telnet_risk_acknowledgement", "").strip(),
                )
                messages.success(request, "Device registered. Telnet devices remain disabled until independent exception approval.")
            elif operation == "credential":
                register_credential_reference(tenant=tenant, actor=request.user, name=request.POST["name"].strip(), provider=request.POST["provider"].strip(), secret_reference=request.POST["secret_reference"].strip())
                messages.success(request, "Opaque credential reference saved; no raw credential was stored.")
            elif operation == "approve_profile":
                profile = CommandProfile.objects.get(tenant=tenant, pk=request.POST["profile_id"])
                approve_command_profile(profile=profile, actor=request.user, approval_reference=request.POST.get("approval_reference"))
                messages.success(request, "Command profile independently approved.")
            elif operation == "approve_telnet":
                device = Device.objects.get(tenant=tenant, pk=request.POST["device_id"])
                approve_telnet_device(device=device, actor=request.user)
                messages.success(request, "Telnet exception independently approved; no SSH downgrade is permitted.")
            else:
                raise ValidationError("Unknown collector operation.")
            return redirect("collector-center")
        except (ValidationError, PermissionDenied, Asset.DoesNotExist, Device.DoesNotExist, CommandProfile.DoesNotExist, KeyError, ValueError) as exc:
            messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    return render(request, "collector/center.html", {
        "tenant": tenant,
        "can_manage": can_manage,
        "assets": Asset.objects.filter(tenant=tenant, is_active=True),
        "device_vendors": Device.Vendor.choices,
        "device_transports": Device.Transport.choices,
        "devices": Device.objects.filter(tenant=tenant).select_related("asset", "created_by", "telnet_approved_by"),
        "agents": CollectorAgent.objects.filter(tenant=tenant),
        "credential_references": CredentialReference.objects.filter(tenant=tenant),
        "scope_grants": ScopeGrant.objects.filter(tenant=tenant).select_related("device", "agent"),
        "profiles": CommandProfile.objects.filter(tenant=tenant).prefetch_related("commands"),
        "jobs": CollectionJob.objects.filter(tenant=tenant).select_related("device")[:25],
    })
