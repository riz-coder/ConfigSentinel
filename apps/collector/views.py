from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.inventory.models import Asset
from apps.tenancy.access import tenant_for_request
from apps.tenancy.models import Membership

from .models import CollectionJob, CollectorAgent, CommandProfile, CredentialReference, Device, DeviceAssessment, ScopeGrant
from .services import activate_agent, approve_command_profile, approve_scope, approve_telnet_device, create_scope_grant, register_agent, register_credential_reference, register_device, request_collection


@login_required
def collector_center(request):
    tenant = tenant_for_request(request)
    can_manage = request.tenant_membership.role in {Membership.Role.OWNER, Membership.Role.COMPLIANCE_LEAD}
    if request.method == "POST":
        try:
            operation = request.POST.get("operation")
            if operation == "device":
                asset = Asset.objects.get(tenant=tenant, pk=request.POST["asset"], is_active=True)
                transport = request.POST["transport"]
                register_device(
                    tenant=tenant, actor=request.user, asset=asset,
                    name=request.POST["name"].strip(), vendor=request.POST["vendor"],
                    platform=request.POST["platform"].strip(), management_address=request.POST["management_address"].strip(),
                    transport=transport, port=23 if transport == Device.Transport.TELNET else int(request.POST["port"]),
                    pinned_host_key_sha256=request.POST.get("pinned_host_key_sha256", "").strip(),
                    telnet_exception_reference="PENDING_INDEPENDENT_APPROVAL" if transport == Device.Transport.TELNET else "",
                    telnet_risk_acknowledgement="Legacy clear-text transport remains blocked until a separate authorized reviewer records and approves the exception." if transport == Device.Transport.TELNET else "",
                )
                messages.success(request, "Device registered. Telnet devices remain disabled until independent exception approval.")
            elif operation == "credential":
                register_credential_reference(tenant=tenant, actor=request.user, name=request.POST["name"].strip(), provider=request.POST["provider"].strip(), secret_reference=request.POST["secret_reference"].strip())
                messages.success(request, "Opaque credential reference saved; no raw credential was stored.")
            elif operation == "agent":
                register_agent(tenant=tenant, actor=request.user, name=request.POST["name"].strip(), identity_fingerprint=request.POST["identity_fingerprint"].strip())
                messages.success(request, "Collector agent registered pending independent activation.")
            elif operation == "activate_agent":
                agent = CollectorAgent.objects.get(tenant=tenant, pk=request.POST["agent_id"])
                activate_agent(agent=agent, actor=request.user)
                messages.success(request, "Collector agent activated.")
            elif operation == "scope":
                device = Device.objects.get(tenant=tenant, pk=request.POST["device_id"])
                agent = CollectorAgent.objects.get(tenant=tenant, pk=request.POST["agent_id"])
                credential = CredentialReference.objects.get(tenant=tenant, pk=request.POST["credential_id"])
                valid_from, valid_until = parse_datetime(request.POST["valid_from"]), parse_datetime(request.POST["valid_until"])
                if valid_from is None or valid_until is None:
                    raise ValidationError("Authorization dates are invalid.")
                if timezone.is_naive(valid_from): valid_from = timezone.make_aware(valid_from)
                if timezone.is_naive(valid_until): valid_until = timezone.make_aware(valid_until)
                create_scope_grant(tenant=tenant, actor=request.user, device=device, agent=agent, credential=credential, authorization_reference=request.POST["authorization_reference"].strip(), purpose=request.POST["purpose"].strip(), valid_from=valid_from, valid_until=valid_until, max_commands=int(request.POST["max_commands"]), max_runtime_seconds=int(request.POST["max_runtime_seconds"]), max_output_bytes=int(request.POST["max_output_bytes"]))
                messages.success(request, "Collection scope recorded pending independent approval.")
            elif operation == "approve_scope":
                grant = ScopeGrant.objects.get(tenant=tenant, pk=request.POST["scope_id"])
                approve_scope(grant=grant, actor=request.user)
                messages.success(request, "Collection scope independently approved.")
            elif operation == "queue_collection":
                grant = ScopeGrant.objects.select_related("device", "agent").get(tenant=tenant, pk=request.POST["scope_id"])
                normalized = grant.device.platform.upper().replace("_", "-").replace(" ", "-")
                candidates = CommandProfile.objects.filter(tenant=tenant, vendor=grant.device.vendor, status=CommandProfile.Status.APPROVED)
                profile = next((item for item in candidates if item.platform.upper() == normalized or (item.platform == "IOS_IOS_XE" and normalized in {"IOS", "IOS-XE", "IOS-IOS-XE"}) or (item.platform == "NX-OS" and normalized in {"NXOS", "NX-OS"})), None)
                if profile is None:
                    raise ValidationError("No independently approved command profile supports this device yet.")
                request_collection(tenant=tenant, actor=request.user, device=grant.device, agent=grant.agent, scope_grant=grant, command_profile=profile, observed_host_key_sha256=grant.device.pinned_host_key_sha256)
                messages.success(request, "Collection job queued for the on-prem agent.")
            elif operation == "approve_profile":
                profile = CommandProfile.objects.get(tenant=tenant, pk=request.POST["profile_id"])
                approve_command_profile(profile=profile, actor=request.user, approval_reference=request.POST.get("approval_reference"))
                messages.success(request, "Command profile independently approved.")
            elif operation == "approve_telnet":
                device = Device.objects.get(tenant=tenant, pk=request.POST["device_id"])
                approve_telnet_device(device=device, actor=request.user, approval_reference=request.POST.get("approval_reference", "").strip())
                messages.success(request, "Telnet exception independently approved; no SSH downgrade is permitted.")
            else:
                raise ValidationError("Unknown collector operation.")
            return redirect("collector-center")
        except (ValidationError, PermissionDenied, Asset.DoesNotExist, Device.DoesNotExist, CollectorAgent.DoesNotExist, CredentialReference.DoesNotExist, ScopeGrant.DoesNotExist, CommandProfile.DoesNotExist, KeyError, ValueError) as exc:
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


@login_required
def device_assessment_report(request, assessment_id):
    tenant = tenant_for_request(request)
    assessment = get_object_or_404(DeviceAssessment.objects.select_related("job__device").prefetch_related("findings__evidence_execution__command"), tenant=tenant, pk=assessment_id)
    return render(request, "collector/assessment_report.html", {"tenant": tenant, "assessment": assessment, "findings": assessment.findings.order_by("category", "rule_id")})
