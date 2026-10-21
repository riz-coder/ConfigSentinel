from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.utils import timezone

from apps.tenancy.access import tenant_for_request
from apps.tenancy.models import Membership

from .models import Asset, AssetDependency, CriticalService, Site
from .services import asset_template_csv, asset_template_xlsx, import_assets_file, save_inventory_object


@login_required
def inventory_template_csv(request):
    tenant_for_request(request)
    response = HttpResponse(asset_template_csv(request.user.username), content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = 'attachment; filename="asset-register-template.csv"'
    return response


@login_required
def inventory_template_xlsx(request):
    tenant_for_request(request)
    response = HttpResponse(asset_template_xlsx(request.user.username), content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    response["Content-Disposition"] = 'attachment; filename="asset-register-template.xlsx"'
    return response


@login_required
def inventory_center(request):
    tenant = tenant_for_request(request)
    can_manage = request.tenant_membership.role in {Membership.Role.OWNER, Membership.Role.COMPLIANCE_LEAD}
    if request.method == "POST":
        try:
            operation = request.POST.get("operation")
            if operation == "site":
                save_inventory_object(obj=Site(tenant=tenant, code=request.POST["code"].strip(), name=request.POST["name"].strip(), kind=request.POST["kind"], city=request.POST.get("city", "").strip(), created_by=request.user), actor=request.user)
            elif operation == "service":
                owner = tenant.memberships.get(user_id=request.POST["owner"], is_active=True).user
                save_inventory_object(obj=CriticalService(tenant=tenant, code=request.POST["code"].strip(), name=request.POST["name"].strip(), criticality=request.POST["criticality"], owner=owner, description=request.POST.get("description", "").strip(), created_by=request.user), actor=request.user)
            elif operation == "asset":
                owner = tenant.memberships.get(user_id=request.POST["owner"], is_active=True).user
                custodian = tenant.memberships.get(user_id=request.POST["custodian"], is_active=True).user
                site = Site.objects.filter(tenant=tenant, pk=request.POST.get("site") or None).first()
                service = CriticalService.objects.filter(tenant=tenant, pk=request.POST.get("service") or None).first()
                save_inventory_object(obj=Asset(tenant=tenant, asset_tag=request.POST["asset_tag"].strip(), name=request.POST["name"].strip(), kind=request.POST["kind"], site=site, service=service, owner=owner, custodian=custodian, criticality=request.POST["criticality"], classification=request.POST["classification"], lifecycle=request.POST["lifecycle"], is_cii=bool(request.POST.get("is_cii")), created_by=request.user), actor=request.user)
            elif operation == "dependency":
                dependent = Asset.objects.get(tenant=tenant, pk=request.POST["dependent"])
                provider = Asset.objects.get(tenant=tenant, pk=request.POST["provider"])
                save_inventory_object(obj=AssetDependency(tenant=tenant, dependent=dependent, provider=provider, kind=request.POST["kind"], notes=request.POST.get("notes", "").strip(), created_by=request.user), actor=request.user)
            elif operation == "csv":
                upload = request.FILES["inventory_file"]
                count = import_assets_file(tenant=tenant, actor=request.user, filename=upload.name, content=upload.read())
                messages.success(request, f"Imported {count} validated assets.")
            else:
                raise ValidationError("Unknown inventory operation.")
            if operation != "csv":
                messages.success(request, "Inventory record created.")
            return redirect("inventory-center")
        except (ValidationError, PermissionDenied, Membership.DoesNotExist, Asset.DoesNotExist, KeyError) as exc:
            messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    assets = Asset.objects.filter(tenant=tenant).select_related("site", "service", "owner", "custodian")
    today = timezone.localdate()
    return render(request, "inventory/center.html", {
        "tenant": tenant, "assets": assets, "sites": Site.objects.filter(tenant=tenant),
        "services": CriticalService.objects.filter(tenant=tenant), "members": tenant.memberships.filter(is_active=True).select_related("user"),
        "can_manage": can_manage, "cii_count": assets.filter(is_cii=True).count(),
        "critical_count": assets.filter(criticality=CriticalService.Criticality.CRITICAL).count(),
        "overdue_count": assets.filter(review_due_at__lt=today).count(),
        "site_kinds": Site.Kind.choices, "criticalities": CriticalService.Criticality.choices,
        "asset_kinds": Asset.Kind.choices, "classifications": Asset.Classification.choices, "lifecycles": Asset.Lifecycle.choices,
        "dependency_kinds": AssetDependency.Kind.choices,
        "dependencies": AssetDependency.objects.filter(tenant=tenant).select_related("dependent", "provider"),
    })
