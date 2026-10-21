import csv
import io

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction

from apps.auditlog.models import AuditEvent
from apps.tenancy.models import Membership

from .models import Asset, CriticalService, Site


def require_inventory_operator(*, tenant, actor):
    membership = Membership.objects.filter(tenant=tenant, user=actor, is_active=True).first()
    if not membership or membership.role not in {Membership.Role.OWNER, Membership.Role.COMPLIANCE_LEAD}:
        raise PermissionDenied("Tenant owner or compliance lead access is required.")


def save_inventory_object(*, obj, actor):
    require_inventory_operator(tenant=obj.tenant, actor=actor)
    obj.full_clean()
    obj.save()
    AuditEvent.objects.create(tenant=obj.tenant, actor=actor, action=f"inventory.{obj._meta.model_name}_created", object_type=obj.__class__.__name__, object_id=str(obj.pk), metadata={})
    return obj


@transaction.atomic
def import_assets_csv(*, tenant, actor, content):
    require_inventory_operator(tenant=tenant, actor=actor)
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValidationError("CSV must be UTF-8 encoded.") from exc
    reader = csv.DictReader(io.StringIO(text))
    required = {"asset_tag", "name", "kind", "owner_username", "custodian_username", "criticality"}
    if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
        raise ValidationError(f"CSV requires columns: {', '.join(sorted(required))}.")
    rows, errors, seen_tags = [], [], set()
    for number, row in enumerate(reader, start=2):
        try:
            owner = tenant.memberships.get(user__username=row["owner_username"].strip(), is_active=True).user
            custodian = tenant.memberships.get(user__username=row["custodian_username"].strip(), is_active=True).user
            site_code, service_code = row.get("site_code", "").strip(), row.get("service_code", "").strip()
            site = Site.objects.filter(tenant=tenant, code=site_code).first() if site_code else None
            service = CriticalService.objects.filter(tenant=tenant, code=service_code).first() if service_code else None
            if site_code and not site:
                raise ValidationError(f"Unknown site_code {site_code}.")
            if service_code and not service:
                raise ValidationError(f"Unknown service_code {service_code}.")
            tag = row["asset_tag"].strip()
            if tag in seen_tags:
                raise ValidationError(f"Duplicate asset_tag {tag} in this batch.")
            seen_tags.add(tag)
            obj = Asset(tenant=tenant, asset_tag=tag, name=row["name"].strip(), kind=row["kind"].strip(), owner=owner, custodian=custodian, criticality=row["criticality"].strip(), site=site, service=service, is_cii=row.get("is_cii", "").strip().lower() in {"1", "true", "yes"}, created_by=actor)
            obj.full_clean()
            rows.append(obj)
        except Exception as exc:
            errors.append(f"Row {number}: {exc}")
    if errors:
        raise ValidationError(errors)
    Asset.objects.bulk_create(rows)
    AuditEvent.objects.create(tenant=tenant, actor=actor, action="inventory.assets_imported", object_type="Asset", object_id="batch", metadata={"count": len(rows)})
    return len(rows)
