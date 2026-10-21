import csv
import io
import re
from datetime import date, datetime

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import models, transaction

from apps.auditlog.models import AuditEvent
from apps.tenancy.models import Membership

from .models import Asset, CriticalService, Site


FIELD_ALIASES = {
    "asset_tag": {"assettag", "assetid", "assetcode", "inventoryid", "inventorycode", "tag", "deviceid"},
    "name": {"name", "assetname", "devicename", "hostname", "systemname"},
    "kind": {"kind", "type", "assettype", "devicetype", "category", "assetcategory"},
    "owner_username": {"owner", "ownerusername", "assetowner", "businessowner", "responsibleperson", "responsibleowner"},
    "custodian_username": {"custodian", "custodianusername", "assetcustodian", "technicalowner", "technicalcustodian"},
    "criticality": {"criticality", "assetcriticality", "businesscriticality", "impact", "priority"},
    "site_code": {"site", "sitecode", "siteid", "location", "locationcode", "pop", "office"},
    "service_code": {"service", "servicecode", "businessservice", "criticalservice", "serviceid"},
    "is_cii": {"iscii", "cii", "ciistatus", "criticalinfrastructure", "criticalasset"},
    "classification": {"classification", "dataclassification", "securityclassification", "assetclassification"},
    "lifecycle": {"lifecycle", "lifecyclestatus", "assetstatus", "status"},
    "manufacturer": {"manufacturer", "vendor", "make", "brand"},
    "model": {"model", "modelnumber", "productmodel"},
    "serial_number": {"serial", "serialnumber", "serialno", "servicetag"},
    "source_reference": {"sourcereference", "source", "inventorysource", "cmdbreference", "reference"},
    "review_due_at": {"reviewdue", "reviewdate", "nextreview", "reviewdueat"},
    "description": {"assetdescription", "description"},
    "business_function": {"businessfunction", "businessprocess", "function"},
    "physical_location": {"physicallocation"},
    "logical_network_location": {"logicalnetworklocation", "networklocation", "logicaladdress"},
    "acquired_on": {"dateofacquisition", "acquisitiondate", "acquiredon"},
    "end_of_support": {"endofsupport", "eos", "eosdate"},
    "end_of_life": {"endoflife", "eol", "eoldate"},
    "decommissioning_plan": {"decommissioningplan", "decommissionplan"},
    "asset_value": {"assetvalue", "value"},
    "risk_rating": {"riskrating", "risklevel"},
    "associated_security_controls": {"associatedsecuritycontrols", "securitycontrols", "controls"},
    "data_stored_or_processed": {"typeofdatastoredorprocessed", "datastoredorprocessed", "datatype"},
    "backup_recovery_status": {"backupandrecoverystatus", "backuprecoverystatus", "backupstatus"},
    "linked_systems_dependencies": {"linkedsystemsdependencies", "dependencies", "linkedsystems"},
    "licensing_warranty_information": {"licensingorwarrantyinformation", "licensingwarranty", "warranty"},
    "last_reviewed_on": {"lastreviewedon", "lastreviewdate"},
}
TEMPLATE_COLUMNS = [
    "asset_id", "asset_name", "asset_description", "asset_type", "classification",
    "business_function", "asset_owner", "custodian_responsible_person",
    "physical_location", "logical_network_location", "date_of_acquisition",
    "end_of_support", "end_of_life", "decommissioning_plan", "current_status",
    "asset_value", "risk_rating", "associated_security_controls",
    "type_of_data_stored_or_processed", "backup_and_recovery_status",
    "linked_systems_dependencies", "licensing_or_warranty_information",
    "cii_asset", "last_reviewed_on", "next_review_due", "manufacturer", "model",
    "serial_number", "site_code", "service_code", "source_reference",
]
CANONICAL_FIELDS = {
    "asset_id": "asset_tag", "asset_name": "name", "asset_description": "description",
    "asset_type": "kind", "classification": "criticality", "business_function": "business_function",
    "asset_owner": "owner_username", "custodian_responsible_person": "custodian_username",
    "physical_location": "physical_location", "logical_network_location": "logical_network_location",
    "date_of_acquisition": "acquired_on", "end_of_support": "end_of_support",
    "end_of_life": "end_of_life", "decommissioning_plan": "decommissioning_plan",
    "current_status": "lifecycle", "asset_value": "asset_value", "risk_rating": "risk_rating",
    "associated_security_controls": "associated_security_controls",
    "type_of_data_stored_or_processed": "data_stored_or_processed",
    "backup_and_recovery_status": "backup_recovery_status",
    "linked_systems_dependencies": "linked_systems_dependencies",
    "licensing_or_warranty_information": "licensing_warranty_information",
    "cii_asset": "is_cii", "last_reviewed_on": "last_reviewed_on",
    "next_review_due": "review_due_at", "manufacturer": "manufacturer", "model": "model",
    "serial_number": "serial_number", "site_code": "site_code", "service_code": "service_code",
    "source_reference": "source_reference",
}
REQUIRED_FIELDS = {
    "asset_tag", "name", "description", "kind", "criticality", "business_function",
    "owner_username", "custodian_username", "physical_location", "logical_network_location",
    "acquired_on", "decommissioning_plan", "lifecycle", "asset_value", "risk_rating",
    "associated_security_controls", "data_stored_or_processed", "backup_recovery_status",
    "linked_systems_dependencies", "licensing_warranty_information", "is_cii",
    "last_reviewed_on", "review_due_at",
}
REQUIRED_VALUE_FIELDS = REQUIRED_FIELDS - {"acquired_on", "last_reviewed_on", "review_due_at"}


def _key(value):
    return re.sub(r"[^a-z0-9]", "", str(value or "").strip().lower())


def _field_map(headers):
    mapped = {}
    for header in headers:
        normalized = _key(header)
        canonical = CANONICAL_FIELDS.get(str(header or "").strip().lower())
        if canonical and canonical not in mapped:
            mapped[canonical] = header
            continue
        for field, aliases in FIELD_ALIASES.items():
            if normalized in aliases and field not in mapped:
                mapped[field] = header
                break
    missing = REQUIRED_FIELDS - mapped.keys()
    if missing:
        raise ValidationError("Required template columns are missing or renamed: " + ", ".join(sorted(missing)) + ". Download and use the standard Asset Register template.")
    return mapped


def _sheet_rows(*, filename, content):
    if not content:
        raise ValidationError("The inventory file is empty.")
    extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    # Trust the file signature over a misleading extension. Excel exports are
    # commonly renamed to .csv without being converted to text.
    if content.startswith(b"PK\x03\x04"):
        extension = "xlsx"
    elif content.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        extension = "xls"
    if extension == "csv":
        text = None
        if content.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
            encodings = ["utf-32"]
        elif content.startswith((b"\xff\xfe", b"\xfe\xff")):
            encodings = ["utf-16"]
        elif b"\x00" in content[:512]:
            encodings = ["utf-16-le", "utf-16-be"]
        else:
            encodings = ["utf-8-sig", "cp1252", "latin-1"]
        for encoding in encodings:
            try:
                text = content.decode(encoding)
                if "\x00" in text:
                    text = None
                    continue
                break
            except UnicodeDecodeError:
                continue
        if text is None:
            raise ValidationError("The CSV text encoding could not be detected.")
        try:
            dialect = csv.Sniffer().sniff(text[:8192], delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(io.StringIO(text), dialect=dialect)
        return reader.fieldnames or [], list(reader)
    if extension == "xlsx":
        from openpyxl import load_workbook
        try:
            sheet = load_workbook(io.BytesIO(content), read_only=True, data_only=True).active
            values = list(sheet.iter_rows(values_only=True))
        except Exception as exc:
            raise ValidationError("XLSX file could not be read.") from exc
    elif extension == "xls":
        import xlrd
        try:
            sheet = xlrd.open_workbook(file_contents=content).sheet_by_index(0)
            values = [sheet.row_values(index) for index in range(sheet.nrows)]
        except Exception as exc:
            raise ValidationError("XLS file could not be read.") from exc
    else:
        raise ValidationError("Upload a CSV, XLSX or XLS asset inventory file.")
    if not values:
        raise ValidationError("The spreadsheet is empty.")
    headers = [str(value or "").strip() for value in values[0]]
    rows = [dict(zip(headers, row)) for row in values[1:] if any(value not in (None, "") for value in row)]
    return headers, rows


def _enum(value, choices, aliases=None):
    normalized = _key(value)
    aliases = aliases or {}
    if normalized in aliases:
        return aliases[normalized]
    for code, label in choices:
        if normalized in {_key(code), _key(label)}:
            return code
    return str(value or "").strip().upper()


def _member_user(*, tenant, value, label):
    wanted = str(value or "").strip().casefold()
    matches = []
    for membership in tenant.memberships.filter(is_active=True).select_related("user"):
        user = membership.user
        candidates = {user.username.casefold(), user.email.casefold(), user.get_full_name().strip().casefold()}
        if wanted and wanted in candidates:
            matches.append(user)
    if len(matches) != 1:
        raise ValidationError(f"{label} '{value}' must match exactly one active tenant username, email or full name.")
    return matches[0]


def _date_value(value, *, required=False):
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    raw = str(value or "").strip()
    if not raw and not required:
        return None
    try:
        return datetime.fromisoformat(raw).date()
    except ValueError as exc:
        raise ValidationError(f"Date '{raw}' must use YYYY-MM-DD format.") from exc


def _compact_row_errors(errors):
    grouped = {}
    for row_number, message in errors:
        grouped.setdefault(message, []).append(row_number)
    summaries = []
    for message, row_numbers in grouped.items():
        if len(row_numbers) == 1:
            location = f"Row {row_numbers[0]}"
        elif row_numbers == list(range(row_numbers[0], row_numbers[-1] + 1)):
            location = f"Rows {row_numbers[0]}-{row_numbers[-1]}"
        else:
            shown = ", ".join(map(str, row_numbers[:8]))
            suffix = f" and {len(row_numbers) - 8} more" if len(row_numbers) > 8 else ""
            location = f"Rows {shown}{suffix}"
        summaries.append(f"{location}: {message}")
    if len(summaries) > 10:
        return summaries[:10] + [f"{len(summaries) - 10} more error groups were omitted."]
    return summaries


def standard_template_rows(username):
    shared = {
        "asset_owner": username, "custodian_responsible_person": username,
        "last_reviewed_on": "2026-01-15", "next_review_due": "2027-01-15",
        "source_reference": "CMDB-2026", "site_code": "", "service_code": "",
    }
    return [
        {**shared, "asset_id": "NET-CORE-001", "asset_name": "Core Edge Router", "asset_description": "Primary internet edge routing platform", "asset_type": "NETWORK_DEVICE", "classification": "CRITICAL", "business_function": "Internet connectivity", "physical_location": "Karachi DC - Rack A01", "logical_network_location": "Core VRF / management DNS name", "date_of_acquisition": "2024-01-15", "end_of_support": "2028-12-31", "end_of_life": "2029-12-31", "decommissioning_plan": "Replace during approved network refresh and securely erase configuration", "current_status": "ACTIVE", "asset_value": "Tier 1 / finance reference FIN-001", "risk_rating": "CRITICAL", "associated_security_controls": "MFA; AAA; configuration backup; logging; access review", "type_of_data_stored_or_processed": "Network configuration and traffic metadata", "backup_and_recovery_status": "Nightly configuration backup; restore test passed", "linked_systems_dependencies": "Upstream transit; core firewall; AAA; NMS", "licensing_or_warranty_information": "Support contract SUP-001 valid to 2028-12-31", "cii_asset": "YES", "manufacturer": "Example Vendor", "model": "Example Router 9000", "serial_number": "EXAMPLE-NET-001"},
        {**shared, "asset_id": "APP-BILLING-001", "asset_name": "Billing Platform", "asset_description": "Customer billing application", "asset_type": "APPLICATION", "classification": "CRITICAL", "business_function": "Billing and revenue assurance", "physical_location": "Primary data center", "logical_network_location": "Production application segment", "date_of_acquisition": "2025-03-01", "end_of_support": "2029-03-01", "end_of_life": "2030-03-01", "decommissioning_plan": "Archive required records, revoke access and retire through CAB", "current_status": "ACTIVE", "asset_value": "Tier 1", "risk_rating": "HIGH", "associated_security_controls": "RBAC; encryption; audit logs; vulnerability management", "type_of_data_stored_or_processed": "Billing and customer account data", "backup_and_recovery_status": "Daily backup; quarterly recovery test", "linked_systems_dependencies": "Database cluster; identity provider; payment gateway", "licensing_or_warranty_information": "Enterprise license LIC-APP-001", "cii_asset": "YES", "manufacturer": "Internal / Supplier", "model": "Release 5", "serial_number": ""},
        {**shared, "asset_id": "SRV-MON-001", "asset_name": "Monitoring Server", "asset_description": "Infrastructure monitoring and alerting server", "asset_type": "SERVER", "classification": "HIGH", "business_function": "Network operations monitoring", "physical_location": "Islamabad DC - Rack B04", "logical_network_location": "Management segment", "date_of_acquisition": "2023-06-10", "end_of_support": "2027-06-10", "end_of_life": "2028-06-10", "decommissioning_plan": "Migrate monitoring, sanitize disks and record disposal", "current_status": "ACTIVE", "asset_value": "Tier 2", "risk_rating": "HIGH", "associated_security_controls": "EDR; hardening; patching; restricted administration", "type_of_data_stored_or_processed": "Availability metrics and infrastructure alerts", "backup_and_recovery_status": "Weekly full backup; recovery procedure documented", "linked_systems_dependencies": "Network devices; notification gateway; directory service", "licensing_or_warranty_information": "Warranty WAR-001", "cii_asset": "NO", "manufacturer": "Example Vendor", "model": "Example Server R1", "serial_number": "EXAMPLE-SRV-001"},
    ]


def asset_template_csv(username):
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=TEMPLATE_COLUMNS, lineterminator="\n")
    writer.writeheader(); writer.writerows(standard_template_rows(username))
    return stream.getvalue().encode("utf-8-sig")


def asset_template_xlsx(username):
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill
    workbook = Workbook(); sheet = workbook.active; sheet.title = "Asset Register"
    sheet.append(TEMPLATE_COLUMNS)
    for row in standard_template_rows(username):
        sheet.append([row.get(column, "") for column in TEMPLATE_COLUMNS])
    for cell in sheet[1]:
        cell.font = Font(bold=True, color="FFFFFF"); cell.fill = PatternFill("solid", fgColor="3157D5")
    sheet.freeze_panes = "A2"; sheet.auto_filter.ref = sheet.dimensions
    instructions = workbook.create_sheet("Instructions")
    instructions.append(["ConfigSentinel Asset Register Template"])
    instructions.append(["Do not rename or remove columns. Replace the three EXAMPLE rows with actual tenant assets."])
    instructions.append(["Dates use YYYY-MM-DD and may be blank when genuinely unknown. Classification: CRITICAL/HIGH/MEDIUM/LOW. Current status: PLANNED/ACTIVE/MAINTENANCE/RETIRED. CII asset: YES/NO."])
    instructions.append(["Owner and custodian must match an active workspace username, email or full name. site_code/service_code may remain blank until those records exist."])
    output = io.BytesIO(); workbook.save(output); return output.getvalue()


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
def import_assets_file(*, tenant, actor, filename, content):
    require_inventory_operator(tenant=tenant, actor=actor)
    headers, source_rows = _sheet_rows(filename=filename, content=content)
    mapping = _field_map(headers)
    rows, errors, seen_tags = [], [], set()
    for number, source_row in enumerate(source_rows, start=2):
        try:
            row = {field: source_row.get(header, "") for field, header in mapping.items()}
            row = {field: "" if value is None else str(value).strip() for field, value in row.items()}
            blank_required = sorted(field for field in REQUIRED_VALUE_FIELDS if not row.get(field, "").strip())
            if blank_required:
                raise ValidationError("Required values are blank: " + ", ".join(blank_required))
            owner = _member_user(tenant=tenant, value=row["owner_username"], label="Owner")
            custodian = _member_user(tenant=tenant, value=row["custodian_username"], label="Custodian")
            site_code, service_code = row.get("site_code", "").strip(), row.get("service_code", "").strip()
            site = Site.objects.filter(tenant=tenant).filter(models.Q(code__iexact=site_code) | models.Q(name__iexact=site_code)).first() if site_code else None
            service = CriticalService.objects.filter(tenant=tenant).filter(models.Q(code__iexact=service_code) | models.Q(name__iexact=service_code)).first() if service_code else None
            if site_code and not site:
                raise ValidationError(f"Unknown site_code {site_code}.")
            if service_code and not service:
                raise ValidationError(f"Unknown service_code {service_code}.")
            tag = row["asset_tag"].strip()
            if tag in seen_tags:
                raise ValidationError(f"Duplicate asset_tag {tag} in this batch.")
            seen_tags.add(tag)
            kind = _enum(row["kind"], Asset.Kind.choices, {"router": Asset.Kind.NETWORK_DEVICE, "switch": Asset.Kind.NETWORK_DEVICE, "olt": Asset.Kind.NETWORK_DEVICE, "firewall": Asset.Kind.SECURITY_DEVICE, "vm": Asset.Kind.SERVER})
            criticality = _enum(row["criticality"], CriticalService.Criticality.choices)
            classification = _enum(row.get("classification", "INTERNAL"), Asset.Classification.choices)
            lifecycle = _enum(row.get("lifecycle", "ACTIVE"), Asset.Lifecycle.choices)
            obj = Asset(tenant=tenant, asset_tag=tag, name=row["name"], description=row["description"], kind=kind, business_function=row["business_function"], owner=owner, custodian=custodian, criticality=criticality, site=site, service=service, is_cii=row["is_cii"].lower() in {"1", "true", "yes", "y", "cii"}, classification=classification, lifecycle=lifecycle, manufacturer=row.get("manufacturer", ""), model=row.get("model", ""), serial_number=row.get("serial_number", ""), physical_location=row["physical_location"], logical_network_location=row["logical_network_location"], acquired_on=_date_value(row["acquired_on"]), end_of_support=_date_value(row.get("end_of_support")), end_of_life=_date_value(row.get("end_of_life")), decommissioning_plan=row["decommissioning_plan"], asset_value=row["asset_value"], risk_rating=row["risk_rating"], associated_security_controls=row["associated_security_controls"], data_stored_or_processed=row["data_stored_or_processed"], backup_recovery_status=row["backup_recovery_status"], linked_systems_dependencies=row["linked_systems_dependencies"], licensing_warranty_information=row["licensing_warranty_information"], source_reference=row.get("source_reference", ""), last_reviewed_on=_date_value(row["last_reviewed_on"]), review_due_at=_date_value(row["review_due_at"]), created_by=actor)
            obj.full_clean()
            rows.append(obj)
        except Exception as exc:
            message = "; ".join(getattr(exc, "messages", [str(exc)]))
            errors.append((number, message))
    if errors:
        raise ValidationError(_compact_row_errors(errors))
    Asset.objects.bulk_create(rows)
    AuditEvent.objects.create(tenant=tenant, actor=actor, action="inventory.assets_imported", object_type="Asset", object_id="batch", metadata={"count": len(rows)})
    return len(rows)


def import_assets_csv(*, tenant, actor, content):
    """Backward-compatible wrapper for existing callers."""
    return import_assets_file(tenant=tenant, actor=actor, filename="assets.csv", content=content)
