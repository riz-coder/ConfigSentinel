import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q

from apps.tenancy.models import Tenant


class Site(models.Model):
    class Kind(models.TextChoices):
        HEAD_OFFICE = "HEAD_OFFICE", "Head office"
        DATA_CENTER = "DATA_CENTER", "Data center"
        POP = "POP", "Point of presence"
        EXCHANGE = "EXCHANGE", "Exchange"
        OFFICE = "OFFICE", "Office"
        OTHER = "OTHER", "Other"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="inventory_sites")
    code = models.CharField(max_length=40)
    name = models.CharField(max_length=160)
    kind = models.CharField(max_length=20, choices=Kind.choices)
    city = models.CharField(max_length=100, blank=True)
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["code"]
        constraints = [models.UniqueConstraint(fields=["tenant", "code"], name="unique_tenant_site_code")]

    def __str__(self):
        return f"{self.code} - {self.name}"


class CriticalService(models.Model):
    class Criticality(models.TextChoices):
        LOW = "LOW", "Low"
        MEDIUM = "MEDIUM", "Medium"
        HIGH = "HIGH", "High"
        CRITICAL = "CRITICAL", "Critical"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="critical_services")
    code = models.CharField(max_length=40)
    name = models.CharField(max_length=160)
    description = models.TextField(blank=True)
    criticality = models.CharField(max_length=12, choices=Criticality.choices)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="owned_critical_services")
    rto_hours = models.PositiveIntegerField(null=True, blank=True)
    rpo_hours = models.PositiveIntegerField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="created_critical_services")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["code"]
        constraints = [models.UniqueConstraint(fields=["tenant", "code"], name="unique_tenant_service_code")]

    def clean(self):
        if self.owner_id and not self.owner.tenant_memberships.filter(tenant=self.tenant, is_active=True).exists():
            raise ValidationError({"owner": "Service owner must be an active member of this tenant."})

    def __str__(self):
        return f"{self.code} - {self.name}"


class Asset(models.Model):
    class Kind(models.TextChoices):
        NETWORK_DEVICE = "NETWORK_DEVICE", "Network device"
        SERVER = "SERVER", "Server"
        APPLICATION = "APPLICATION", "Application"
        DATABASE = "DATABASE", "Database"
        SECURITY_DEVICE = "SECURITY_DEVICE", "Security device"
        CLOUD_RESOURCE = "CLOUD_RESOURCE", "Cloud resource"
        FACILITY = "FACILITY", "Facility"
        OTHER = "OTHER", "Other"

    class Lifecycle(models.TextChoices):
        PLANNED = "PLANNED", "Planned"
        ACTIVE = "ACTIVE", "Active"
        MAINTENANCE = "MAINTENANCE", "Maintenance"
        RETIRED = "RETIRED", "Retired"

    class Classification(models.TextChoices):
        PUBLIC = "PUBLIC", "Public"
        INTERNAL = "INTERNAL", "Internal"
        CONFIDENTIAL = "CONFIDENTIAL", "Confidential"
        RESTRICTED = "RESTRICTED", "Restricted"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="assets")
    asset_tag = models.CharField(max_length=80)
    name = models.CharField(max_length=160)
    description = models.TextField(default="")
    kind = models.CharField(max_length=24, choices=Kind.choices)
    business_function = models.CharField(max_length=200, default="")
    site = models.ForeignKey(Site, null=True, blank=True, on_delete=models.PROTECT, related_name="assets")
    service = models.ForeignKey(CriticalService, null=True, blank=True, on_delete=models.PROTECT, related_name="assets")
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="owned_assets")
    custodian = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="custodied_assets")
    criticality = models.CharField(max_length=12, choices=CriticalService.Criticality.choices)
    classification = models.CharField(max_length=16, choices=Classification.choices, default=Classification.INTERNAL)
    lifecycle = models.CharField(max_length=16, choices=Lifecycle.choices, default=Lifecycle.ACTIVE)
    is_cii = models.BooleanField(default=False)
    manufacturer = models.CharField(max_length=80, blank=True)
    model = models.CharField(max_length=100, blank=True)
    serial_number = models.CharField(max_length=120, blank=True)
    physical_location = models.CharField(max_length=240, default="")
    logical_network_location = models.CharField(max_length=240, default="")
    acquired_on = models.DateField(null=True)
    end_of_support = models.DateField(null=True, blank=True)
    end_of_life = models.DateField(null=True, blank=True)
    decommissioning_plan = models.TextField(default="")
    asset_value = models.CharField(max_length=120, default="")
    risk_rating = models.CharField(max_length=40, default="")
    associated_security_controls = models.TextField(default="")
    data_stored_or_processed = models.TextField(default="")
    backup_recovery_status = models.CharField(max_length=200, default="")
    linked_systems_dependencies = models.TextField(default="")
    licensing_warranty_information = models.TextField(default="")
    source_reference = models.CharField(max_length=160, blank=True)
    last_reviewed_on = models.DateField(null=True)
    review_due_at = models.DateField(null=True, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="created_assets")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["asset_tag"]
        constraints = [
            models.UniqueConstraint(fields=["tenant", "asset_tag"], name="unique_tenant_asset_tag"),
            models.UniqueConstraint(fields=["tenant", "serial_number"], condition=~Q(serial_number=""), name="unique_tenant_asset_serial"),
        ]

    def clean(self):
        if self.site_id and self.site.tenant_id != self.tenant_id:
            raise ValidationError({"site": "Site must belong to the active tenant."})
        if self.service_id and self.service.tenant_id != self.tenant_id:
            raise ValidationError({"service": "Service must belong to the active tenant."})
        for field in ("owner", "custodian"):
            user = getattr(self, field, None)
            if user and not user.tenant_memberships.filter(tenant=self.tenant, is_active=True).exists():
                raise ValidationError({field: f"{field.title()} must be an active member of this tenant."})
        if self.end_of_support and self.end_of_life and self.end_of_support > self.end_of_life:
            raise ValidationError({"end_of_life": "End-of-life cannot be before end-of-support."})
        if self.review_due_at and self.last_reviewed_on and self.review_due_at <= self.last_reviewed_on:
            raise ValidationError({"review_due_at": "Next review must be after the last review date."})

    def __str__(self):
        return f"{self.asset_tag} - {self.name}"


class AssetDependency(models.Model):
    class Kind(models.TextChoices):
        NETWORK = "NETWORK", "Network"
        COMPUTE = "COMPUTE", "Compute"
        DATA = "DATA", "Data"
        IDENTITY = "IDENTITY", "Identity"
        FACILITY = "FACILITY", "Facility"
        OTHER = "OTHER", "Other"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="asset_dependencies")
    dependent = models.ForeignKey(Asset, on_delete=models.PROTECT, related_name="dependencies")
    provider = models.ForeignKey(Asset, on_delete=models.PROTECT, related_name="dependents")
    kind = models.CharField(max_length=16, choices=Kind.choices)
    notes = models.TextField(blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["dependent", "provider", "kind"], name="unique_asset_dependency"),
            models.CheckConstraint(condition=~Q(dependent=models.F("provider")), name="asset_dependency_not_self"),
        ]

    def clean(self):
        if self.dependent_id and self.provider_id:
            if self.dependent.tenant_id != self.tenant_id or self.provider.tenant_id != self.tenant_id:
                raise ValidationError("Dependency assets must belong to the active tenant.")
            if self.dependent_id == self.provider_id:
                raise ValidationError("An asset cannot depend on itself.")
