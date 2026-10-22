import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q

from apps.tenancy.models import Tenant
from apps.inventory.models import Asset


class Device(models.Model):
    class Transport(models.TextChoices):
        SSH = "SSH", "SSH"
        TELNET = "TELNET", "Telnet (legacy exception)"

    class Vendor(models.TextChoices):
        CISCO = "CISCO", "Cisco"
        HUAWEI = "HUAWEI", "Huawei"
        MIKROTIK = "MIKROTIK", "MikroTik"
        OTHER = "OTHER", "Other / unsupported"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="devices")
    asset = models.ForeignKey(Asset, null=True, blank=True, on_delete=models.PROTECT, related_name="collector_devices")
    name = models.CharField(max_length=160)
    vendor = models.CharField(max_length=20, choices=Vendor.choices)
    platform = models.CharField(max_length=80, blank=True)
    software_release = models.CharField(max_length=80, blank=True)
    management_address = models.GenericIPAddressField()
    transport = models.CharField(max_length=10, choices=Transport.choices, default=Transport.SSH)
    ssh_port = models.PositiveIntegerField(default=22)
    pinned_host_key_sha256 = models.CharField(max_length=95, blank=True)
    telnet_exception_reference = models.CharField(max_length=160, blank=True)
    telnet_risk_acknowledgement = models.TextField(blank=True)
    telnet_approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="approved_telnet_devices")
    telnet_approved_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["tenant", "management_address", "ssh_port"], name="unique_tenant_device_endpoint"),
            models.CheckConstraint(condition=Q(ssh_port__gte=1, ssh_port__lte=65535), name="valid_device_ssh_port"),
        ]

    def clean(self):
        if self.asset_id and (self.asset.tenant_id != self.tenant_id or not self.asset.is_active):
            raise ValidationError({"asset": "Device must link to an active asset in the same tenant."})
        if self.transport == self.Transport.SSH and (not self.pinned_host_key_sha256.startswith("SHA256:") or len(self.pinned_host_key_sha256) < 20):
            raise ValidationError({"pinned_host_key_sha256": "A pinned SHA256 host-key fingerprint is required."})
        if self.transport == self.Transport.TELNET:
            if not self.telnet_exception_reference.strip() or len(self.telnet_risk_acknowledgement.strip()) < 20:
                raise ValidationError("Telnet requires an exception reference and explicit transport-risk acknowledgement.")
            if self.pinned_host_key_sha256:
                raise ValidationError({"pinned_host_key_sha256": "Telnet has no SSH host key; do not enter a misleading fingerprint."})

    def __str__(self):
        return self.name


class CredentialReference(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="credential_references")
    name = models.CharField(max_length=120)
    provider = models.CharField(max_length=40)
    secret_reference = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["tenant", "name"], name="unique_tenant_credential_name")]

    def clean(self):
        if "://" not in self.secret_reference or self.secret_reference.lower().startswith(("http://", "https://")):
            raise ValidationError({"secret_reference": "Use an opaque secrets-manager reference, never a URL or raw credential."})

    def __str__(self):
        return self.name


class CollectorAgent(models.Model):
    class Status(models.TextChoices):
        PENDING = "PENDING", "Pending"
        ACTIVE = "ACTIVE", "Active"
        SUSPENDED = "SUSPENDED", "Suspended"
        REVOKED = "REVOKED", "Revoked"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="collector_agents")
    name = models.CharField(max_length=120)
    identity_fingerprint = models.CharField(max_length=95)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    registered_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    activated_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="activated_collector_agents")
    activated_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["tenant", "identity_fingerprint"], name="unique_tenant_agent_identity")]

    def clean(self):
        value = self.identity_fingerprint.strip()
        if not value.startswith("SHA256:") or len(value) < 20:
            raise ValidationError({"identity_fingerprint": "A SHA256 agent identity fingerprint is required."})


class CommandProfile(models.Model):
    class Status(models.TextChoices):
        DRAFT = "DRAFT", "Draft / non-executable"
        APPROVED = "APPROVED", "Approved"
        REVOKED = "REVOKED", "Revoked"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="command_profiles")
    name = models.CharField(max_length=120)
    vendor = models.CharField(max_length=20, choices=Device.Vendor.choices)
    platform = models.CharField(max_length=80)
    version = models.PositiveIntegerField(default=1)
    manifest_sha256 = models.CharField(max_length=64)
    command_count = models.PositiveIntegerField(default=0)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.DRAFT)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="created_command_profiles")
    approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="approved_command_profiles")
    approved_at = models.DateTimeField(null=True, blank=True)
    approval_reference = models.CharField(max_length=160, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["tenant", "name", "version"], name="unique_tenant_command_profile_version")]


class CommandDefinition(models.Model):
    class Purpose(models.TextChoices):
        DISCOVERY = "DISCOVERY", "Platform discovery"
        CONFIGURATION = "CONFIGURATION", "Configuration assessment"
        SECURITY = "SECURITY", "Security posture"
        TOPOLOGY = "TOPOLOGY", "Topology discovery"
        OPERATIONS = "OPERATIONS", "Operational health"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="command_definitions")
    profile = models.ForeignKey(CommandProfile, on_delete=models.PROTECT, related_name="commands")
    key = models.CharField(max_length=80)
    command_text = models.CharField(max_length=200)
    purpose = models.CharField(max_length=20, choices=Purpose.choices)
    sequence = models.PositiveSmallIntegerField()
    contains_sensitive_output = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["sequence"]
        constraints = [
            models.UniqueConstraint(fields=["profile", "key"], name="unique_profile_command_key"),
            models.UniqueConstraint(fields=["profile", "sequence"], name="unique_profile_command_sequence"),
        ]

    def clean(self):
        if self.profile_id and self.profile.tenant_id != self.tenant_id:
            raise ValidationError("Command and profile must belong to the same tenant.")


class ScopeGrant(models.Model):
    class Status(models.TextChoices):
        DRAFT = "DRAFT", "Draft"
        APPROVED = "APPROVED", "Approved"
        REVOKED = "REVOKED", "Revoked"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="scope_grants")
    device = models.ForeignKey(Device, on_delete=models.PROTECT, related_name="scope_grants")
    agent = models.ForeignKey(CollectorAgent, on_delete=models.PROTECT, related_name="scope_grants")
    credential = models.ForeignKey(CredentialReference, on_delete=models.PROTECT, related_name="scope_grants")
    authorization_reference = models.CharField(max_length=160)
    purpose = models.TextField()
    valid_from = models.DateTimeField()
    valid_until = models.DateTimeField()
    max_commands = models.PositiveSmallIntegerField()
    max_runtime_seconds = models.PositiveIntegerField()
    max_output_bytes = models.PositiveIntegerField()
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.DRAFT)
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="requested_scope_grants")
    approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="approved_scope_grants")
    approved_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def clean(self):
        related = [self.device, self.agent, self.credential]
        if any(item.tenant_id != self.tenant_id for item in related):
            raise ValidationError("Device, agent and credential reference must belong to the same tenant.")
        if self.valid_until <= self.valid_from:
            raise ValidationError({"valid_until": "Authorization end must be after its start."})
        if not (1 <= self.max_commands <= 100 and 1 <= self.max_runtime_seconds <= 3600 and 1 <= self.max_output_bytes <= 100 * 1024 * 1024):
            raise ValidationError("Collection budgets exceed the hard safety limits.")


class CollectionJob(models.Model):
    class State(models.TextChoices):
        QUEUED = "QUEUED", "Queued"
        PREFLIGHT = "PREFLIGHT", "Preflight"
        CAPABILITY_PROBE = "CAPABILITY_PROBE", "Capability probe"
        COLLECTING = "COLLECTING", "Collecting"
        PARSING = "PARSING", "Parsing"
        ASSESSING = "ASSESSING", "Assessing"
        COMPLETE = "COMPLETE", "Complete"
        PARTIAL = "PARTIAL", "Partial"
        FAILED = "FAILED", "Failed"
        TIMED_OUT = "TIMED_OUT", "Timed out"
        CANCELLED = "CANCELLED", "Cancelled"

    class Result(models.TextChoices):
        UNKNOWN = "UNKNOWN", "Unknown"
        ERROR = "ERROR", "Error"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="collection_jobs")
    device = models.ForeignKey(Device, on_delete=models.PROTECT, related_name="collection_jobs")
    agent = models.ForeignKey(CollectorAgent, on_delete=models.PROTECT, related_name="collection_jobs")
    scope_grant = models.ForeignKey(ScopeGrant, on_delete=models.PROTECT, related_name="collection_jobs")
    command_profile = models.ForeignKey(CommandProfile, on_delete=models.PROTECT, related_name="collection_jobs")
    observed_host_key_sha256 = models.CharField(max_length=95)
    max_commands = models.PositiveSmallIntegerField()
    max_runtime_seconds = models.PositiveIntegerField()
    max_output_bytes = models.PositiveIntegerField()
    state = models.CharField(max_length=16, choices=State.choices, default=State.QUEUED)
    technical_result = models.CharField(max_length=16, choices=Result.choices, default=Result.UNKNOWN)
    failure_reason = models.CharField(max_length=255, blank=True)
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    created_at = models.DateTimeField(auto_now_add=True)
    claimed_at = models.DateTimeField(null=True, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    collector_version = models.CharField(max_length=40, blank=True)
    discovered_vendor = models.CharField(max_length=20, blank=True)
    discovered_platform = models.CharField(max_length=80, blank=True)
    discovered_model = models.CharField(max_length=120, blank=True)
    discovered_release = models.CharField(max_length=80, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["device"], condition=Q(state__in=["QUEUED", "PREFLIGHT", "CAPABILITY_PROBE", "COLLECTING", "PARSING", "ASSESSING"]), name="one_active_job_per_device"),
        ]


class CommandExecution(models.Model):
    class State(models.TextChoices):
        PLANNED = "PLANNED", "Planned"
        SUCCEEDED = "SUCCEEDED", "Succeeded"
        UNSUPPORTED = "UNSUPPORTED", "Unsupported"
        DENIED = "DENIED", "Denied"
        TIMEOUT = "TIMEOUT", "Timeout"
        TRUNCATED = "TRUNCATED", "Truncated"
        ERROR = "ERROR", "Error"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="command_executions")
    job = models.ForeignKey(CollectionJob, on_delete=models.PROTECT, related_name="command_executions")
    command = models.ForeignKey(CommandDefinition, on_delete=models.PROTECT, related_name="executions")
    state = models.CharField(max_length=16, choices=State.choices, default=State.PLANNED)
    reason = models.CharField(max_length=255, blank=True)
    output_size_bytes = models.PositiveIntegerField(default=0)
    output_sha256 = models.CharField(max_length=64, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["command__sequence"]
        constraints = [models.UniqueConstraint(fields=["job", "command"], name="unique_job_command_execution")]

    def clean(self):
        if self.job_id and self.command_id and (self.job.tenant_id != self.tenant_id or self.command.tenant_id != self.tenant_id or self.command.profile_id != self.job.command_profile_id):
            raise ValidationError("Command execution must match the job tenant and approved profile.")


class RawSnapshot(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="raw_snapshots")
    execution = models.OneToOneField(CommandExecution, on_delete=models.PROTECT, related_name="snapshot")
    storage_key = models.CharField(max_length=255)
    wrapped_dek = models.TextField()
    wrap_nonce = models.CharField(max_length=64)
    content_nonce = models.CharField(max_length=64)
    plaintext_sha256 = models.CharField(max_length=64)
    ciphertext_sha256 = models.CharField(max_length=64)
    size_bytes = models.PositiveIntegerField()
    collected_at = models.DateTimeField(auto_now_add=True)

    def clean(self):
        if self.execution_id and self.execution.tenant_id != self.tenant_id:
            raise ValidationError("Snapshot and command execution must belong to the same tenant.")


class DeviceAssessment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="device_assessments")
    job = models.OneToOneField(CollectionJob, on_delete=models.PROTECT, related_name="assessment")
    rule_pack = models.CharField(max_length=80, default="cisco-ios-xe-baseline")
    rule_pack_version = models.PositiveIntegerField(default=1)
    result = models.CharField(max_length=20, choices=[("PASS", "Pass"), ("FAIL", "Fail"), ("WARNING", "Warning"), ("UNKNOWN", "Unknown"), ("ERROR", "Error")], default="UNKNOWN")
    facts = models.JSONField(default=dict)
    assessed_at = models.DateTimeField(auto_now_add=True)

    def clean(self):
        if self.job_id and self.job.tenant_id != self.tenant_id:
            raise ValidationError("Assessment and job must belong to the same tenant.")


class TechnicalFinding(models.Model):
    class Result(models.TextChoices):
        PASS = "PASS", "Pass"
        FAIL = "FAIL", "Fail"
        WARNING = "WARNING", "Warning"
        UNKNOWN = "UNKNOWN", "Unknown"
        NOT_APPLICABLE = "NOT_APPLICABLE", "Not applicable"
        ERROR = "ERROR", "Error"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="technical_findings")
    assessment = models.ForeignKey(DeviceAssessment, on_delete=models.PROTECT, related_name="findings")
    evidence_execution = models.ForeignKey(CommandExecution, null=True, blank=True, on_delete=models.PROTECT, related_name="technical_findings")
    rule_id = models.CharField(max_length=100)
    category = models.CharField(max_length=40)
    severity = models.CharField(max_length=16, choices=[("INFO", "Info"), ("LOW", "Low"), ("MEDIUM", "Medium"), ("HIGH", "High"), ("CRITICAL", "Critical")])
    result = models.CharField(max_length=20, choices=Result.choices)
    title = models.CharField(max_length=200)
    detail = models.TextField()
    remediation = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["assessment", "rule_id"], name="unique_assessment_technical_rule")]

    def clean(self):
        if self.assessment_id and self.assessment.tenant_id != self.tenant_id:
            raise ValidationError("Finding and assessment must belong to the same tenant.")
        if self.evidence_execution_id and self.evidence_execution.tenant_id != self.tenant_id:
            raise ValidationError("Finding evidence must belong to the same tenant.")

