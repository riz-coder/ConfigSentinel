from django.core.exceptions import PermissionDenied as DjangoPermissionDenied, ValidationError as DjangoValidationError
from rest_framework import mixins, permissions, serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from apps.auditlog.models import AuditEvent
from apps.tenancy.access import tenant_for_request
from apps.tenancy.models import Membership

from .models import CollectionJob, CollectorAgent, CommandProfile, CredentialReference, Device, ScopeGrant
from .serializers import CollectionJobSerializer, CollectionRequestSerializer, CollectorAgentSerializer, CommandProfileSerializer, CredentialReferenceSerializer, DeviceSerializer, ScopeGrantSerializer
from .services import approve_command_profile, approve_scope, approve_telnet_device, request_collection


class TenantCollectorViewSet:
    permission_classes = [permissions.IsAuthenticated]

    def tenant(self):
        return tenant_for_request(self.request)

    def require_operator(self):
        self.tenant()
        if self.request.tenant_membership.role not in {Membership.Role.OWNER, Membership.Role.COMPLIANCE_LEAD}:
            self.permission_denied(self.request, message="Tenant owner or compliance lead access is required.")

    def save_new(self, serializer, actor_field):
        self.require_operator()
        obj = serializer.save(tenant=self.tenant(), **{actor_field: self.request.user})
        try:
            obj.full_clean()
            obj.save()
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.message_dict if hasattr(exc, "message_dict") else exc.messages)
        AuditEvent.objects.create(tenant=obj.tenant, actor=self.request.user, action=f"collector.{obj._meta.model_name}_created", object_type=obj.__class__.__name__, object_id=str(obj.pk), metadata={})


class DeviceViewSet(TenantCollectorViewSet, mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.CreateModelMixin, viewsets.GenericViewSet):
    serializer_class = DeviceSerializer

    def get_queryset(self):
        return Device.objects.filter(tenant=self.tenant())

    def perform_create(self, serializer):
        self.require_operator()
        transport = serializer.validated_data.get("transport", Device.Transport.SSH)
        obj = serializer.save(tenant=self.tenant(), created_by=self.request.user, is_active=transport != Device.Transport.TELNET)
        try:
            obj.full_clean()
            obj.save()
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.message_dict if hasattr(exc, "message_dict") else exc.messages)
        AuditEvent.objects.create(tenant=obj.tenant, actor=self.request.user, action="collector.device_created", object_type="Device", object_id=str(obj.pk), metadata={"transport": obj.transport})

    @action(detail=True, methods=["post"])
    def approve_telnet(self, request, pk=None):
        try:
            device = approve_telnet_device(device=self.get_object(), actor=request.user)
        except DjangoPermissionDenied as exc:
            self.permission_denied(request, message=str(exc))
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages)
        return Response(self.get_serializer(device).data)


class CredentialReferenceViewSet(TenantCollectorViewSet, mixins.ListModelMixin, mixins.CreateModelMixin, viewsets.GenericViewSet):
    serializer_class = CredentialReferenceSerializer

    def get_queryset(self):
        return CredentialReference.objects.filter(tenant=self.tenant())

    def perform_create(self, serializer):
        self.save_new(serializer, "created_by")


class CollectorAgentViewSet(TenantCollectorViewSet, mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.CreateModelMixin, viewsets.GenericViewSet):
    serializer_class = CollectorAgentSerializer

    def get_queryset(self):
        return CollectorAgent.objects.filter(tenant=self.tenant())

    def perform_create(self, serializer):
        self.save_new(serializer, "registered_by")


class CommandProfileViewSet(TenantCollectorViewSet, mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.CreateModelMixin, viewsets.GenericViewSet):
    serializer_class = CommandProfileSerializer

    def get_queryset(self):
        return CommandProfile.objects.filter(tenant=self.tenant())

    def perform_create(self, serializer):
        self.save_new(serializer, "created_by")

    @action(detail=True, methods=["post"])
    def approve(self, request, pk=None):
        try:
            profile = approve_command_profile(profile=self.get_object(), actor=request.user, approval_reference=request.data.get("approval_reference"))
        except DjangoPermissionDenied as exc:
            self.permission_denied(request, message=str(exc))
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages)
        return Response(self.get_serializer(profile).data)


class ScopeGrantViewSet(TenantCollectorViewSet, mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.CreateModelMixin, viewsets.GenericViewSet):
    serializer_class = ScopeGrantSerializer

    def get_queryset(self):
        return ScopeGrant.objects.filter(tenant=self.tenant()).select_related("device", "agent", "credential", "requested_by", "approved_by")

    def perform_create(self, serializer):
        self.save_new(serializer, "requested_by")

    @action(detail=True, methods=["post"])
    def approve(self, request, pk=None):
        try:
            grant = approve_scope(grant=self.get_object(), actor=request.user)
        except DjangoPermissionDenied as exc:
            self.permission_denied(request, message=str(exc))
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages)
        return Response(self.get_serializer(grant).data)


class CollectionJobViewSet(TenantCollectorViewSet, mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.CreateModelMixin, viewsets.GenericViewSet):
    serializer_class = CollectionJobSerializer

    def get_queryset(self):
        return CollectionJob.objects.filter(tenant=self.tenant()).select_related("device", "agent", "scope_grant", "command_profile")

    def create(self, request):
        tenant = self.tenant()
        incoming = CollectionRequestSerializer(data=request.data)
        incoming.is_valid(raise_exception=True)
        data = incoming.validated_data
        objects = {
            "device": Device.objects.filter(tenant=tenant, pk=data["device"]).first(),
            "agent": CollectorAgent.objects.filter(tenant=tenant, pk=data["agent"]).first(),
            "scope_grant": ScopeGrant.objects.filter(tenant=tenant, pk=data["scope_grant"]).first(),
            "command_profile": CommandProfile.objects.filter(tenant=tenant, pk=data["command_profile"]).first(),
        }
        if any(value is None for value in objects.values()):
            AuditEvent.objects.create(tenant=tenant, actor=request.user, action="collector.job_denied", object_type="CollectionJob", object_id="not_created", metadata={"reason": "invalid_or_cross_tenant_reference"})
            return Response({"detail": "Every referenced object must exist in the active tenant."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            job = request_collection(tenant=tenant, actor=request.user, observed_host_key_sha256=data["observed_host_key_sha256"], **objects)
        except DjangoPermissionDenied as exc:
            self.permission_denied(request, message=str(exc))
        except DjangoValidationError as exc:
            AuditEvent.objects.create(tenant=tenant, actor=request.user, action="collector.job_denied", object_type="CollectionJob", object_id="not_created", metadata={"reason": "safety_validation_failed"})
            raise serializers.ValidationError(exc.messages)
        return Response(self.get_serializer(job).data, status=status.HTTP_201_CREATED)
