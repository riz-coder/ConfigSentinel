from rest_framework import mixins, permissions, viewsets

from apps.auditlog.models import AuditEvent
from apps.tenancy.access import tenant_for_request
from apps.tenancy.models import Membership

from .models import Regulation, RegulatorySource
from .serializers import RegulationSerializer, RegulatorySourceSerializer


class TenantScopedViewSetMixin:
    def tenant(self):
        return tenant_for_request(self.request)


class RegulatorySourceViewSet(TenantScopedViewSetMixin, mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.CreateModelMixin, viewsets.GenericViewSet):
    serializer_class = RegulatorySourceSerializer
    permission_classes = [permissions.IsAuthenticated]
    ordering = "-created_at"

    def get_queryset(self):
        return RegulatorySource.objects.filter(tenant=self.tenant()).select_related("reviewed_by")

    def perform_create(self, serializer):
        tenant = self.tenant()
        membership = self.request.tenant_membership
        if membership.role not in {Membership.Role.OWNER, Membership.Role.LEGAL_REVIEWER}:
            self.permission_denied(self.request, message="Only tenant owners or legal reviewers may add sources.")
        source = serializer.save(tenant=tenant)
        AuditEvent.objects.create(
            tenant=tenant, actor=self.request.user, action="regulatory_source.created",
            object_type="RegulatorySource", object_id=str(source.id), metadata={"legal_status": source.legal_status},
        )


class RegulationViewSet(TenantScopedViewSetMixin, mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    serializer_class = RegulationSerializer
    permission_classes = [permissions.IsAuthenticated]
    ordering = "number"

    def get_queryset(self):
        return Regulation.objects.filter(version__source__tenant=self.tenant()).select_related("version", "version__source")

