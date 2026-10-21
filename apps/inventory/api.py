from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import mixins, permissions, serializers, viewsets

from apps.tenancy.access import tenant_for_request

from .models import Asset, AssetDependency, CriticalService, Site
from .serializers import AssetDependencySerializer, AssetSerializer, CriticalServiceSerializer, SiteSerializer
from .services import save_inventory_object


class InventoryViewSet:
    permission_classes = [permissions.IsAuthenticated]
    model = None

    def tenant(self):
        return tenant_for_request(self.request)

    def get_queryset(self):
        return self.model.objects.filter(tenant=self.tenant())

    def perform_create(self, serializer):
        obj = self.model(tenant=self.tenant(), created_by=self.request.user, **serializer.validated_data)
        try:
            save_inventory_object(obj=obj, actor=self.request.user)
            serializer.instance = obj
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.message_dict if hasattr(exc, "message_dict") else exc.messages)


class SiteViewSet(InventoryViewSet, mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.CreateModelMixin, viewsets.GenericViewSet):
    model, serializer_class = Site, SiteSerializer


class CriticalServiceViewSet(InventoryViewSet, mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.CreateModelMixin, viewsets.GenericViewSet):
    model, serializer_class = CriticalService, CriticalServiceSerializer


class AssetViewSet(InventoryViewSet, mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.CreateModelMixin, viewsets.GenericViewSet):
    model, serializer_class = Asset, AssetSerializer
    def get_queryset(self):
        return super().get_queryset().filter(is_active=True).select_related("site", "service", "owner", "custodian")


class AssetDependencyViewSet(InventoryViewSet, mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.CreateModelMixin, viewsets.GenericViewSet):
    model, serializer_class = AssetDependency, AssetDependencySerializer
