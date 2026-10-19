from django.core.exceptions import PermissionDenied as DjangoPermissionDenied, ValidationError as DjangoValidationError
from rest_framework import mixins, permissions, serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.response import Response

from apps.auditlog.models import AuditEvent
from apps.tenancy.access import tenant_for_request
from apps.tenancy.models import Membership

from .models import Regulation, RegulatoryReview, RegulatorySource, RegulatoryVersion, TrustedSigningKey
from .serializers import RegulationSerializer, RegulatorySourceSerializer, RegulatoryVersionSerializer, TrustedSigningKeySerializer
from .services import compare_versions, coverage_report, import_pack, review_version


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


class TrustedSigningKeyViewSet(TenantScopedViewSetMixin, mixins.ListModelMixin, mixins.CreateModelMixin, viewsets.GenericViewSet):
    serializer_class = TrustedSigningKeySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return TrustedSigningKey.objects.filter(tenant=self.tenant()).order_by("name")

    def perform_create(self, serializer):
        tenant = self.tenant()
        if self.request.tenant_membership.role != Membership.Role.OWNER:
            self.permission_denied(self.request, message="Only tenant owners may register trusted signing keys.")
        key = serializer.save(tenant=tenant)
        AuditEvent.objects.create(
            tenant=tenant, actor=self.request.user, action="regulatory_signing_key.registered",
            object_type="TrustedSigningKey", object_id=str(key.id), metadata={"fingerprint": key.fingerprint},
        )


class RegulatoryVersionViewSet(TenantScopedViewSetMixin, mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    serializer_class = RegulatoryVersionSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return RegulatoryVersion.objects.filter(source__tenant=self.tenant()).select_related("source").prefetch_related("reviews__reviewer")

    @action(detail=False, methods=["post"], parser_classes=[MultiPartParser, FormParser], url_path="import")
    def import_manifest(self, request):
        tenant = self.tenant()
        if request.tenant_membership.role not in {Membership.Role.OWNER, Membership.Role.LEGAL_REVIEWER}:
            self.permission_denied(request, message="Only tenant owners or legal reviewers may import packs.")
        try:
            manifest = request.FILES["manifest"]
            signature = request.FILES["signature"]
            signing_key = TrustedSigningKey.objects.get(pk=request.data.get("signing_key"), tenant=tenant, is_active=True)
            version = import_pack(tenant=tenant, actor=request.user, signing_key=signing_key, manifest_bytes=manifest.read(), signature_bytes=signature.read())
        except KeyError:
            raise serializers.ValidationError("manifest and signature files are required.")
        except TrustedSigningKey.DoesNotExist:
            AuditEvent.objects.create(
                tenant=tenant, actor=request.user, action="regulatory_pack.import_denied",
                object_type="TrustedSigningKey", object_id="unavailable", metadata={"reason": "invalid_or_cross_tenant_key"},
            )
            return Response({"detail": "An active signing key for this tenant is required."}, status=status.HTTP_400_BAD_REQUEST)
        except DjangoValidationError as exc:
            AuditEvent.objects.create(
                tenant=tenant, actor=request.user, action="regulatory_pack.import_denied",
                object_type="RegulatoryImportBatch", object_id="not_created", metadata={"reason": "validation_failed"},
            )
            return Response({"detail": exc.messages}, status=status.HTTP_400_BAD_REQUEST)
        return Response(self.get_serializer(version).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"])
    def review(self, request, pk=None):
        tenant = self.tenant()
        version = self.get_queryset().filter(pk=pk).first()
        if version is None:
            AuditEvent.objects.create(
                tenant=tenant, actor=request.user, action="regulatory_version.review_denied",
                object_type="RegulatoryVersion", object_id="unavailable", metadata={"reason": "not_found_or_cross_tenant"},
            )
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
        kind = request.data.get("kind")
        decision = request.data.get("decision")
        if kind not in RegulatoryReview.Kind.values or decision not in RegulatoryReview.Decision.values:
            raise serializers.ValidationError("Valid kind and decision are required.")
        try:
            review_version(version=version, reviewer=request.user, kind=kind, decision=decision, note=request.data.get("note", ""))
        except DjangoPermissionDenied as exc:
            self.permission_denied(request, message=str(exc))
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages)
        return Response(self.get_serializer(RegulatoryVersion.objects.get(pk=version.pk)).data)

    @action(detail=True, methods=["get"])
    def coverage(self, request, pk=None):
        return Response(coverage_report(self.get_object()))

    @action(detail=True, methods=["get"])
    def diff(self, request, pk=None):
        target = self.get_object()
        base = self.get_queryset().filter(pk=request.query_params.get("base")).first()
        if base is None:
            raise serializers.ValidationError("A valid same-tenant base version is required.")
        return Response(compare_versions(base, target))

