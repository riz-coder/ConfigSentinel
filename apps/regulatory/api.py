from django.core.exceptions import PermissionDenied as DjangoPermissionDenied, ValidationError as DjangoValidationError
from rest_framework import mixins, permissions, serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.response import Response

from apps.auditlog.models import AuditEvent
from apps.tenancy.access import tenant_for_request
from apps.tenancy.models import Membership

from .models import (
    ControlDefinition, EvidenceRequirement, MappingReview, ObligationControlMapping,
    Regulation, RegulatoryReview, RegulatorySource, RegulatoryVersion, TestProcedure,
    TrustedSigningKey,
    ClauseAuditAssessment, ClauseEvidence, ClauseEvidenceReview, SubClause,
    AuditorReport,
)
from .serializers import (
    ControlDefinitionSerializer, EvidenceRequirementSerializer, ObligationControlMappingSerializer,
    RegulationSerializer, RegulatorySourceSerializer, RegulatoryVersionSerializer,
    TestProcedureSerializer, TrustedSigningKeySerializer,
    ClauseAuditAssessmentSerializer, ClauseEvidenceReviewSerializer,
    ClauseAuditAssessmentCreateSerializer, ClauseEvidenceReviewCreateSerializer,
    AuditorAccountSerializer, AuditorReportSerializer, AuditorReportUploadSerializer,
)
from .services import assess_clause, compare_versions, coverage_report, create_auditor_account, create_mapping, import_pack, review_clause_evidence, review_mapping, review_version, upload_auditor_report


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


class MappingCatalogueViewSet(TenantScopedViewSetMixin, mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.CreateModelMixin, viewsets.GenericViewSet):
    permission_classes = [permissions.IsAuthenticated]
    audit_object_type = ""

    def perform_create(self, serializer):
        tenant = self.tenant()
        if self.request.tenant_membership.role not in {Membership.Role.OWNER, Membership.Role.COMPLIANCE_LEAD}:
            self.permission_denied(self.request, message="Only tenant owners or compliance leads may create mapping catalogue versions.")
        item = serializer.save(tenant=tenant, created_by=self.request.user)
        AuditEvent.objects.create(
            tenant=tenant, actor=self.request.user, action="mapping_catalogue.created",
            object_type=self.audit_object_type, object_id=str(item.id),
            metadata={"key": str(item), "version": item.version},
        )


class ControlDefinitionViewSet(MappingCatalogueViewSet):
    serializer_class = ControlDefinitionSerializer
    audit_object_type = "ControlDefinition"

    def get_queryset(self):
        return ControlDefinition.objects.filter(tenant=self.tenant()).select_related("created_by")


class TestProcedureViewSet(MappingCatalogueViewSet):
    serializer_class = TestProcedureSerializer
    audit_object_type = "TestProcedure"

    def get_queryset(self):
        return TestProcedure.objects.filter(tenant=self.tenant()).select_related("control", "created_by")


class EvidenceRequirementViewSet(MappingCatalogueViewSet):
    serializer_class = EvidenceRequirementSerializer
    audit_object_type = "EvidenceRequirement"

    def get_queryset(self):
        return EvidenceRequirement.objects.filter(tenant=self.tenant()).select_related("test_procedure", "created_by")


class ObligationControlMappingViewSet(TenantScopedViewSetMixin, mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    serializer_class = ObligationControlMappingSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return ObligationControlMapping.objects.filter(tenant=self.tenant()).select_related(
            "obligation", "control", "test_procedure", "evidence_requirement", "created_by",
        ).prefetch_related("reviews__reviewer")

    def create(self, request):
        tenant = self.tenant()
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            AuditEvent.objects.create(
                tenant=tenant, actor=request.user, action="obligation_mapping.denied",
                object_type="ObligationControlMapping", object_id="not_created", metadata={"reason": "invalid_or_cross_tenant_reference"},
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        try:
            mapping = create_mapping(tenant=tenant, actor=request.user, **serializer.validated_data)
        except DjangoPermissionDenied as exc:
            self.permission_denied(request, message=str(exc))
        except DjangoValidationError as exc:
            AuditEvent.objects.create(
                tenant=tenant, actor=request.user, action="obligation_mapping.denied",
                object_type="ObligationControlMapping", object_id="not_created", metadata={"reason": "validation_failed"},
            )
            return Response({"detail": exc.messages}, status=status.HTTP_400_BAD_REQUEST)
        return Response(self.get_serializer(mapping).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"])
    def review(self, request, pk=None):
        tenant = self.tenant()
        mapping = self.get_queryset().filter(pk=pk).first()
        if mapping is None:
            AuditEvent.objects.create(
                tenant=tenant, actor=request.user, action="obligation_mapping.review_denied",
                object_type="ObligationControlMapping", object_id="unavailable", metadata={"reason": "not_found_or_cross_tenant"},
            )
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
        try:
            review_mapping(
                mapping=mapping, reviewer=request.user, kind=request.data.get("kind"),
                decision=request.data.get("decision"), note=request.data.get("note", ""),
            )
        except DjangoPermissionDenied as exc:
            self.permission_denied(request, message=str(exc))
        except DjangoValidationError as exc:
            return Response({"detail": exc.messages}, status=status.HTTP_400_BAD_REQUEST)
        mapping.refresh_from_db()
        return Response(self.get_serializer(mapping).data)


class ClauseEvidenceReviewViewSet(TenantScopedViewSetMixin, mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    serializer_class = ClauseEvidenceReviewSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        return ClauseEvidenceReviewCreateSerializer if self.action == "create" else ClauseEvidenceReviewSerializer

    def get_queryset(self):
        return ClauseEvidenceReview.objects.filter(artifact__tenant=self.tenant()).select_related("artifact", "reviewer")

    def create(self, request):
        incoming = self.get_serializer(data=request.data)
        incoming.is_valid(raise_exception=True)
        artifact = ClauseEvidence.objects.filter(pk=incoming.validated_data["artifact"], tenant=self.tenant()).first()
        if artifact is None:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
        try:
            review = review_clause_evidence(
                artifact=artifact, reviewer=request.user, decision=incoming.validated_data["decision"], note=incoming.validated_data["note"],
            )
        except DjangoPermissionDenied as exc:
            self.permission_denied(request, message=str(exc))
        except DjangoValidationError as exc:
            return Response({"detail": exc.messages}, status=status.HTTP_400_BAD_REQUEST)
        return Response(ClauseEvidenceReviewSerializer(review).data, status=status.HTTP_201_CREATED)


class ClauseAuditAssessmentViewSet(TenantScopedViewSetMixin, mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    serializer_class = ClauseAuditAssessmentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        return ClauseAuditAssessmentCreateSerializer if self.action == "create" else ClauseAuditAssessmentSerializer

    def get_queryset(self):
        return ClauseAuditAssessment.objects.filter(tenant=self.tenant()).select_related("subclause", "reviewer", "preliminary_analysis")

    def create(self, request):
        incoming = self.get_serializer(data=request.data)
        incoming.is_valid(raise_exception=True)
        clause = SubClause.objects.filter(pk=incoming.validated_data["subclause"], regulation__version__source__tenant=self.tenant()).first()
        if clause is None:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
        try:
            assessment = assess_clause(
                subclause=clause, reviewer=request.user, decision=incoming.validated_data["decision"],
                note=incoming.validated_data["note"], gaps=incoming.validated_data.get("gaps", ""),
            )
        except DjangoPermissionDenied as exc:
            self.permission_denied(request, message=str(exc))
        except DjangoValidationError as exc:
            return Response({"detail": exc.messages}, status=status.HTTP_400_BAD_REQUEST)
        return Response(ClauseAuditAssessmentSerializer(assessment).data, status=status.HTTP_201_CREATED)


class AuditorAccountViewSet(TenantScopedViewSetMixin, mixins.ListModelMixin, viewsets.GenericViewSet):
    serializer_class = AuditorAccountSerializer
    permission_classes = [permissions.IsAuthenticated]

    def list(self, request):
        if request.tenant_membership.role != Membership.Role.OWNER:
            self.permission_denied(request, message="Only the tenant owner may manage auditor accounts.")
        rows = Membership.objects.filter(
            tenant=self.tenant(), role=Membership.Role.AUDITOR, is_active=True,
        ).select_related("user")
        return Response([{"id": row.user_id, "username": row.user.username, "email": row.user.email} for row in rows])

    def create(self, request):
        incoming = self.get_serializer(data=request.data)
        incoming.is_valid(raise_exception=True)
        try:
            user = create_auditor_account(
                tenant=self.tenant(), actor=request.user,
                username=incoming.validated_data["username"], email=incoming.validated_data.get("email", ""),
                password=incoming.validated_data["password"],
            )
        except DjangoPermissionDenied as exc:
            self.permission_denied(request, message=str(exc))
        except DjangoValidationError as exc:
            return Response({"detail": exc.messages}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"id": user.pk, "username": user.username, "email": user.email}, status=status.HTTP_201_CREATED)


class AuditorReportViewSet(TenantScopedViewSetMixin, mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def get_serializer_class(self):
        return AuditorReportUploadSerializer if self.action == "create" else AuditorReportSerializer

    def get_queryset(self):
        return AuditorReport.objects.filter(tenant=self.tenant()).select_related("uploaded_by")

    def create(self, request):
        incoming = self.get_serializer(data=request.data)
        incoming.is_valid(raise_exception=True)
        upload = incoming.validated_data["report"]
        try:
            report = upload_auditor_report(
                tenant=self.tenant(), actor=request.user, title=incoming.validated_data["title"],
                filename=upload.name, content=upload.read(),
            )
        except DjangoPermissionDenied as exc:
            self.permission_denied(request, message=str(exc))
        except DjangoValidationError as exc:
            return Response({"detail": exc.messages}, status=status.HTTP_400_BAD_REQUEST)
        return Response(AuditorReportSerializer(report).data, status=status.HTTP_201_CREATED)

