from django.core.exceptions import PermissionDenied as DjangoPermissionDenied, ValidationError as DjangoValidationError
from django.http import HttpResponse
from rest_framework import mixins, permissions, serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.response import Response

from apps.auditlog.models import AuditEvent
from apps.tenancy.access import tenant_for_request

from .models import EvidenceArtifact, EvidenceReview, RetentionHold
from .serializers import EvidenceArtifactSerializer, EvidenceUploadSerializer
from .services import apply_hold, purge_ciphertext, release_hold, retrieve_evidence, review_evidence, upload_evidence
from .vault import EvidenceIntegrityError, VaultError


class EvidenceArtifactViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def tenant(self):
        return tenant_for_request(self.request)

    def get_queryset(self):
        return EvidenceArtifact.objects.filter(tenant=self.tenant()).select_related(
            "mapping", "requirement", "uploaded_by", "review__reviewer",
        ).prefetch_related("retention_holds__applied_by", "retention_holds__released_by", "custody_events__actor")

    def get_serializer_class(self):
        return EvidenceUploadSerializer if self.action == "create" else EvidenceArtifactSerializer

    def artifact_for_action(self, pk, action_name):
        artifact = self.get_queryset().filter(pk=pk).first()
        if artifact is None:
            AuditEvent.objects.create(
                tenant=self.tenant(), actor=self.request.user, action=f"evidence.{action_name}_denied",
                object_type="EvidenceArtifact", object_id="unavailable",
                metadata={"reason": "not_found_or_cross_tenant"},
            )
        return artifact

    def create(self, request):
        tenant = self.tenant()
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            AuditEvent.objects.create(
                tenant=tenant, actor=request.user, action="evidence.upload_denied", object_type="EvidenceArtifact",
                object_id="not_created", metadata={"reason": "invalid_or_cross_tenant_request"},
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        uploaded_file = serializer.validated_data.pop("file")
        try:
            artifact = upload_evidence(
                tenant=tenant, actor=request.user, filename=uploaded_file.name,
                media_type=uploaded_file.content_type or "application/octet-stream",
                content=uploaded_file.read(), **serializer.validated_data,
            )
        except DjangoPermissionDenied as exc:
            self.permission_denied(request, message=str(exc))
        except (DjangoValidationError, VaultError) as exc:
            return Response({"detail": getattr(exc, "messages", [str(exc)])}, status=status.HTTP_400_BAD_REQUEST)
        return Response(EvidenceArtifactSerializer(artifact, context={"request": request}).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["get"])
    def download(self, request, pk=None):
        artifact = self.artifact_for_action(pk, "download")
        if artifact is None:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
        try:
            content = retrieve_evidence(artifact=artifact, actor=request.user)
        except (DjangoPermissionDenied, EvidenceIntegrityError) as exc:
            code = status.HTTP_403_FORBIDDEN if isinstance(exc, DjangoPermissionDenied) else status.HTTP_409_CONFLICT
            return Response({"detail": str(exc)}, status=code)
        response = HttpResponse(content, content_type="application/octet-stream")
        response["Content-Disposition"] = f'attachment; filename="evidence-{artifact.id}"'
        response["X-Content-Type-Options"] = "nosniff"
        response["Cache-Control"] = "no-store"
        return response

    @action(detail=True, methods=["post"])
    def review(self, request, pk=None):
        artifact = self.artifact_for_action(pk, "review")
        if artifact is None:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
        try:
            review_evidence(
                artifact=artifact, reviewer=request.user, decision=request.data.get("decision"),
                note=request.data.get("note", ""),
            )
        except DjangoPermissionDenied as exc:
            self.permission_denied(request, message=str(exc))
        except (DjangoValidationError, EvidenceIntegrityError) as exc:
            return Response({"detail": getattr(exc, "messages", [str(exc)])}, status=status.HTTP_400_BAD_REQUEST)
        artifact.refresh_from_db()
        return Response(EvidenceArtifactSerializer(artifact, context={"request": request}).data)

    @action(detail=True, methods=["post"])
    def hold(self, request, pk=None):
        artifact = self.artifact_for_action(pk, "hold")
        if artifact is None:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
        try:
            hold = apply_hold(artifact=artifact, actor=request.user, reason=request.data.get("reason", ""))
        except DjangoPermissionDenied as exc:
            self.permission_denied(request, message=str(exc))
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages)
        return Response({"id": hold.id, "status": "ACTIVE"}, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"], url_path=r"holds/(?P<hold_id>[^/.]+)/release")
    def release(self, request, pk=None, hold_id=None):
        artifact = self.artifact_for_action(pk, "release")
        hold = RetentionHold.objects.filter(pk=hold_id, artifact=artifact).first() if artifact else None
        if hold is None:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
        try:
            release_hold(hold=hold, actor=request.user, reason=request.data.get("reason", ""))
        except DjangoPermissionDenied as exc:
            self.permission_denied(request, message=str(exc))
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages)
        return Response({"id": hold.id, "status": "RELEASED"})

    @action(detail=True, methods=["post"])
    def purge(self, request, pk=None):
        artifact = self.artifact_for_action(pk, "purge")
        if artifact is None:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
        try:
            purge_ciphertext(artifact=artifact, actor=request.user)
        except DjangoPermissionDenied as exc:
            self.permission_denied(request, message=str(exc))
        except (DjangoValidationError, EvidenceIntegrityError) as exc:
            return Response({"detail": getattr(exc, "messages", [str(exc)])}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"id": artifact.id, "purged": True})
