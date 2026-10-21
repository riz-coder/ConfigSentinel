from django.contrib import admin
from django.conf import settings
from django.contrib.auth import views as auth_views
from django.http import JsonResponse
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from rest_framework.schemas import get_schema_view

from apps.regulatory.api import (
    ControlDefinitionViewSet, EvidenceRequirementViewSet, ObligationControlMappingViewSet,
    RegulationViewSet, RegulatorySourceViewSet, RegulatoryVersionViewSet,
    TestProcedureViewSet, TrustedSigningKeyViewSet,
    ClauseAuditAssessmentViewSet, ClauseEvidenceReviewViewSet,
    AuditorAccountViewSet, AuditorReportViewSet,
    AuditorReportImportViewSet, AuditorReportImportRowViewSet,
    CorrectiveActionViewSet,
)
from apps.regulatory.views import audit_report, auditor_report_download, auditor_room, corrective_action_center, dashboard, mapping_center, regulatory_center
from apps.evidence.api import EvidenceArtifactViewSet
from apps.evidence.views import evidence_center, evidence_download
from apps.collector.api import CollectionJobViewSet, CollectorAgentViewSet, CommandProfileViewSet, CredentialReferenceViewSet, DeviceViewSet, ScopeGrantViewSet
from apps.collector.views import collector_center
from apps.security.views import MFASetupView, MFAVerifyView

router = DefaultRouter()
router.register("regulatory-sources", RegulatorySourceViewSet, basename="regulatory-source")
router.register("regulations", RegulationViewSet, basename="regulation")
router.register("regulatory-versions", RegulatoryVersionViewSet, basename="regulatory-version")
router.register("regulatory-signing-keys", TrustedSigningKeyViewSet, basename="regulatory-signing-key")
router.register("controls", ControlDefinitionViewSet, basename="control")
router.register("test-procedures", TestProcedureViewSet, basename="test-procedure")
router.register("evidence-requirements", EvidenceRequirementViewSet, basename="evidence-requirement")
router.register("obligation-mappings", ObligationControlMappingViewSet, basename="obligation-mapping")
router.register("clause-evidence-reviews", ClauseEvidenceReviewViewSet, basename="clause-evidence-review")
router.register("clause-audit-assessments", ClauseAuditAssessmentViewSet, basename="clause-audit-assessment")
router.register("auditor-accounts", AuditorAccountViewSet, basename="auditor-account")
router.register("auditor-reports", AuditorReportViewSet, basename="auditor-report")
router.register("auditor-report-imports", AuditorReportImportViewSet, basename="auditor-report-import")
router.register("auditor-report-import-rows", AuditorReportImportRowViewSet, basename="auditor-report-import-row")
router.register("corrective-actions", CorrectiveActionViewSet, basename="corrective-action")
router.register("evidence", EvidenceArtifactViewSet, basename="evidence")
router.register("devices", DeviceViewSet, basename="device")
router.register("credential-references", CredentialReferenceViewSet, basename="credential-reference")
router.register("collector-agents", CollectorAgentViewSet, basename="collector-agent")
router.register("command-profiles", CommandProfileViewSet, basename="command-profile")
router.register("scope-grants", ScopeGrantViewSet, basename="scope-grant")
router.register("collection-jobs", CollectionJobViewSet, basename="collection-job")

urlpatterns = [
    path("health/", lambda request: JsonResponse({"status": "ok"}), name="health"),
    path("api/v1/openapi/", get_schema_view(title=f"{settings.PRODUCT_NAME} API", version="1.0.0"), name="openapi-schema"),
    path("admin/", admin.site.urls),
    path("accounts/login/", auth_views.LoginView.as_view(template_name="registration/login.html"), name="login"),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("accounts/mfa/setup/", MFASetupView.as_view(), name="mfa-setup"),
    path("accounts/mfa/verify/", MFAVerifyView.as_view(), name="mfa-verify"),
    path("api/v1/", include(router.urls)),
    path("regulatory/", regulatory_center, name="regulatory-center"),
    path("regulatory/mappings/", mapping_center, name="mapping-center"),
    path("auditor/", auditor_room, name="auditor-room"),
    path("auditor/report/", audit_report, name="audit-report"),
    path("auditor/reports/<uuid:report_id>/download/", auditor_report_download, name="auditor-report-download"),
    path("actions/", corrective_action_center, name="corrective-action-center"),
    path("evidence/", evidence_center, name="evidence-center"),
    path("evidence/<uuid:artifact_id>/download/", evidence_download, name="evidence-download"),
    path("collector/", collector_center, name="collector-center"),
    path("", dashboard, name="dashboard"),
]

