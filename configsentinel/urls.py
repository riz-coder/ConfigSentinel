from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.http import JsonResponse
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from rest_framework.schemas import get_schema_view

from apps.regulatory.api import (
    ControlDefinitionViewSet, EvidenceRequirementViewSet, ObligationControlMappingViewSet,
    RegulationViewSet, RegulatorySourceViewSet, RegulatoryVersionViewSet,
    TestProcedureViewSet, TrustedSigningKeyViewSet,
)
from apps.regulatory.views import dashboard, mapping_center, regulatory_center
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

urlpatterns = [
    path("health/", lambda request: JsonResponse({"status": "ok"}), name="health"),
    path("api/v1/openapi/", get_schema_view(title="ConfigSentinel API", version="1.0.0"), name="openapi-schema"),
    path("admin/", admin.site.urls),
    path("accounts/login/", auth_views.LoginView.as_view(template_name="registration/login.html"), name="login"),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("accounts/mfa/setup/", MFASetupView.as_view(), name="mfa-setup"),
    path("accounts/mfa/verify/", MFAVerifyView.as_view(), name="mfa-verify"),
    path("api/v1/", include(router.urls)),
    path("regulatory/", regulatory_center, name="regulatory-center"),
    path("regulatory/mappings/", mapping_center, name="mapping-center"),
    path("", dashboard, name="dashboard"),
]

