from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.http import JsonResponse
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from rest_framework.schemas import get_schema_view

from apps.regulatory.api import RegulationViewSet, RegulatorySourceViewSet
from apps.regulatory.views import dashboard

router = DefaultRouter()
router.register("regulatory-sources", RegulatorySourceViewSet, basename="regulatory-source")
router.register("regulations", RegulationViewSet, basename="regulation")

urlpatterns = [
    path("health/", lambda request: JsonResponse({"status": "ok"}), name="health"),
    path("api/v1/openapi/", get_schema_view(title="ConfigSentinel API", version="1.0.0"), name="openapi-schema"),
    path("admin/", admin.site.urls),
    path("accounts/login/", auth_views.LoginView.as_view(template_name="registration/login.html"), name="login"),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("api/v1/", include(router.urls)),
    path("", dashboard, name="dashboard"),
]

