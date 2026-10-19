from django.http import JsonResponse
from django.shortcuts import redirect
from django.urls import reverse
from django_otp.plugins.otp_totp.models import TOTPDevice


class MFAEnforcementMiddleware:
    EXEMPT_PATHS = {
        "/accounts/login/", "/accounts/logout/", "/accounts/mfa/setup/",
        "/accounts/mfa/verify/", "/health/",
    }

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated and self._requires_mfa(request):
            has_device = TOTPDevice.objects.filter(user=request.user, confirmed=True).exists()
            if not has_device:
                return self._deny_or_redirect(request, "mfa-setup")
            if not request.user.is_verified():
                return self._deny_or_redirect(request, "mfa-verify")
        return self.get_response(request)

    def _requires_mfa(self, request):
        if request.path in self.EXEMPT_PATHS:
            return False
        return not request.path.startswith("/static/")

    @staticmethod
    def _deny_or_redirect(request, url_name):
        if request.path.startswith("/api/"):
            return JsonResponse({"detail": "MFA verification required.", "code": "mfa_required"}, status=403)
        destination = f"{reverse(url_name)}?next={request.get_full_path()}"
        return redirect(destination)

