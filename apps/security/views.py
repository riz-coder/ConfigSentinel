import base64
from io import BytesIO

import qrcode
import qrcode.image.svg
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.utils.decorators import method_decorator
from django.views import View
from django_otp import login as otp_login
from django_otp.plugins.otp_totp.models import TOTPDevice

from apps.auditlog.models import AuditEvent
from apps.tenancy.models import Membership
from apps.tenancy.rls import set_rls_context


def _tenant_for_user(user):
    membership = Membership.objects.filter(user=user, is_active=True).select_related("tenant").first()
    return membership.tenant if membership else None


def _audit(user, action, device):
    tenant = _tenant_for_user(user)
    set_rls_context(user_id=user.pk, tenant_id=getattr(tenant, "pk", None))
    AuditEvent.objects.create(
        tenant=tenant, actor=user, action=action,
        object_type="TOTPDevice", object_id=str(device.persistent_id), metadata={},
    )


@method_decorator(login_required, name="dispatch")
class MFASetupView(View):
    template_name = "security/mfa_setup.html"

    def get_device(self, user):
        confirmed = TOTPDevice.objects.filter(user=user, confirmed=True).first()
        if confirmed:
            return confirmed
        device, _ = TOTPDevice.objects.get_or_create(user=user, name="primary", confirmed=False)
        return device

    def get(self, request):
        device = self.get_device(request.user)
        if device.confirmed:
            return redirect("mfa-verify")
        qr = qrcode.make(device.config_url, image_factory=qrcode.image.svg.SvgPathImage)
        output = BytesIO()
        qr.save(output)
        qr_data = base64.b64encode(output.getvalue()).decode()
        return render(request, self.template_name, {"qr_data": qr_data})

    def post(self, request):
        device = self.get_device(request.user)
        token = request.POST.get("token", "").replace(" ", "")
        if device.confirmed:
            return redirect("mfa-verify")
        if not device.verify_token(token):
            messages.error(request, "Invalid authenticator code. Check device time and try again.")
            return redirect("mfa-setup")
        device.confirmed = True
        device.save(update_fields=["confirmed"])
        otp_login(request, device)
        _audit(request.user, "authentication.mfa_enrolled", device)
        messages.success(request, "Multi-factor authentication is now enabled.")
        return redirect(request.GET.get("next") or "dashboard")


@method_decorator(login_required, name="dispatch")
class MFAVerifyView(View):
    template_name = "security/mfa_verify.html"

    def get(self, request):
        if request.user.is_verified():
            return redirect(request.GET.get("next") or "dashboard")
        if not TOTPDevice.objects.filter(user=request.user, confirmed=True).exists():
            return redirect("mfa-setup")
        return render(request, self.template_name)

    def post(self, request):
        token = request.POST.get("token", "").replace(" ", "")
        devices = TOTPDevice.objects.filter(user=request.user, confirmed=True)
        device = next((item for item in devices if item.verify_token(token)), None)
        if device is None:
            messages.error(request, "Invalid authenticator code.")
            return redirect("mfa-verify")
        otp_login(request, device)
        _audit(request.user, "authentication.mfa_verified", device)
        return redirect(request.GET.get("next") or "dashboard")

