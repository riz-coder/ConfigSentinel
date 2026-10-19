from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.oath import totp

from apps.auditlog.models import AuditEvent
from apps.tenancy.models import Membership, Tenant


class MFAFlowTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="mfa-user", password="Strong-Test-Pass-2026!")
        self.tenant = Tenant.objects.create(name="MFA Tenant", slug="mfa-tenant")
        Membership.objects.create(user=self.user, tenant=self.tenant, role=Membership.Role.OWNER)
        self.client.force_login(self.user)

    def test_enrollment_confirms_device_and_verifies_session(self):
        response = self.client.get(reverse("mfa-setup"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "data:image/svg+xml;base64")
        device = TOTPDevice.objects.get(user=self.user, confirmed=False)

        token = totp(device.bin_key, device.step, device.t0, device.digits, device.drift)
        response = self.client.post(reverse("mfa-setup"), {"token": str(token)})
        self.assertRedirects(response, reverse("dashboard"), fetch_redirect_response=False)
        device.refresh_from_db()
        self.assertTrue(device.confirmed)
        self.assertTrue(AuditEvent.objects.filter(action="authentication.mfa_enrolled", actor=self.user).exists())

    def test_api_returns_structured_mfa_error(self):
        response = self.client.get("/api/v1/regulatory-sources/")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["code"], "mfa_required")


class LoginThrottlingTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="lock-me", password="Correct-Test-Pass-2026!")

    def test_repeated_failed_login_is_locked_and_audited_without_raw_username(self):
        last_response = None
        for _ in range(5):
            last_response = self.client.post(reverse("login"), {"username": "lock-me", "password": "wrong"})
        self.assertEqual(last_response.status_code, 429)
        events = AuditEvent.objects.filter(action="authentication.password_failed")
        self.assertEqual(events.count(), 5)
        self.assertFalse(events.filter(object_id="lock-me").exists())
