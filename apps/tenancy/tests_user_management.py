from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.test import TestCase
from django.urls import reverse
from django_otp.plugins.otp_totp.models import TOTPDevice

from apps.auditlog.models import AuditEvent

from .models import Membership, Tenant
from .services import create_tenant_user, disable_tenant_user, reset_tenant_user_password, transfer_tenant_ownership


class OwnerUserManagementTests(TestCase):
    def setUp(self):
        users = get_user_model().objects
        self.owner = users.create_user(username="workspace-owner", password="Owner-Strong-Pass-2026!")
        self.tenant = Tenant.objects.create(name="Owner Controls ISP", slug="owner-controls-isp")
        self.owner_membership = Membership.objects.create(tenant=self.tenant, user=self.owner, role=Membership.Role.OWNER)
        self.lead = users.create_user(username="workspace-lead", password="Lead-Strong-Pass-2026!")
        self.lead_membership = Membership.objects.create(tenant=self.tenant, user=self.lead, role=Membership.Role.COMPLIANCE_LEAD)

    def login_verified(self, user):
        device = TOTPDevice.objects.create(user=user, name="test", confirmed=True)
        self.client.force_login(user)
        session = self.client.session
        session["otp_device_id"] = device.persistent_id
        session.save()

    def test_owner_creates_user_and_action_is_audited(self):
        membership = create_tenant_user(tenant=self.tenant, actor=self.owner, username="reviewer-two", email="reviewer@example.test", role=Membership.Role.COMPLIANCE_LEAD, temporary_password="Temporary-Strong-2026!")
        self.assertTrue(membership.user.check_password("Temporary-Strong-2026!"))
        self.assertTrue(AuditEvent.objects.filter(action="tenant.user_created", object_id=str(membership.pk)).exists())

    def test_non_owner_cannot_manage_users(self):
        with self.assertRaises(PermissionDenied):
            create_tenant_user(tenant=self.tenant, actor=self.lead, username="blocked", email="", role=Membership.Role.VIEWER, temporary_password="Temporary-Strong-2026!")
        self.login_verified(self.lead)
        self.assertEqual(self.client.get(reverse("user-management")).status_code, 403)

    def test_owner_can_reset_and_disable_but_not_self_disable(self):
        reset_tenant_user_password(membership=self.lead_membership, actor=self.owner, temporary_password="Replacement-Strong-2026!")
        self.lead.refresh_from_db()
        self.assertTrue(self.lead.check_password("Replacement-Strong-2026!"))
        disable_tenant_user(membership=self.lead_membership, actor=self.owner)
        self.lead_membership.refresh_from_db(); self.lead.refresh_from_db()
        self.assertFalse(self.lead_membership.is_active)
        self.assertFalse(self.lead.is_active)
        with self.assertRaises(ValidationError):
            disable_tenant_user(membership=self.owner_membership, actor=self.owner)

    def test_transfer_requires_owner_password_and_leaves_exactly_one_owner(self):
        with self.assertRaises(ValidationError):
            transfer_tenant_ownership(tenant=self.tenant, actor=self.owner, target_membership=self.lead_membership, current_password="wrong")
        transfer_tenant_ownership(tenant=self.tenant, actor=self.owner, target_membership=self.lead_membership, current_password="Owner-Strong-Pass-2026!")
        self.owner_membership.refresh_from_db(); self.lead_membership.refresh_from_db()
        self.assertEqual(self.owner_membership.role, Membership.Role.COMPLIANCE_LEAD)
        self.assertEqual(self.lead_membership.role, Membership.Role.OWNER)
        self.assertEqual(Membership.objects.filter(tenant=self.tenant, role=Membership.Role.OWNER, is_active=True).count(), 1)

    def test_owner_page_creates_compliance_lead(self):
        self.login_verified(self.owner)
        response = self.client.post(reverse("user-management"), {"operation": "create", "username": "telnet-reviewer", "email": "", "role": Membership.Role.COMPLIANCE_LEAD, "password": "Reviewer-Strong-2026!"})
        self.assertRedirects(response, reverse("user-management"))
        self.assertTrue(Membership.objects.filter(tenant=self.tenant, user__username="telnet-reviewer", role=Membership.Role.COMPLIANCE_LEAD).exists())
