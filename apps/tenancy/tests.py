from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from .models import Membership, Tenant


class DashboardAccessTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="owner", password="a-secure-test-password")
        self.tenant = Tenant.objects.create(name="Alpha Telecom", slug="alpha")
        Membership.objects.create(user=self.user, tenant=self.tenant, role=Membership.Role.OWNER)

    def test_dashboard_requires_authentication(self):
        response = self.client.get(reverse("dashboard"))
        self.assertRedirects(response, f"{reverse('login')}?next=/")

    def test_member_can_open_dashboard(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Alpha Telecom")
        self.assertContains(response, "SOURCE_PENDING")

