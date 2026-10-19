from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.tenancy.models import Tenant
from apps.tenancy.rls import set_rls_context

from .models import AuditEvent


class AuditEventImmutabilityTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="auditor")
        self.tenant = Tenant.objects.create(name="Alpha", slug="alpha")
        set_rls_context(user_id=self.user.pk, tenant_id=self.tenant.pk)
        self.event = AuditEvent.objects.create(
            tenant=self.tenant, actor=self.user, action="test.created", object_type="Test", object_id="1"
        )

    def test_existing_event_cannot_be_saved(self):
        self.event.action = "tampered"
        with self.assertRaises(ValidationError):
            self.event.save()

    def test_event_cannot_be_deleted_by_instance_or_queryset(self):
        with self.assertRaises(ValidationError):
            self.event.delete()
        with self.assertRaises(ValidationError):
            AuditEvent.objects.filter(pk=self.event.pk).delete()

    def test_event_cannot_be_bulk_updated(self):
        with self.assertRaises(ValidationError):
            AuditEvent.objects.filter(pk=self.event.pk).update(action="tampered")

