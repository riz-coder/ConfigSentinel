from django.contrib.auth import get_user_model
from django.db import DatabaseError, connection, transaction
from django.test import TransactionTestCase, skipUnlessDBFeature

from apps.auditlog.models import AuditEvent
from apps.regulatory.models import RegulatorySource
from apps.tenancy.models import Tenant
from apps.tenancy.rls import set_rls_context


class PostgreSQLBoundaryTests(TransactionTestCase):
    @skipUnlessDBFeature("supports_transactions")
    def test_forced_rls_hides_and_rejects_cross_tenant_rows(self):
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL-specific RLS test")
        alpha = Tenant.objects.create(name="RLS Alpha", slug="rls-alpha")
        beta = Tenant.objects.create(name="RLS Beta", slug="rls-beta")
        with transaction.atomic():
            set_rls_context(tenant_id=alpha.pk)
            source = RegulatorySource.objects.create(tenant=alpha, title="Alpha confidential source")
            set_rls_context(tenant_id=beta.pk)
            self.assertFalse(RegulatorySource.objects.filter(pk=source.pk).exists())
            with self.assertRaises(DatabaseError), transaction.atomic():
                RegulatorySource.objects.create(tenant=alpha, title="Blocked cross-tenant write")

    @skipUnlessDBFeature("supports_transactions")
    def test_database_trigger_rejects_raw_audit_mutation(self):
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL-specific audit trigger test")
        user = get_user_model().objects.create_user(username="db-guard")
        tenant = Tenant.objects.create(name="Audit Guard", slug="audit-guard")
        with transaction.atomic():
            set_rls_context(user_id=user.pk, tenant_id=tenant.pk)
            event = AuditEvent.objects.create(
                tenant=tenant, actor=user, action="guard.created", object_type="Guard", object_id="1"
            )
            with self.assertRaises(DatabaseError), transaction.atomic():
                with connection.cursor() as cursor:
                    cursor.execute("UPDATE auditlog_auditevent SET action = %s WHERE id = %s", ["tampered", event.pk])
            event.refresh_from_db()
            self.assertEqual(event.action, "guard.created")
