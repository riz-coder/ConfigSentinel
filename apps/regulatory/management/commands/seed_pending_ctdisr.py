from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.regulatory.models import Regulation, RegulatorySource, RegulatoryVersion
from apps.tenancy.models import Tenant
from apps.tenancy.rls import set_rls_context


class Command(BaseCommand):
    help = "Create an explicitly unverified CTDISR workspace with 84 SOURCE_PENDING slots."

    def add_arguments(self, parser):
        parser.add_argument("tenant_slug")

    @transaction.atomic
    def handle(self, tenant_slug, **options):
        try:
            tenant = Tenant.objects.get(slug=tenant_slug)
        except Tenant.DoesNotExist as exc:
            raise CommandError(f"Tenant '{tenant_slug}' does not exist.") from exc
        set_rls_context(tenant_id=tenant.pk)

        source, _ = RegulatorySource.objects.get_or_create(
            tenant=tenant,
            title="PTA CTDISR 2025 — authenticated source required",
        )
        version, _ = RegulatoryVersion.objects.get_or_create(source=source, version_label="source-pending")
        created = 0
        for number in range(1, 85):
            _, was_created = Regulation.objects.get_or_create(version=version, number=number)
            created += int(was_created)
        self.stdout.write(self.style.SUCCESS(f"Created {created} slots; all 84 remain SOURCE_PENDING."))

