from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from apps.auditlog.models import AuditEvent
from apps.evidence.models import CustodyEvent, EvidenceArtifact, EvidenceStatus
from apps.tenancy.models import Tenant
from apps.tenancy.rls import set_rls_context


class Command(BaseCommand):
    help = "Mark expired accepted evidence as STALE without treating it as a pass."

    def handle(self, **options):
        total = 0
        for tenant_id in Tenant.objects.filter(is_active=True).values_list("id", flat=True):
            with transaction.atomic():
                set_rls_context(tenant_id=tenant_id)
                artifacts = list(EvidenceArtifact.objects.filter(
                    tenant_id=tenant_id, status=EvidenceStatus.ACCEPTED,
                    expires_at__isnull=False, expires_at__lte=timezone.now(),
                ))
                for artifact in artifacts:
                    artifact.status = EvidenceStatus.STALE
                    artifact.save(update_fields=["status"])
                    CustodyEvent.objects.create(artifact=artifact, actor=None, kind=CustodyEvent.Kind.STALE_MARKED, metadata={})
                    AuditEvent.objects.create(
                        tenant_id=tenant_id, actor=None, action="evidence.marked_stale",
                        object_type="EvidenceArtifact", object_id=str(artifact.id), metadata={},
                    )
                total += len(artifacts)
        self.stdout.write(self.style.SUCCESS(f"Marked {total} evidence artifact(s) STALE."))
