from django.core.management.base import BaseCommand, CommandError

from apps.collector.agent import CollectorExecutionError, run_collection_job
from apps.collector.models import CollectionJob
from apps.collector.secretstore import CollectorSecretError


class Command(BaseCommand):
    help = "Claim and execute one authorized collection job on this on-prem collector host."

    def add_arguments(self, parser):
        parser.add_argument("--job", help="Specific queued collection-job UUID")
        parser.add_argument("--agent", help="Collector-agent UUID; claims its oldest queued job")

    def handle(self, *args, **options):
        if bool(options["job"]) == bool(options["agent"]):
            raise CommandError("Provide exactly one of --job or --agent.")
        if options["job"]:
            job = CollectionJob.objects.filter(pk=options["job"]).first()
        else:
            job = CollectionJob.objects.filter(agent_id=options["agent"], state=CollectionJob.State.QUEUED).order_by("created_at").first()
        if job is None:
            raise CommandError("No matching queued job was found.")
        try:
            result = run_collection_job(job.id)
        except (CollectorExecutionError, CollectorSecretError) as exc:
            code = getattr(exc, "code", "COLLECTOR_SECRET_ERROR")
            raise CommandError(f"Collection failed safely: {code}") from exc
        self.stdout.write(self.style.SUCCESS(f"Collection job finished with state {result.state}."))
