import getpass

from django.core.management.base import BaseCommand, CommandError

from apps.collector.models import CredentialReference
from apps.collector.secretstore import CollectorSecretError, LocalAgentSecretStore


class Command(BaseCommand):
    help = "Store a device credential in the agent-local encrypted store without printing the password."

    def add_arguments(self, parser):
        selector = parser.add_mutually_exclusive_group(required=True)
        selector.add_argument("--credential", help="Credential-reference UUID from the collector setup page")
        selector.add_argument("--reference", help="Opaque reference; intended for controlled automation")
        parser.add_argument("--username", required=True)

    def handle(self, *args, **options):
        reference = options["reference"]
        if options["credential"]:
            credential = CredentialReference.objects.filter(pk=options["credential"], is_active=True).only("secret_reference").first()
            if credential is None:
                raise CommandError("No active credential reference matched that ID.")
            reference = credential.secret_reference
        password = getpass.getpass("Read-only device password: ")
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            raise CommandError("Passwords did not match; nothing was stored.")
        try:
            LocalAgentSecretStore().store(reference=reference, username=options["username"], password=password)
        except CollectorSecretError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(self.style.SUCCESS("Credential stored on this collector host. The password was not printed or sent to the control plane."))
