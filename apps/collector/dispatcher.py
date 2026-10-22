import os
import subprocess
import sys

from django.conf import settings
from django.core.exceptions import ValidationError

from apps.auditlog.models import AuditEvent

from .models import CollectionJob


def dispatch_local_job(*, job, actor):
    job = CollectionJob.objects.select_related("tenant").get(pk=job.pk)
    if job.state != CollectionJob.State.QUEUED:
        raise ValidationError("Only a queued collection job can be started.")
    command = [sys.executable, str(settings.BASE_DIR / "manage.py"), "run_collector_agent", "--job", str(job.id)]
    options = {
        "cwd": str(settings.BASE_DIR),
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "shell": False,
        "close_fds": True,
    }
    if os.name == "nt":
        options["creationflags"] = subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS
    else:
        options["start_new_session"] = True
    try:
        subprocess.Popen(command, **options)
    except OSError as exc:
        raise ValidationError("The local collector worker could not be started. Check the application service account and Python environment.") from exc
    AuditEvent.objects.create(tenant=job.tenant, actor=actor, action="collector.job_dispatched", object_type="CollectionJob", object_id=str(job.id), metadata={"worker": "local_detached_v1"})
    return job
