import base64
import hashlib
import re
import socket
import tempfile
import time
import uuid
from dataclasses import dataclass

import paramiko
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException, ReadTimeout

from apps.auditlog.models import AuditEvent
from apps.evidence.vault import LocalEncryptedObjectStore, VaultError

from .assessment import assess_cisco_job
from .models import CollectionJob, CommandExecution, Device, RawSnapshot, ScopeGrant
from .secretstore import CollectorSecretError, LocalAgentSecretStore


COLLECTOR_VERSION = "0.1.0"
UNSUPPORTED_MARKERS = ("% invalid input", "% incomplete command", "% ambiguous command", "invalid input detected")
DENIED_MARKERS = ("authorization failed", "not authorized", "permission denied", "command authorization failed")

CAPABILITY_RULES = {
    "lldp_topology": (r"(?:^|\n)(?:feature\s+lldp|lldp\s+run)\b", "LLDP_NOT_CONFIGURED"),
    "ospf_neighbors": (r"(?:^|\n)(?:feature\s+ospf|router\s+ospf)\b", "OSPF_NOT_CONFIGURED"),
    "bgp_summary": (r"(?:^|\n)(?:feature\s+bgp|router\s+bgp)\b", "BGP_NOT_CONFIGURED"),
    "aaa_servers": (r"(?:^|\n)(?:aaa\s+new-model|feature\s+tacacs\+|tacacs-server|radius-server)\b", "EXTERNAL_AAA_NOT_CONFIGURED"),
    "time_sync": (r"(?:^|\n)ntp\s+(?:server|peer)\b", "NTP_NOT_CONFIGURED"),
    "snmp_posture": (r"(?:^|\n)snmp-server\b", "SNMP_NOT_CONFIGURED"),
    "vrfs": (r"(?:^|\n)(?:vrf\s+(?:context|definition)|ip\s+vrf)\b", "VRF_NOT_CONFIGURED"),
    "vpc": (r"(?:^|\n)(?:feature\s+vpc|vpc\s+domain)\b", "VPC_NOT_CONFIGURED"),
    "hsrp": (r"(?:^|\n)(?:feature\s+hsrp|standby\s+\d+)\b", "HSRP_NOT_CONFIGURED"),
    "trunks": (r"(?:^|\n)\s*switchport\s+(?:mode\s+trunk|trunk\s+allowed|trunk\s+native)\b", "TRUNKING_NOT_CONFIGURED"),
    "ospf_interfaces": (r"(?:^|\n)(?:feature\s+ospf|router\s+ospf)\b", "OSPF_NOT_CONFIGURED"),
    "bgp_neighbors_detail": (r"(?:^|\n)(?:feature\s+bgp|router\s+bgp)\b", "BGP_NOT_CONFIGURED"),
}


class CollectorExecutionError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class PlatformIdentity:
    vendor: str
    platform: str
    model: str
    release: str


def parse_cisco_show_version(output):
    text = str(output or "")
    lowered = text.lower()
    if "cisco" not in lowered or ("ios" not in lowered and "nx-os" not in lowered and "nxos" not in lowered and "internetwork operating system" not in lowered):
        raise CollectorExecutionError("UNSUPPORTED_PLATFORM_OUTPUT")
    if "nx-os" in lowered or "nxos" in lowered:
        release_match = re.search(r"(?:NXOS|NX-OS)\s*:\s*version\s+(\S+)", text, re.I) or re.search(r"system:\s+version\s+(\S+)", text, re.I)
        model_match = re.search(r"^cisco\s+(N\S+).*Chassis", text, re.I | re.M) or re.search(r"^Hardware\s*\n\s+cisco\s+(\S+)", text, re.I | re.M)
        return PlatformIdentity(vendor=Device.Vendor.CISCO, platform="NX-OS", model=model_match.group(1) if model_match else "UNKNOWN", release=release_match.group(1) if release_match else "UNKNOWN")
    release_match = re.search(r"(?:Cisco IOS XE Software|Cisco IOS Software|Version)\s*(?:,|\()?[\w ()/-]*?Version\s+([^,\s]+)", text, re.I)
    if not release_match:
        release_match = re.search(r"\bVersion\s+([^,\s]+)", text, re.I)
    model_match = re.search(r"^Model Number\s*:\s*(\S+)", text, re.I | re.M)
    if not model_match:
        model_match = re.search(r"^cisco\s+(\S+)\s+.*(?:processor|bytes of memory)", text, re.I | re.M)
    platform = "IOS-XE" if "ios xe" in text.lower() else "IOS"
    return PlatformIdentity(vendor=Device.Vendor.CISCO, platform=platform, model=model_match.group(1) if model_match else "UNKNOWN", release=release_match.group(1) if release_match else "UNKNOWN")


def probe_ssh_host_key(host, port, timeout=10):
    sock = socket.create_connection((host, port), timeout=timeout)
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=timeout)
        key = transport.get_remote_server_key()
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode("ascii").rstrip("=")
        return fingerprint, key
    except Exception as exc:
        raise CollectorExecutionError("SSH_HOST_KEY_PREFLIGHT_FAILED") from exc
    finally:
        transport.close()
        sock.close()


class NetmikoSession:
    def __init__(self, *, device, credential, verified_host_key=None, timeout=10):
        nxos = device.platform.upper().replace(" ", "-") in {"NXOS", "NX-OS"}
        self._telnet = device.transport == Device.Transport.TELNET
        device_type = ("cisco_nxos_telnet" if self._telnet else "cisco_nxos") if nxos else ("cisco_ios_telnet" if self._telnet else "cisco_ios")
        arguments = {
            "device_type": device_type, "host": str(device.management_address), "port": device.ssh_port,
            "username": credential["username"], "password": credential["password"],
            "conn_timeout": timeout, "auth_timeout": timeout, "banner_timeout": timeout,
            "fast_cli": False,
        }
        self._known_hosts = None
        if device.transport == Device.Transport.SSH:
            if verified_host_key is None:
                raise CollectorExecutionError("SSH_HOST_KEY_NOT_VERIFIED")
            self._known_hosts = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False)
            host_label = str(device.management_address) if device.ssh_port == 22 else f"[{device.management_address}]:{device.ssh_port}"
            host_keys = paramiko.HostKeys(); host_keys.add(host_label, verified_host_key.get_name(), verified_host_key); host_keys.save(self._known_hosts.name)
            self._known_hosts.close()
            arguments.update({"ssh_strict": True, "alt_host_keys": True, "alt_key_file": self._known_hosts.name})
        try:
            self.connection = ConnectHandler(**arguments)
        except NetmikoAuthenticationException as exc:
            self.close(); raise CollectorExecutionError("AUTHENTICATION_FAILED") from exc
        except (NetmikoTimeoutException, OSError) as exc:
            self.close(); raise CollectorExecutionError("CONNECTION_TIMEOUT_OR_UNREACHABLE") from exc

    def send(self, command, timeout):
        if self._telnet:
            return self.connection.send_command_timing(command, read_timeout=max(45, timeout), last_read=3, strip_prompt=True, strip_command=True)
        return self.connection.send_command(command, read_timeout=timeout, strip_prompt=True, strip_command=True)

    def close(self):
        connection = getattr(self, "connection", None)
        if connection:
            try:
                connection.disconnect()
            except Exception:
                pass
        known_hosts = getattr(self, "_known_hosts", None)
        if known_hosts:
            try:
                import os
                os.remove(known_hosts.name)
            except OSError:
                pass


ALLOWED_TRANSITIONS = {
    CollectionJob.State.QUEUED: {CollectionJob.State.PREFLIGHT, CollectionJob.State.FAILED, CollectionJob.State.CANCELLED},
    CollectionJob.State.PREFLIGHT: {CollectionJob.State.CAPABILITY_PROBE, CollectionJob.State.FAILED, CollectionJob.State.TIMED_OUT},
    CollectionJob.State.CAPABILITY_PROBE: {CollectionJob.State.COLLECTING, CollectionJob.State.FAILED, CollectionJob.State.PARTIAL, CollectionJob.State.TIMED_OUT},
    CollectionJob.State.COLLECTING: {CollectionJob.State.PARSING, CollectionJob.State.PARTIAL, CollectionJob.State.FAILED, CollectionJob.State.TIMED_OUT},
    CollectionJob.State.PARSING: {CollectionJob.State.ASSESSING, CollectionJob.State.PARTIAL, CollectionJob.State.FAILED},
    CollectionJob.State.ASSESSING: {CollectionJob.State.COMPLETE, CollectionJob.State.PARTIAL, CollectionJob.State.FAILED},
}


def _transition(job, target, *, failure_reason="", technical_result=None, finished=False):
    if target not in ALLOWED_TRANSITIONS.get(job.state, set()):
        raise CollectorExecutionError("INVALID_JOB_STATE_TRANSITION")
    job.state = target
    if failure_reason:
        job.failure_reason = failure_reason[:255]
    if technical_result:
        job.technical_result = technical_result
    if finished:
        job.finished_at = timezone.now()
    job.save(update_fields=["state", "failure_reason", "technical_result", "finished_at"])


def _store_output(*, job, execution, output, evidence_store):
    encoded = output.encode("utf-8", errors="replace")
    snapshot_id = uuid.uuid4()
    envelope = evidence_store.encrypt_and_store(tenant_id=job.tenant_id, artifact_id=snapshot_id, plaintext=encoded)
    RawSnapshot.objects.create(id=snapshot_id, tenant=job.tenant, execution=execution, **envelope.__dict__)
    execution.output_size_bytes = len(encoded)
    execution.output_sha256 = envelope.plaintext_sha256


def _execute_command(*, job, command, session, deadline, remaining_bytes, evidence_store):
    execution = CommandExecution.objects.create(tenant=job.tenant, job=job, command=command, started_at=timezone.now())
    try:
        remaining_seconds = max(1, int(deadline - time.monotonic()))
        if remaining_seconds <= 1:
            execution.state, execution.reason = CommandExecution.State.TIMEOUT, "JOB_RUNTIME_BUDGET_EXHAUSTED"
            return execution, 0, ""
        output = session.send(command.command_text, min(30, remaining_seconds))
        encoded = output.encode("utf-8", errors="replace")
        lowered = output.lower()
        if any(marker in lowered for marker in DENIED_MARKERS):
            execution.state, execution.reason = CommandExecution.State.DENIED, "COMMAND_AUTHORIZATION_DENIED"
        elif any(marker in lowered for marker in UNSUPPORTED_MARKERS):
            execution.state, execution.reason = CommandExecution.State.UNSUPPORTED, "COMMAND_UNSUPPORTED"
        elif len(encoded) > remaining_bytes:
            output = encoded[:remaining_bytes].decode("utf-8", errors="ignore")
            execution.state, execution.reason = CommandExecution.State.TRUNCATED, "OUTPUT_BUDGET_EXHAUSTED"
            _store_output(job=job, execution=execution, output=output, evidence_store=evidence_store)
        else:
            execution.state = CommandExecution.State.SUCCEEDED
            _store_output(job=job, execution=execution, output=output, evidence_store=evidence_store)
        return execution, execution.output_size_bytes, output
    except (NetmikoTimeoutException, ReadTimeout):
        execution.state, execution.reason = CommandExecution.State.TIMEOUT, "COMMAND_TIMEOUT"
        return execution, 0, ""
    except (OSError, VaultError):
        execution.state, execution.reason = CommandExecution.State.ERROR, "COMMAND_OR_STORAGE_ERROR"
        return execution, 0, ""
    finally:
        execution.finished_at = timezone.now()
        execution.save(update_fields=["state", "reason", "output_size_bytes", "output_sha256", "finished_at"])


def _record_not_applicable(*, job, command, reason):
    now = timezone.now()
    return CommandExecution.objects.create(tenant=job.tenant, job=job, command=command, state=CommandExecution.State.NOT_APPLICABLE, reason=reason, started_at=now, finished_at=now)


def _capability_decision(command, running_config):
    rule = CAPABILITY_RULES.get(command.key)
    if rule is None or running_config is None:
        return True, ""
    pattern, reason = rule
    return (True, "") if re.search(pattern, running_config, re.I) else (False, reason)


@transaction.atomic
def _claim_job(job_id):
    job = CollectionJob.objects.select_for_update().select_related("device", "agent", "scope_grant__credential", "command_profile", "tenant").get(pk=job_id)
    if job.state != CollectionJob.State.QUEUED:
        raise CollectorExecutionError("JOB_NOT_QUEUED")
    now = timezone.now()
    if job.agent.status != job.agent.Status.ACTIVE or job.scope_grant.status != ScopeGrant.Status.APPROVED or not (job.scope_grant.valid_from <= now < job.scope_grant.valid_until):
        raise CollectorExecutionError("AUTHORIZATION_NOT_CURRENT")
    if not job.scope_grant.credential.is_active:
        raise CollectorExecutionError("CREDENTIAL_REFERENCE_INACTIVE")
    if job.command_profile.status != job.command_profile.Status.APPROVED or not job.command_profile.approval_reference:
        raise CollectorExecutionError("COMMAND_PROFILE_NOT_APPROVED")
    job.state = CollectionJob.State.PREFLIGHT
    job.claimed_at = now; job.started_at = now; job.collector_version = COLLECTOR_VERSION
    job.save(update_fields=["state", "claimed_at", "started_at", "collector_version"])
    return job


def run_collection_job(job_id, *, secret_store=None, evidence_store=None, connector_factory=NetmikoSession, host_key_probe=probe_ssh_host_key):
    secret_store = secret_store or LocalAgentSecretStore()
    evidence_store = evidence_store or LocalEncryptedObjectStore()
    session = None
    try:
        job = _claim_job(job_id)
        device, credential_ref = job.device, job.scope_grant.credential
        credential = secret_store.retrieve(credential_ref.secret_reference)
        verified_key = None
        if device.transport == Device.Transport.SSH:
            observed, verified_key = host_key_probe(str(device.management_address), device.ssh_port)
            if observed != device.pinned_host_key_sha256 or observed != job.observed_host_key_sha256:
                raise CollectorExecutionError("SSH_HOST_KEY_MISMATCH")
        elif not device.telnet_approved_at:
            raise CollectorExecutionError("TELNET_EXCEPTION_NOT_APPROVED")
        deadline = time.monotonic() + job.max_runtime_seconds
        session = connector_factory(device=device, credential=credential, verified_host_key=verified_key, timeout=min(15, job.max_runtime_seconds))
        _transition(job, CollectionJob.State.CAPABILITY_PROBE)
        commands = list(job.command_profile.commands.order_by("sequence"))
        if len(commands) > job.max_commands:
            raise CollectorExecutionError("COMMAND_BUDGET_EXCEEDED")
        discovery = next((item for item in commands if item.key == "platform_version"), None)
        if discovery is None:
            raise CollectorExecutionError("DISCOVERY_COMMAND_MISSING")
        execution, used, output = _execute_command(job=job, command=discovery, session=session, deadline=deadline, remaining_bytes=job.max_output_bytes, evidence_store=evidence_store)
        if execution.state != CommandExecution.State.SUCCEEDED:
            raise CollectorExecutionError("PLATFORM_DISCOVERY_FAILED")
        identity = parse_cisco_show_version(output)
        expected_platform = device.platform.upper().replace("_", "-").replace(" ", "-")
        if device.vendor != identity.vendor or (identity.platform == "NX-OS" and expected_platform not in {"NXOS", "NX-OS"}) or (identity.platform in {"IOS", "IOS-XE"} and expected_platform not in {identity.platform, "IOS-IOS-XE"}):
            raise CollectorExecutionError("DISCOVERED_PLATFORM_MISMATCH")
        job.discovered_vendor, job.discovered_platform, job.discovered_model, job.discovered_release = identity.vendor, identity.platform, identity.model, identity.release
        job.save(update_fields=["discovered_vendor", "discovered_platform", "discovered_model", "discovered_release"])
        _transition(job, CollectionJob.State.COLLECTING)
        remaining = job.max_output_bytes - used
        non_success = False
        running_config = None
        config_command = next((item for item in commands if item.key == "running_config"), None)
        if config_command is not None:
            config_result, config_used, config_output = _execute_command(job=job, command=config_command, session=session, deadline=deadline, remaining_bytes=max(0, remaining), evidence_store=evidence_store)
            remaining -= config_used
            if config_result.state == CommandExecution.State.SUCCEEDED:
                running_config = config_output
            else:
                non_success = True
        for command in commands:
            if command.pk == discovery.pk or (config_command and command.pk == config_command.pk):
                continue
            if time.monotonic() >= deadline:
                raise CollectorExecutionError("JOB_RUNTIME_BUDGET_EXHAUSTED")
            should_run, skip_reason = _capability_decision(command, running_config)
            if not should_run:
                _record_not_applicable(job=job, command=command, reason=skip_reason)
                continue
            result, used, _ = _execute_command(job=job, command=command, session=session, deadline=deadline, remaining_bytes=max(0, remaining), evidence_store=evidence_store)
            remaining -= used
            non_success = non_success or result.state != CommandExecution.State.SUCCEEDED
            if remaining <= 0:
                non_success = True; break
        _transition(job, CollectionJob.State.PARSING)
        _transition(job, CollectionJob.State.ASSESSING)
        assess_cisco_job(job.id, evidence_store=evidence_store)
        _transition(job, CollectionJob.State.PARTIAL if non_success else CollectionJob.State.COMPLETE, finished=True)
        AuditEvent.objects.create(tenant=job.tenant, actor=job.requested_by, action="collector.job_finished", object_type="CollectionJob", object_id=str(job.id), metadata={"state": job.state, "snapshot_count": job.command_executions.filter(snapshot__isnull=False).count()})
        return job
    except (CollectorExecutionError, CollectorSecretError, ValidationError) as exc:
        try:
            job = CollectionJob.objects.get(pk=job_id)
            if job.state in ALLOWED_TRANSITIONS and CollectionJob.State.FAILED in ALLOWED_TRANSITIONS[job.state]:
                _transition(job, CollectionJob.State.FAILED, failure_reason=getattr(exc, "code", "COLLECTOR_VALIDATION_FAILED"), technical_result=CollectionJob.Result.ERROR, finished=True)
                AuditEvent.objects.create(tenant=job.tenant, actor=job.requested_by, action="collector.job_failed", object_type="CollectionJob", object_id=str(job.id), metadata={"reason": job.failure_reason})
        except CollectionJob.DoesNotExist:
            pass
        raise
    except Exception:
        try:
            job = CollectionJob.objects.get(pk=job_id)
            if job.state in ALLOWED_TRANSITIONS and CollectionJob.State.FAILED in ALLOWED_TRANSITIONS[job.state]:
                _transition(job, CollectionJob.State.FAILED, failure_reason="COLLECTOR_INTERNAL_ERROR", technical_result=CollectionJob.Result.ERROR, finished=True)
                AuditEvent.objects.create(tenant=job.tenant, actor=job.requested_by, action="collector.job_failed", object_type="CollectionJob", object_id=str(job.id), metadata={"reason": "COLLECTOR_INTERNAL_ERROR"})
        except CollectionJob.DoesNotExist:
            pass
        raise
    finally:
        if session:
            session.close()
