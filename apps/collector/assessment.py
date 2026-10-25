import re

from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction

from apps.auditlog.models import AuditEvent
from apps.evidence.vault import EvidenceIntegrityError, LocalEncryptedObjectStore

from .models import CollectionJob, CommandExecution, DeviceAssessment, TechnicalFinding


RULE_PACK = "cisco-network-deep-assessment"
RULE_PACK_VERSION = 4


def _has_line(text, pattern):
    return re.search(pattern, text, re.I | re.M) is not None


def _finding(rule_id, category, severity, result, title, detail, remediation="", evidence=None):
    return {"rule_id": rule_id, "category": category, "severity": severity, "result": result, "title": title, "detail": detail, "remediation": remediation, "evidence_execution": evidence}


def _config_rules(config, execution):
    if config is None:
        return [_finding("CISCO.CONFIG.READABLE", "CONFIGURATION", "HIGH", "UNKNOWN", "Running configuration unavailable", "The approved running-configuration command did not produce readable evidence.", "Restore read-only privilege and collect again.")]
    rules = [_finding("CISCO.CONFIG.READABLE", "CONFIGURATION", "INFO", "PASS", "Running configuration captured", "The encrypted running-configuration snapshot passed integrity verification.", evidence=execution)]
    aaa = _has_line(config, r"^aaa new-model\s*$")
    rules.append(_finding("CISCO.AAA.NEW_MODEL", "ACCESS_CONTROL", "HIGH", "PASS" if aaa else "FAIL", "Central AAA framework", "AAA new-model is configured." if aaa else "AAA new-model was not found in the running configuration.", "Configure reviewed AAA with tested fallback access.", execution))
    enable_password = _has_line(config, r"^enable password\b")
    enable_secret = _has_line(config, r"^enable secret\b")
    result = "FAIL" if enable_password else ("PASS" if enable_secret else "UNKNOWN")
    rules.append(_finding("CISCO.AUTH.ENABLE_SECRET", "ACCESS_CONTROL", "HIGH", result, "Privileged access secret", "Legacy enable password is configured." if enable_password else ("Enable secret is configured." if enable_secret else "No enable secret/password line was observed; external AAA or omitted privileges may apply."), "Remove legacy enable password and use an approved strong secret/AAA design.", execution))
    ssh_v2 = _has_line(config, r"^ip ssh version 2\s*$")
    rules.append(_finding("CISCO.MGMT.SSH_V2", "MANAGEMENT", "HIGH", "PASS" if ssh_v2 else "FAIL", "SSH protocol version", "SSH version 2 is explicitly configured." if ssh_v2 else "Explicit SSH version 2 configuration was not found.", "Enable SSH version 2 after validating management compatibility.", execution))
    telnet_lines = re.findall(r"^\s*transport input\s+(.+)$", config, re.I | re.M)
    telnet_allowed = any("telnet" in line.lower().split() or "all" in line.lower().split() for line in telnet_lines)
    rules.append(_finding("CISCO.MGMT.VTY_TELNET", "MANAGEMENT", "HIGH", "FAIL" if telnet_allowed else ("PASS" if telnet_lines else "UNKNOWN"), "VTY management transport", "Telnet is allowed on at least one VTY transport line." if telnet_allowed else ("Observed VTY transport lines do not allow Telnet." if telnet_lines else "No VTY transport input line was observed."), "Restrict VTY access to SSH after an approved migration.", execution))
    http_enabled = _has_line(config, r"^ip http server\s*$")
    rules.append(_finding("CISCO.MGMT.HTTP_SERVER", "MANAGEMENT", "MEDIUM", "FAIL" if http_enabled else "PASS", "Plain HTTP management service", "Plain HTTP server is enabled." if http_enabled else "Plain HTTP server enablement was not found.", "Disable plain HTTP; use reviewed HTTPS or remove the service.", execution))
    logging_host = _has_line(config, r"^(?:logging host|logging)\s+(?:host\s+)?(?:\d{1,3}\.){3}\d{1,3}\b")
    rules.append(_finding("CISCO.LOGGING.REMOTE", "LOGGING", "MEDIUM", "PASS" if logging_host else "FAIL", "Remote logging destination", "A remote logging destination is configured." if logging_host else "No remote logging destination was identified.", "Configure approved, monitored remote logging with protected transport where supported.", execution))
    ntp_configured = _has_line(config, r"^ntp (?:server|peer)\b")
    rules.append(_finding("CISCO.TIME.NTP_CONFIG", "TIME", "MEDIUM", "PASS" if ntp_configured else "FAIL", "NTP configuration", "An NTP server or peer is configured." if ntp_configured else "No NTP server or peer was found.", "Configure approved redundant time sources and authentication where supported.", execution))
    snmp_community = _has_line(config, r"^snmp-server community\b")
    snmp_v3 = _has_line(config, r"^snmp-server user\b.*\bv3\b")
    snmp_result = "FAIL" if snmp_community else ("PASS" if snmp_v3 else "NOT_APPLICABLE")
    rules.append(_finding("CISCO.SNMP.VERSION", "MONITORING", "HIGH", snmp_result, "SNMP credential model", "SNMP community-string configuration was found." if snmp_community else ("SNMPv3 user configuration was found." if snmp_v3 else "No SNMP configuration was identified."), "Replace community-based SNMP with reviewed SNMPv3 authentication and privacy.", execution))
    return rules


def _ios_interface_blocks(config):
    blocks = {}
    current = None
    for raw_line in config.splitlines():
        match = re.match(r"^interface\s+(\S+)", raw_line, re.I)
        if match:
            current = match.group(1)
            blocks[current] = []
        elif current and (raw_line.startswith(" ") or raw_line.startswith("\t")):
            blocks[current].append(raw_line.strip())
        elif raw_line and not raw_line.startswith((" ", "!")):
            current = None
    return blocks


def _ios_hardening_rules(config, execution):
    rules = []
    blocks = _ios_interface_blocks(config)
    vty_blocks = [lines for name, lines in blocks.items() if name.lower().startswith("vty")]
    # IOS line sections are not interface sections, so parse them separately.
    vty_sections = re.findall(r"^line vty[^\n]*\n((?:[ \t]+[^\n]*\n?)*)", config, re.I | re.M)
    vty_acl_missing = [section for section in vty_sections if not re.search(r"^\s*access-class\s+\S+\s+in\b", section, re.I | re.M)]
    vty_result = "UNKNOWN" if not vty_sections else ("FAIL" if vty_acl_missing else "PASS")
    rules.append(_finding("CISCO.IOS.VTY.ACCESS_CLASS", "MANAGEMENT", "HIGH", vty_result, "VTY source restriction", "No VTY line sections were parsed." if not vty_sections else (f"{len(vty_acl_missing)} of {len(vty_sections)} VTY section(s) lack an inbound access-class." if vty_acl_missing else "Every parsed VTY section has an inbound access-class."), "Apply a reviewed management-source ACL to every active VTY range.", execution))

    aaa_enabled = _has_line(config, r"^aaa new-model\s*$")
    exec_auth = _has_line(config, r"^aaa authorization exec\s+")
    aaa_result = "NOT_APPLICABLE" if not aaa_enabled else ("PASS" if exec_auth else "FAIL")
    rules.append(_finding("CISCO.IOS.AAA.EXEC_AUTHORIZATION", "ACCESS_CONTROL", "HIGH", aaa_result, "AAA EXEC authorization", "AAA is not configured, so this dependent check is not applicable." if not aaa_enabled else ("AAA EXEC authorization is configured." if exec_auth else "AAA is enabled but no EXEC authorization method list was found."), "Configure a tested EXEC authorization method list with an approved fallback.", execution))

    credential_lines = re.findall(r"^(?:username\s+\S+.*?\s+(?:password|secret)|enable\s+(?:password|secret))\s+(\d+)\s+", config, re.I | re.M)
    weak_types = sorted({value for value in credential_lines if value in {"0", "4", "5", "7"}})
    strong_types = sorted({value for value in credential_lines if value in {"6", "8", "9"}})
    secret_result = "FAIL" if weak_types else ("PASS" if strong_types else "UNKNOWN")
    secret_detail = f"Weak Cisco credential type(s) observed: {', '.join(weak_types)}." if weak_types else (f"Only reviewed stronger credential type(s) were observed: {', '.join(strong_types)}." if strong_types else "No typed local username/enable credential could be classified; external AAA or omitted privilege may apply.")
    rules.append(_finding("CISCO.IOS.CREDENTIAL.STORAGE", "ACCESS_CONTROL", "HIGH", secret_result, "Local credential storage", secret_detail, "Replace type 0/4/5/7 local credentials with platform-supported type 8/9 secrets where compatible.", execution))

    trunk_blocks = {name: lines for name, lines in blocks.items() if any(re.match(r"switchport mode trunk\b", line, re.I) for line in lines)}
    native_vlan_1 = []
    unrestricted = []
    for name, lines in trunk_blocks.items():
        native = next((re.match(r"switchport trunk native vlan\s+(\d+)", line, re.I) for line in lines if re.match(r"switchport trunk native vlan\s+(\d+)", line, re.I)), None)
        if native is None or native.group(1) == "1":
            native_vlan_1.append(name)
        allowed = [line for line in lines if re.match(r"switchport trunk allowed vlan\b", line, re.I)]
        if not allowed or any(re.search(r"\ball\b", line, re.I) for line in allowed):
            unrestricted.append(name)
    native_result = "NOT_APPLICABLE" if not trunk_blocks else ("WARNING" if native_vlan_1 else "PASS")
    rules.append(_finding("CISCO.IOS.TRUNK.NATIVE_VLAN", "LAYER2", "MEDIUM", native_result, "Trunk native VLAN", "No configured trunk interfaces were parsed." if not trunk_blocks else (f"{len(native_vlan_1)} of {len(trunk_blocks)} configured trunk(s) use or implicitly default to native VLAN 1." if native_vlan_1 else "Every configured trunk has an explicit non-default native VLAN."), "Assign an unused reviewed native VLAN consistently at both ends after impact validation.", execution))
    allowed_result = "NOT_APPLICABLE" if not trunk_blocks else ("WARNING" if unrestricted else "PASS")
    rules.append(_finding("CISCO.IOS.TRUNK.ALLOWED_VLANS", "LAYER2", "MEDIUM", allowed_result, "Trunk VLAN allow-list", "No configured trunk interfaces were parsed." if not trunk_blocks else (f"{len(unrestricted)} of {len(trunk_blocks)} configured trunk(s) do not have a bounded VLAN allow-list." if unrestricted else "Every configured trunk has an explicit VLAN allow-list."), "Permit only VLANs required on each trunk after path and redundancy validation.", execution))

    portfast_access = {name: lines for name, lines in blocks.items() if any(re.match(r"switchport mode access\b", line, re.I) for line in lines) and any(re.match(r"spanning-tree portfast\b", line, re.I) for line in lines)}
    global_guard = _has_line(config, r"^spanning-tree portfast bpduguard default\s*$")
    unguarded = [name for name, lines in portfast_access.items() if not global_guard and not any(re.match(r"spanning-tree bpduguard enable\b", line, re.I) for line in lines)]
    guard_result = "NOT_APPLICABLE" if not portfast_access else ("FAIL" if unguarded else "PASS")
    rules.append(_finding("CISCO.IOS.STP.PORTFAST_BPDU_GUARD", "LAYER2", "HIGH", guard_result, "PortFast BPDU Guard", "No explicit PortFast access interfaces were parsed." if not portfast_access else (f"{len(unguarded)} of {len(portfast_access)} PortFast access interface(s) lack effective BPDU Guard." if unguarded else "All parsed PortFast access interfaces are protected by global or interface BPDU Guard."), "Enable reviewed BPDU Guard protection on host-facing PortFast access ports.", execution))
    facts = {"configured_interfaces": len(blocks), "configured_trunks": len(trunk_blocks), "trunks_native_vlan_1": len(native_vlan_1), "trunks_unrestricted": len(unrestricted), "portfast_access_ports": len(portfast_access), "portfast_without_bpduguard": len(unguarded), "vty_sections": len(vty_sections), "vty_without_access_class": len(vty_acl_missing), "weak_credential_types": weak_types}
    return rules, facts


def _output_rule(outputs, executions, key, rule_id, category, severity, title, good_pattern, pass_detail, fail_detail, remediation):
    item = outputs.get(key)
    if item is None:
        execution = executions.get(key)
        if execution and execution.state == CommandExecution.State.NOT_APPLICABLE:
            return _finding(rule_id, category, severity, "NOT_APPLICABLE", title, f"Capability planner skipped this command: {execution.reason}.", "", execution)
        return _finding(rule_id, category, severity, "UNKNOWN", title, "Required command evidence was unavailable or unreadable.", "Restore command access and collect again.")
    execution, text = item
    passed = _has_line(text, good_pattern)
    return _finding(rule_id, category, severity, "PASS" if passed else "WARNING", title, pass_detail if passed else fail_detail, remediation, execution)


def _deep_operational_rules(outputs, executions):
    findings = []
    facts = {
        "vpc_configured": None,
        "interfaces_with_nonzero_error_counters": None,
        "interfaces_with_errors": [],
        "stp_inconsistent_ports_clear": None,
        "hsrp_groups": None,
        "hsrp_ready_groups": None,
        "hsrp_degraded_groups": None,
    }
    vpc = outputs.get("vpc")
    if vpc:
        execution, text = vpc
        healthy = all(marker in text.lower() for marker in ("peer adjacency formed ok", "peer is alive", "configuration consistency status: success"))
        findings.append(_finding("CISCO.VPC.HEALTH", "RESILIENCE", "HIGH", "PASS" if healthy else "WARNING", "vPC peer health", "vPC peer adjacency, keepalive and consistency are healthy." if healthy else "vPC is configured, but the collected summary did not demonstrate healthy adjacency, keepalive and consistency together.", "Review peer-link, keepalive and consistency output before making a change.", execution))
        facts["vpc_configured"] = True
    elif executions.get("vpc"):
        facts["vpc_configured"] = False

    errors = outputs.get("interface_errors")
    if errors:
        execution, text = errors
        rows = []
        for line in text.splitlines():
            if not re.match(r"^\s*(?:Eth|Gi|Fa|Te|Hu|Twe|Fo|mgmt|Po|Port-channel)\S*\s+", line, re.I):
                continue
            values = [int(value) for value in re.findall(r"(?<![\w/.-])\d+(?![\w/.-])", line)]
            if any(value > 0 for value in values):
                rows.append(line.split()[0])
        findings.append(_finding("CISCO.INTERFACE.ERROR_COUNTERS", "OPERATIONS", "MEDIUM", "WARNING" if rows else "PASS", "Interface error counters", f"Non-zero error/discard counters were observed on {len(rows)} interface(s)." if rows else "No non-zero values were observed in the collected interface error-counter table.", "Establish a time-based baseline and investigate affected links; cumulative counters alone do not prove a current fault.", execution))
        facts["interfaces_with_nonzero_error_counters"] = len(rows)
        facts["interfaces_with_errors"] = list(dict.fromkeys(rows))[:50]

    stp = outputs.get("stp_inconsistent")
    if stp:
        execution, text = stp
        clear = bool(re.search(r"(?:number of inconsistent ports.*?0|no inconsistent ports|none)", text, re.I))
        findings.append(_finding("CISCO.STP.INCONSISTENT_PORTS", "LAYER2", "HIGH", "PASS" if clear else "WARNING", "Spanning-tree inconsistent ports", "The command reported no inconsistent spanning-tree ports." if clear else "The output did not establish that the inconsistent-port count is zero.", "Review root/loop/PVID/type inconsistency details and validate the Layer-2 design.", execution))
        facts["stp_inconsistent_ports_clear"] = clear

    hsrp = outputs.get("hsrp")
    if hsrp:
        execution, text = hsrp
        rows = [line for line in text.splitlines() if re.match(r"^\s*(?:Vlan|Eth|Gi|Fa|Te|Po)\S*\s+\d+\s+", line, re.I)]
        active_or_standby = sum(1 for line in rows if re.search(r"\b(?:Active|Standby)\b", line, re.I))
        degraded = sum(1 for line in rows if re.search(r"\b(?:Init|Learn|Listen|Speak)\b", line, re.I))
        facts.update({"hsrp_groups": len(rows), "hsrp_ready_groups": active_or_standby, "hsrp_degraded_groups": degraded})
        result = "UNKNOWN" if not rows else ("WARNING" if degraded else "PASS")
        findings.append(_finding("CISCO.HSRP.HEALTH", "RESILIENCE", "HIGH", result, "HSRP group health", f"Parsed {len(rows)} group(s); {active_or_standby} are Active/Standby and {degraded} are in transitional states." if rows else "HSRP output was collected but no group rows could be parsed.", "Investigate HSRP groups in Init, Learn, Listen or Speak state.", execution))

    for key, fact, label in (("vrfs", "vrf_evidence_collected", "VRF inventory"), ("trunks", "trunk_evidence_collected", "Trunk inventory"), ("ospf_interfaces", "ospf_interface_evidence_collected", "OSPF interfaces"), ("bgp_neighbors_detail", "bgp_neighbor_evidence_collected", "BGP neighbors")):
        if key in outputs:
            facts[fact] = True
            execution, _ = outputs[key]
            findings.append(_finding(f"CISCO.DEEP.{key.upper()}", "INVENTORY", "INFO", "PASS", label, f"Readable {label.lower()} evidence was collected; this records visibility, not configuration correctness.", "", execution))
        elif executions.get(key) and executions[key].state == CommandExecution.State.NOT_APPLICABLE:
            facts[fact] = False
    return findings, facts


def _structured_device_rules(outputs, executions):
    findings = []
    facts = {
        "interfaces": {"recognized": None, "connected": None, "not_connected": None, "disabled": None, "error_disabled": None},
        "layer2": {"vlan_count": None, "trunk_count": None, "port_channel_count": None, "port_channels_not_up": None},
        "routing": {"ospf_neighbors": None, "ospf_full": None, "bgp_neighbors": None, "bgp_established": None},
        "topology": {"cdp_neighbors": None, "lldp_neighbors": None},
    }

    status = outputs.get("interfaces_status")
    if status:
        execution, text = status
        states = {"connected": 0, "not_connected": 0, "disabled": 0, "error_disabled": 0}
        recognized = 0
        for line in text.splitlines():
            if not re.match(r"^\s*(?:Eth|Gi|Fa|Te|Hu|Twe|Fo|mgmt|Po)\S+\s+", line, re.I):
                continue
            recognized += 1
            lower = line.lower()
            if re.search(r"\berr-?disabled\b", lower):
                states["error_disabled"] += 1
            elif re.search(r"\bnotconnect(?:ed)?\b", lower):
                states["not_connected"] += 1
            elif re.search(r"\b(?:disabled|administratively down)\b", lower):
                states["disabled"] += 1
            elif re.search(r"\bconnected\b", lower):
                states["connected"] += 1
        facts["interfaces"] = {"recognized": recognized, **states}
        result = "UNKNOWN" if not recognized else ("WARNING" if states["error_disabled"] else "PASS")
        detail = "Interface-status output format was not recognized." if not recognized else f"Parsed {recognized} interfaces: {states['connected']} connected, {states['not_connected']} not connected, {states['disabled']} disabled and {states['error_disabled']} error-disabled."
        findings.append(_finding("CISCO.INTERFACE.STATUS", "OPERATIONS", "HIGH", result, "Interface operational summary", detail, "Investigate error-disabled interfaces and validate intentional shutdowns." if states["error_disabled"] else "", execution))

    vlans = outputs.get("vlans")
    if vlans:
        execution, text = vlans
        vlan_ids = {match.group(1) for line in text.splitlines() if (match := re.match(r"^\s*(\d{1,4})\s+\S+", line)) and 1 <= int(match.group(1)) <= 4094}
        facts["layer2"]["vlan_count"] = len(vlan_ids)
        findings.append(_finding("CISCO.VLAN.INVENTORY", "LAYER2", "INFO", "PASS" if vlan_ids else "UNKNOWN", "VLAN inventory", f"Parsed {len(vlan_ids)} VLAN entries." if vlan_ids else "No VLAN rows could be parsed from the collected output.", "", execution))

    trunks = outputs.get("trunks")
    if trunks:
        execution, text = trunks
        trunk_ports = {match.group(1) for line in text.splitlines() if (match := re.match(r"^\s*((?:Eth|Gi|Fa|Te|Hu|Twe|Fo|Po)\S*)\s+.+\b(?:trunking|on)\b", line, re.I))}
        facts["layer2"]["trunk_count"] = len(trunk_ports)
        findings.append(_finding("CISCO.TRUNK.INVENTORY", "LAYER2", "INFO", "PASS" if trunk_ports else "UNKNOWN", "Operational trunks", f"Parsed {len(trunk_ports)} operational trunk interface(s)." if trunk_ports else "Trunk output was collected but no operational trunk row could be parsed.", "Validate expected trunk state and allowed/native VLAN design.", execution))

    channels = outputs.get("etherchannel")
    if channels:
        execution, text = channels
        groups = re.findall(r"^\s*\d+\s+(Po\d+)\(([^)]+)\)", text, re.I | re.M)
        unhealthy = [name for name, flags in groups if "U" not in flags.upper()]
        facts["layer2"].update({"port_channel_count": len(groups), "port_channels_not_up": len(unhealthy)})
        result = "UNKNOWN" if not groups else ("WARNING" if unhealthy else "PASS")
        findings.append(_finding("CISCO.PORT_CHANNEL.HEALTH", "LAYER2", "HIGH", result, "Port-channel health", f"Parsed {len(groups)} port-channel(s); {len(unhealthy)} did not carry an up/in-use flag." if groups else "No port-channel summary rows could be parsed.", "Review member consistency, suspension and protocol state for unhealthy bundles.", execution))

    for key, label in (("cdp_topology", "CDP"), ("lldp_topology", "LLDP")):
        item = outputs.get(key)
        if not item:
            continue
        execution, text = item
        if label == "CDP":
            count = len(re.findall(r"^Device ID\s*:", text, re.I | re.M))
        else:
            count = max(len(re.findall(r"^System Name\s*:", text, re.I | re.M)), len(re.findall(r"^Chassis id\s*:", text, re.I | re.M)))
        facts["topology"][f"{label.lower()}_neighbors"] = count
        findings.append(_finding(f"CISCO.TOPOLOGY.{label}", "TOPOLOGY", "INFO", "PASS" if count else "UNKNOWN", f"{label} neighbor visibility", f"Parsed {count} neighbor record(s)." if count else f"{label} output was collected but no neighbor records could be parsed.", "Validate discovery protocol scope and disabled links where topology is expected.", execution))

    ospf = outputs.get("ospf_neighbors")
    if ospf:
        execution, text = ospf
        rows = [line for line in text.splitlines() if re.match(r"^\s*\d{1,3}(?:\.\d{1,3}){3}\s+", line)]
        full = sum(1 for line in rows if re.search(r"\bFULL(?:/|-|\s)", line, re.I))
        facts["routing"].update({"ospf_neighbors": len(rows), "ospf_full": full})
        result = "UNKNOWN" if not rows else ("WARNING" if full != len(rows) else "PASS")
        findings.append(_finding("CISCO.OSPF.NEIGHBORS", "ROUTING", "HIGH", result, "OSPF adjacency health", f"Parsed {len(rows)} OSPF neighbor(s); {full} are FULL." if rows else "No OSPF neighbor rows could be parsed.", "Investigate neighbors not reaching FULL state.", execution))

    bgp = outputs.get("bgp_summary")
    if bgp:
        execution, text = bgp
        rows = [line.split() for line in text.splitlines() if re.match(r"^\s*(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]+)\s+", line, re.I)]
        established = sum(1 for row in rows if row and row[-1].isdigit())
        facts["routing"].update({"bgp_neighbors": len(rows), "bgp_established": established})
        result = "UNKNOWN" if not rows else ("WARNING" if established != len(rows) else "PASS")
        findings.append(_finding("CISCO.BGP.NEIGHBORS", "ROUTING", "HIGH", result, "BGP session health", f"Parsed {len(rows)} BGP neighbor(s); {established} appear established." if rows else "No BGP summary rows could be parsed.", "Investigate peers whose state column is not a received-prefix count.", execution))

    return findings, facts


def _command_compatibility_rules(executions):
    findings = []
    unsupported = []
    unavailable_states = {
        CommandExecution.State.UNSUPPORTED,
        CommandExecution.State.DENIED,
        CommandExecution.State.TIMEOUT,
        CommandExecution.State.TRUNCATED,
        CommandExecution.State.ERROR,
    }
    for key, execution in executions.items():
        if execution.state not in unavailable_states:
            continue
        unsupported.append({"key": key, "state": execution.state, "reason": execution.reason})
        findings.append(_finding(
            f"CISCO.COMMAND.{key.upper()}", "COMPATIBILITY", "MEDIUM", "UNKNOWN" if execution.state != CommandExecution.State.ERROR else "ERROR",
            f"{key.replace('_', ' ').title()} command unavailable",
            f"The approved command returned {execution.state}: {execution.reason or 'NO_REASON_RECORDED'}. No technical PASS was inferred.",
            "Select a separately reviewed model/firmware command-profile revision or correct read-only command authorization; then recollect.", execution,
        ))
    return findings, {"unavailable_commands": unsupported, "unavailable_command_count": len(unsupported)}


@transaction.atomic
def assess_cisco_job(job_id, *, evidence_store=None):
    evidence_store = evidence_store or LocalEncryptedObjectStore()
    job = CollectionJob.objects.select_for_update().select_related("tenant", "device").get(pk=job_id)
    if job.discovered_vendor != "CISCO" or job.discovered_platform not in {"IOS", "IOS-XE", "NX-OS"}:
        raise ValueError("Only discovered Cisco IOS/IOS-XE/NX-OS jobs are supported by this rule pack.")
    existing = DeviceAssessment.objects.filter(job=job).first()
    if existing is not None:
        return existing
    assessment = DeviceAssessment.objects.create(job=job, tenant=job.tenant, rule_pack=RULE_PACK, rule_pack_version=RULE_PACK_VERSION, result="UNKNOWN", facts={})
    outputs = {}
    executions = {}
    integrity_errors = 0
    for execution in job.command_executions.select_related("command", "snapshot"):
        executions[execution.command.key] = execution
        if execution.state != CommandExecution.State.SUCCEEDED:
            continue
        try:
            text = evidence_store.retrieve_and_verify(execution.snapshot).decode("utf-8", errors="replace")
            outputs[execution.command.key] = (execution, text)
        except (ObjectDoesNotExist, EvidenceIntegrityError):
            integrity_errors += 1
    config_item = outputs.get("running_config")
    findings = _config_rules(config_item[1] if config_item else None, config_item[0] if config_item else None)
    hardening_facts = {}
    if config_item and job.discovered_platform in {"IOS", "IOS-XE"}:
        hardening_findings, hardening_facts = _ios_hardening_rules(config_item[1], config_item[0])
        findings.extend(hardening_findings)
    findings.append(_finding("CISCO.TRANSPORT.TELNET", "MANAGEMENT", "HIGH", "FAIL" if job.device.transport == "TELNET" else "PASS", "Collector management transport", "Collector access uses clear-text Telnet under an approved exception." if job.device.transport == "TELNET" else "Collector access uses SSH with a pinned host key.", "Migrate the management plane to SSH and revoke the Telnet exception." if job.device.transport == "TELNET" else ""))
    findings.append(_output_rule(outputs, executions, "time_sync", "CISCO.TIME.NTP_STATE", "TIME", "MEDIUM", "NTP synchronization evidence", r"^[*+#o]", "At least one selected/valid NTP association was observed.", "No selected NTP association was identified in command output.", "Verify reachability, synchronization and approved NTP sources."))
    findings.append(_output_rule(outputs, executions, "logging_posture", "CISCO.LOGGING.ACTIVE", "LOGGING", "MEDIUM", "Logging operational state", r"logging to|trap logging|syslog logging", "Operational logging output was observed.", "Operational output did not demonstrate active remote logging.", "Verify the remote collector path and receipt on the logging platform."))
    findings.append(_finding("CISCO.PSIRT.CORRELATION", "VULNERABILITY", "HIGH", "UNKNOWN", "Cisco security advisory correlation", f"Device release {job.discovered_release or 'UNKNOWN'} was identified, but no reviewed Cisco advisory feed is installed.", "Integrate and review the official Cisco advisory feed before asserting affected/not-affected status.", outputs.get("platform_version", (None,))[0]))
    deep_findings, deep_facts = _deep_operational_rules(outputs, executions)
    findings.extend(deep_findings)
    structured_findings, structured_facts = _structured_device_rules(outputs, executions)
    findings.extend(structured_findings)
    compatibility_findings, compatibility_facts = _command_compatibility_rules(executions)
    findings.extend(compatibility_findings)
    if integrity_errors:
        findings.append(_finding("CISCO.EVIDENCE.INTEGRITY", "EVIDENCE", "CRITICAL", "ERROR", "Snapshot integrity/read failure", f"{integrity_errors} successful command snapshot(s) could not be authenticated and read.", "Investigate encrypted evidence storage and recollect."))
    TechnicalFinding.objects.bulk_create([TechnicalFinding(tenant=job.tenant, assessment=assessment, **item) for item in findings])
    counts = {state: sum(1 for item in findings if item["result"] == state) for state in TechnicalFinding.Result.values}
    overall = "ERROR" if counts["ERROR"] else ("FAIL" if counts["FAIL"] else ("WARNING" if counts["WARNING"] else ("UNKNOWN" if counts["UNKNOWN"] else "PASS")))
    facts = {"vendor": job.discovered_vendor, "platform": job.discovered_platform, "model": job.discovered_model, "release": job.discovered_release, "commands_succeeded": len(outputs), "commands_total": job.command_executions.count(), "finding_counts": counts, "configuration": hardening_facts, **structured_facts, **deep_facts, **compatibility_facts}
    assessment.result = overall; assessment.facts = facts
    assessment.save(update_fields=["result", "facts"])
    AuditEvent.objects.create(tenant=job.tenant, actor=job.requested_by, action="collector.assessment_completed", object_type="DeviceAssessment", object_id=str(assessment.id), metadata={"result": overall, "rule_pack": RULE_PACK, "rule_pack_version": RULE_PACK_VERSION})
    return assessment
