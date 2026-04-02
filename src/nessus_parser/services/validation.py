from __future__ import annotations

import subprocess
import re
from collections import Counter
from pathlib import Path

from nessus_parser.core.colors import (
    bold,
    bright_cyan,
    bright_red,
    bright_yellow,
    cyan,
    dim,
    green,
    heavy_separator,
    red,
    separator,
    severity_badge,
    status_badge,
    status_text,
    yellow,
)
from nessus_parser.db.connection import connect
from nessus_parser.services.playbooks import get_playbook
from nessus_parser.services.scans import (
    get_finding_ids_for_plugin,
    list_scan_plugin_ids,
    load_scan_targets,
    upsert_plugin_from_scan,
)


def validate_plugin(db_path: Path, plugin_id: int, project_name: str = "default") -> str:
    playbook = get_playbook(db_path, plugin_id)
    if playbook is None:
        return f"No playbook found for plugin {plugin_id}"

    targets = get_finding_ids_for_plugin(db_path, plugin_id, project_name=project_name)
    if not targets:
        return f"No findings found for plugin {plugin_id}"

    results: list[tuple[str, str | None, str, int | None]] = []
    skipped: list[tuple[str, int | None, str]] = []
    connection = connect(db_path)
    try:
        for finding_id, host, port, protocol in targets:
            applicable, skip_reason = _is_target_applicable(playbook, port, protocol)
            if not applicable:
                skipped.append((host, port, skip_reason or "not_applicable"))
                connection.execute(
                    """
                INSERT INTO validation_runs (
                    finding_id,
                    plugin_id,
                    host,
                    port,
                    command,
                    status,
                    reason,
                    analyst_note,
                    source,
                    stdout,
                    stderr,
                    exit_code,
                    project_name
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding_id,
                        plugin_id,
                        host,
                        port,
                        "",
                        "skipped",
                        skip_reason or "not_applicable",
                        None,
                        "automation",
                        "",
                        "",
                        None,
                        project_name,
                    ),
                )
                continue
            command, execution, status, reason = _execute_playbook_command(
                playbook, host, port or 0, protocol
            )
            connection.execute(
                """
                INSERT INTO validation_runs (
                    finding_id,
                    plugin_id,
                    host,
                    port,
                    command,
                    status,
                    reason,
                    analyst_note,
                    source,
                    stdout,
                    stderr,
                    exit_code,
                    project_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    plugin_id,
                    host,
                    port,
                    command,
                    status,
                    reason,
                    None,
                    "automation",
                    execution["stdout"],
                    execution["stderr"],
                    execution["exit_code"],
                    project_name,
                ),
            )
            results.append((status, reason, host, port))
        connection.commit()
    finally:
        connection.close()

    summary = Counter(status for status, _, _, _ in results)
    lines = [bold(f"Validated {len(results)} targets for plugin {plugin_id}")]
    if skipped:
        lines.append(dim(f"  skipped: {len(skipped)}"))
    for status, count in sorted(summary.items()):
        lines.append(f"  {status_text(status)}: {count}")
    for status, reason, host, port in results[:20]:
        detail = f"{host}:{port}" if port is not None else host
        suffix = f" {dim('reason=' + reason)}" if reason else ""
        lines.append(f"  {bold(detail)}  {status_badge(status)}{suffix}")
    if len(results) > 20:
        lines.append(dim(f"  ... truncated {len(results) - 20} additional results"))
    for host, port, reason in skipped[:20]:
        detail = f"{host}:{port}" if port is not None else host
        lines.append(f"  {dim('skipped')}  {detail}  {dim('reason=' + reason)}")
    if len(skipped) > 20:
        lines.append(dim(f"  ... truncated {len(skipped) - 20} additional skipped targets"))
    return "\n".join(lines)


def validate_scan_file(
    db_path: Path,
    scan_path: Path,
    plugin_id: int,
    persist_results: bool = False,
    project_name: str = "default",
) -> str:
    playbook = get_playbook(db_path, plugin_id)
    if playbook is None:
        return f"No playbook found for plugin {plugin_id}"

    scan_data = load_scan_targets(scan_path, plugin_id)
    if scan_data is None:
        return f"Plugin {plugin_id} not found in {scan_path}"

    upsert_plugin_from_scan(db_path, scan_path, plugin_id)

    results: list[dict[str, object]] = []
    groups: dict[str, list[str]] = {
        "validated": [],
        "not_validated": [],
        "inconclusive": [],
        "host_down": [],
        "port_closed": [],
        "port_filtered": [],
        "skipped": [],
        "error": [],
    }

    connection = connect(db_path) if persist_results else None
    try:
        for target in scan_data["targets"]:
            host = str(target["host"])
            port = int(target["port"])
            protocol = target.get("protocol")
            applicable, skip_reason = _is_target_applicable(playbook, port, protocol)
            if not applicable:
                if connection is not None:
                    _insert_validation_run(
                        connection,
                        plugin_id=plugin_id,
                        host=host,
                        port=port,
                        command="",
                        status="skipped",
                        reason=skip_reason or "not_applicable",
                        stdout="",
                        stderr="",
                        exit_code=None,
                        source="automation",
                        project_name=project_name,
                    )
                groups["skipped"].append(f"{host}:{port}")
                results.append(
                    {
                        "host": host,
                        "port": port,
                        "status": "skipped",
                        "reason": skip_reason or "not_applicable",
                        "command": "",
                        "stdout": "",
                        "stderr": "",
                    }
                )
                continue

            command, execution, status, reason = _execute_playbook_command(
                playbook, host, port, protocol
            )
            if connection is not None:
                _insert_validation_run(
                    connection,
                    plugin_id=plugin_id,
                    host=host,
                    port=port,
                    command=command,
                    status=status,
                    reason=reason,
                    stdout=str(execution["stdout"]),
                    stderr=str(execution["stderr"]),
                    exit_code=execution["exit_code"],
                    source="automation",
                    project_name=project_name,
                )
            groups.setdefault(status, []).append(f"{host}:{port}")
            results.append(
                {
                    "host": host,
                    "port": port,
                    "status": status,
                    "reason": reason,
                    "command": command,
                    "stdout": str(execution["stdout"]),
                    "stderr": str(execution["stderr"]),
                }
            )
        if connection is not None:
            connection.commit()
    finally:
        if connection is not None:
            connection.close()

    return _format_scan_validation_output(
        scan_path,
        scan_data,
        groups,
        results,
        persisted_results=persist_results,
    )


def validate_scan_file_all(
    db_path: Path,
    scan_path: Path,
    plugin_ids: list[int],
    persist_results: bool = False,
    project_name: str = "default",
) -> str:
    # include_informational=True: callers already applied severity filtering;
    # re-filtering here would silently drop severity=0 (informational) plugins.
    scan_plugin_ids = set(list_scan_plugin_ids(scan_path, include_informational=True))
    matching_plugin_ids = [plugin_id for plugin_id in plugin_ids if plugin_id in scan_plugin_ids]
    if not matching_plugin_ids:
        return f"No matching playbooks found for plugins present in {scan_path}"

    reports: list[str] = []
    for plugin_id in matching_plugin_ids:
        report = validate_scan_file(
            db_path,
            scan_path,
            plugin_id,
            persist_results=persist_results,
            project_name=project_name,
        )
        reports.append(report)
    return "\n\n".join(reports)


def get_matching_scan_playbook_ids(
    db_path: Path,
    scan_path: Path,
    plugin_ids: list[int],
    include_informational: bool = False,
    min_severity: int | None = None,
) -> list[int]:
    scan_plugin_ids = set(
        list_scan_plugin_ids(
            scan_path,
            include_informational=include_informational,
            min_severity=min_severity,
        )
    )
    return [plugin_id for plugin_id in plugin_ids if plugin_id in scan_plugin_ids]


def get_validation_summary(db_path: Path, plugin_id: int, project_name: str | None = None) -> list[tuple[str, int]]:
    connection = connect(db_path)
    try:
        return list(
            connection.execute(
                """
                SELECT vr.status, COUNT(*) AS count
                FROM validation_runs vr
                INNER JOIN (
                    SELECT host, port, MAX(id) AS latest_id
                    FROM validation_runs
                    WHERE plugin_id = ?
                    AND (? IS NULL OR project_name = ?)
                    GROUP BY host, port
                ) latest
                    ON vr.id = latest.latest_id
                GROUP BY status
                ORDER BY count DESC, vr.status ASC
                """,
                (plugin_id, project_name, project_name),
            )
        )
    finally:
        connection.close()


def get_latest_validation_results(
    db_path: Path,
    plugin_id: int,
    project_name: str | None = None,
) -> list[tuple[str, int | None, str, str | None, str | None, str, str, str, str | None, str | None]]:
    connection = connect(db_path)
    try:
        return list(
            connection.execute(
                """
                SELECT
                    vr.host,
                    vr.port,
                    vr.status,
                    vr.reason,
                    vr.analyst_note,
                    vr.command,
                    vr.executed_at,
                    vr.source,
                    vr.stdout,
                    vr.stderr
                FROM validation_runs vr
                INNER JOIN (
                    SELECT host, port, MAX(id) AS latest_id
                    FROM validation_runs
                    WHERE plugin_id = ?
                    AND (? IS NULL OR project_name = ?)
                    GROUP BY host, port
                ) latest
                    ON vr.id = latest.latest_id
                ORDER BY vr.host ASC, vr.port ASC, vr.id ASC
                """,
                (plugin_id, project_name, project_name),
            )
        )
    finally:
        connection.close()


def list_projects(db_path: Path) -> list[tuple[str, int, str]]:
    connection = connect(db_path)
    try:
        return list(
            connection.execute(
                """
                SELECT project_name, COUNT(*) AS run_count, MAX(executed_at) AS last_run
                FROM validation_runs
                GROUP BY project_name
                ORDER BY last_run DESC
                """
            )
        )
    finally:
        connection.close()


def override_result(
    db_path: Path,
    plugin_id: int,
    host: str,
    port: int | None,
    status: str,
    reason: str | None,
    analyst_note: str | None,
    project_name: str = "default",
) -> bool:
    connection = connect(db_path)
    try:
        _insert_validation_run(
            connection,
            plugin_id=plugin_id,
            host=host,
            port=port,
            command="",
            status=status,
            reason=reason,
            stdout="",
            stderr="",
            exit_code=None,
            source="manual",
            analyst_note=analyst_note,
            project_name=project_name,
        )
        connection.commit()
        return True
    finally:
        connection.close()


# Sentinel value used as finding_id for validation_runs that are not linked to a
# findings row (e.g. manual overrides). No FK constraint exists on this column,
# so 0 is safe; a future schema migration can make the column nullable if needed.
_MANUAL_OVERRIDE_FINDING_ID = 0


def _insert_validation_run(
    connection,
    plugin_id: int,
    host: str,
    port: int | None,
    command: str,
    status: str,
    reason: str | None,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    source: str,
    analyst_note: str | None = None,
    project_name: str = "default",
) -> None:
    connection.execute(
        """
        INSERT INTO validation_runs (
            finding_id,
            plugin_id,
            host,
            port,
            command,
            status,
            reason,
            analyst_note,
            source,
            stdout,
            stderr,
            exit_code,
            project_name
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            _MANUAL_OVERRIDE_FINDING_ID,
            plugin_id,
            host,
            port,
            command,
            status,
            reason,
            analyst_note,
            source,
            stdout,
            stderr,
            exit_code,
            project_name,
        ),
    )


def _format_scan_validation_output(
    scan_path: Path,
    scan_data: dict[str, object],
    groups: dict[str, list[str]],
    results: list[dict[str, object]],
    persisted_results: bool,
) -> str:
    plugin_name = str(scan_data["plugin_name"])
    description = _short_finding_description(scan_data)
    sev = scan_data.get("severity")
    sev_tag = severity_badge(str(sev)) if sev is not None else ""

    lines = [
        separator(),
        sev_tag + " " + bold(cyan("Plugin " + str(scan_data["plugin_id"]))) + " " + dim("|") + " " + bold(plugin_name),
        dim("scan: " + str(scan_path)),
        dim("persisted: " + ("yes" if persisted_results else "no")),
        "",
        bright_cyan("SUMMARY"),
        dim(description),
    ]
    lines.extend(_build_report_ready_block(scan_data, groups, results))

    # Status group sections (only non-empty)
    for heading, status, color_fn in (
        ("INCONCLUSIVE", "inconclusive", yellow),
        ("HOST DOWN", "host_down", dim),
        ("PORT CLOSED", "port_closed", dim),
        ("PORT FILTERED", "port_filtered", dim),
        ("SKIPPED", "skipped", dim),
        ("ERROR", "error", red),
    ):
        members = groups.get(status, [])
        if members:
            lines.extend(["", bright_yellow(f"{heading} ({len(members)}):") if status in ("inconclusive", "error") else dim(f"{heading} ({len(members)}):")])
            for target in members:
                lines.append(f"  {color_fn(target)}")

    # Detailed command output
    lines.extend(["", bright_cyan("COMMAND OUTPUT")])
    ordered_results = sorted(
        results,
        key=lambda item: (
            _status_rank(str(item["status"])),
            str(item["host"]),
            int(item["port"]),
        ),
    )
    for result in ordered_results[:20]:
        status_str = str(result["status"])
        target_label = f"{result['host']}:{result['port']}"
        reason_str = result["reason"] or "-"
        lines.append(
            f"  {bold(target_label)}  {status_badge(status_str)}  {dim('reason='+ reason_str)}"
        )
        if result["command"]:
            lines.append(f"    {dim('$')} {dim(str(result['command']))}")
        stdout = str(result["stdout"]).strip()
        stderr = str(result["stderr"]).strip()
        if stdout:
            lines.append(f"    {dim('stdout=')}{ stdout[:400]}")
        if stderr:
            lines.append(f"    {dim('stderr=')}{red(stderr[:400])}")
    if len(ordered_results) > 20:
        lines.append(dim(f"  ... truncated {len(ordered_results) - 20} additional outputs"))
    return "\n".join(lines)


def build_summary_banner(
    total_plugins: int,
    status_totals: dict[str, int],
    total_targets: int,
) -> str:
    lines = [
        "",
        heavy_separator(),
        bold(bright_cyan("  VALIDATION SUMMARY")),
        heavy_separator(),
        f"  {bold('Plugins processed:')}  {total_plugins}",
        f"  {bold('Total targets:')}      {total_targets}",
        "",
    ]

    for label, key, color_fn in (
        ("True Positives", "validated", bright_red),
        ("False Positives", "not_validated", green),
        ("Inconclusive", "inconclusive", yellow),
        ("Host Down", "host_down", dim),
        ("Port Closed", "port_closed", dim),
        ("Port Filtered", "port_filtered", dim),
        ("Skipped", "skipped", dim),
        ("Errors", "error", red),
    ):
        count = status_totals.get(key, 0)
        if count > 0:
            bar_len = min(count, 40)
            bar = "\u2588" * bar_len
            lines.append(f"  {color_fn(f'{label:<18} {count:>5}  {bar}')}")

    validated = status_totals.get("validated", 0)
    not_validated = status_totals.get("not_validated", 0)
    if total_targets > 0:
        tp_rate = validated / total_targets * 100
        fp_rate = not_validated / total_targets * 100
        lines.extend([
            "",
            f"  {bold('Confirmation rate:')} {bright_red(f'{tp_rate:.1f}%')} true positive, {green(f'{fp_rate:.1f}%')} false positive",
        ])

    lines.append(heavy_separator())
    return "\n".join(lines)


def _short_finding_description(scan_data: dict[str, object]) -> str:
    description = scan_data.get("description") or scan_data.get("synopsis") or scan_data.get("solution")
    if description:
        text = str(description).replace("\n", " ").strip()
        sentence = text.split(". ")[0].strip()
        if not sentence.endswith("."):
            sentence += "."
        return sentence
    return f"The scan reported the finding '{scan_data['plugin_name']}' on the listed targets."


def _build_report_ready_block(
    scan_data: dict[str, object],
    groups: dict[str, list[str]],
    results: list[dict[str, object]],
) -> list[str]:
    true_positive = groups.get("validated", [])
    false_positive = groups.get("not_validated", [])
    plugin_name = str(scan_data["plugin_name"])
    lines: list[str] = []

    # Status counts bar
    status_counts: list[str] = []
    for label, key, color_fn in (
        ("TRUE POS", "validated", bright_red),
        ("FALSE POS", "not_validated", green),
        ("INCONCLUSIVE", "inconclusive", yellow),
        ("DOWN/CLOSED", "host_down", dim),
        ("SKIPPED", "skipped", dim),
        ("ERROR", "error", red),
    ):
        count = len(groups.get(key, []))
        if key == "DOWN/CLOSED":
            count = len(groups.get("host_down", [])) + len(groups.get("port_closed", [])) + len(groups.get("port_filtered", []))
        if count > 0:
            status_counts.append(color_fn(f"{label}: {count}"))
    if status_counts:
        lines.append("  " + dim(" | ").join(status_counts))

    if true_positive:
        target_label = ", ".join(true_positive)
        lines.extend([
            "",
            bright_red(f"  CONFIRMED VULNERABLE ({len(true_positive)}):"),
        ])
        for target in true_positive:
            lines.append(f"    {bright_red('*')} {bold(target)}")
    elif false_positive:
        target_label = ", ".join(false_positive)
        lines.extend([
            "",
            green(f"  FALSE POSITIVE ({len(false_positive)}):"),
        ])
        for target in false_positive:
            lines.append(f"    {green('*')} {target}")
    else:
        lines.append(dim(f"  No target conclusively validated for '{plugin_name}'."))

    commands: list[str] = []
    for result in results:
        status = str(result["status"])
        command = str(result["command"]).strip()
        if status in {"validated", "not_validated"} and command and command not in commands:
            commands.append(command)

    if commands:
        lines.append(dim("  Validation command(s):"))
        for command in commands:
            lines.append(f"    {dim('$')} {dim(command)}")

    return lines


def _status_rank(status: str) -> int:
    order = {
        "validated": 0,
        "not_validated": 1,
        "host_down": 2,
        "port_closed": 3,
        "port_filtered": 4,
        "inconclusive": 5,
        "error": 6,
        "skipped": 7,
    }
    return order.get(status, 99)


def _run_command(command: str, timeout_seconds: int) -> dict[str, object]:
    try:
        completed = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        return {
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "exit_code": completed.returncode,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "timed out",
            "exit_code": None,
        }


def _execute_playbook_command(
    playbook: dict[str, object],
    host: str,
    port: int,
    protocol: str | None,
) -> tuple[str, dict[str, object], str, str | None]:
    commands = [str(playbook["command_template"])] + [
        str(item) for item in playbook.get("fallback_commands", [])
    ]
    last_command = ""
    last_execution: dict[str, object] = {"stdout": "", "stderr": "", "exit_code": None}
    last_status = "error"
    last_reason: str | None = None

    for template in commands:
        command = template.format(
            host=host,
            port=port,
            protocol=protocol or "",
            openssl_tls_args=_build_openssl_tls_args(playbook, port),
            sslscan_starttls_args=_build_sslscan_starttls_args(playbook, port),
            testssl_starttls_args=_build_testssl_starttls_args(playbook, port),
        )
        execution = _run_command(command, int(playbook["timeout_seconds"]))
        status, reason = _derive_status(
            playbook,
            str(execution["stdout"]),
            str(execution["stderr"]),
            execution["exit_code"],
        )
        last_command = command
        last_execution = execution
        last_status = status
        last_reason = reason
        if status not in {"error", "inconclusive"}:
            break

    return last_command, last_execution, last_status, last_reason


def _derive_status(
    playbook: dict[str, object],
    stdout: str,
    stderr: str,
    exit_code: int | None,
) -> tuple[str, str | None]:
    haystack = f"{stdout}\n{stderr}".lower()

    version_status = _derive_version_rule_status(playbook, haystack)
    if version_status is not None:
        return version_status

    validated_terms = [item.lower() for item in playbook["validated_if"]]
    for term in validated_terms:
        if term and term in haystack:
            return "validated", None

    not_validated_terms = [item.lower() for item in playbook["not_validated_if"]]
    for term in not_validated_terms:
        if term and term in haystack:
            return "not_validated", _map_reason(playbook, haystack, default="not_validated")

    not_validated_present_terms = [
        item.lower() for item in playbook.get("not_validated_if_present", [])
    ]
    for term in not_validated_present_terms:
        if term and term in haystack:
            return "not_validated", _map_reason(playbook, haystack, default="not_validated")

    inconclusive_terms = [item.lower() for item in playbook["inconclusive_if"]]
    for term in inconclusive_terms:
        if term and term in haystack:
            return _map_reason(playbook, haystack, default="inconclusive"), _map_reason(playbook, haystack, default=None)

    if exit_code == 0:
        # Only check for absent-term validation on a successful command execution.
        # Applying this against a failed command's garbage output would produce false positives.
        validated_absent_terms = [item.lower() for item in playbook.get("validated_if_absent", [])]
        if validated_absent_terms and all(term and term not in haystack for term in validated_absent_terms):
            return "validated", None
        return "inconclusive", None

    return _map_reason(playbook, haystack, default="error"), _map_reason(playbook, haystack, default=None)


def _map_reason(
    playbook: dict[str, object],
    haystack: str,
    default: str | None,
) -> str | None:
    for term, reason in dict(playbook["failure_reason_map"]).items():
        if term.lower() in haystack:
            return reason
    return default


def _is_target_applicable(
    playbook: dict[str, object],
    port: int | None,
    protocol: str | None,
) -> tuple[bool, str | None]:
    service = str(playbook.get("service") or "")

    if service == "icmp":
        return _is_icmp_target(protocol)

    if port in (None, 0):
        return False, "invalid_port"

    if service == "dns":
        protocol_value = (protocol or "").lower()
        if protocol_value not in {"udp", "tcp"}:
            return False, "unsupported_protocol"
    elif protocol and protocol.lower() != "tcp":
        return False, "unsupported_protocol"

    allowed_ports = {int(item) for item in playbook.get("allowed_ports", [])}
    if allowed_ports and port not in allowed_ports:
        return False, "port_not_allowed"

    blocked_ports = {int(item) for item in playbook.get("blocked_ports", [])}
    if port in blocked_ports:
        return False, "port_blocked"

    # If allowed_ports is empty the playbook accepts any port, so skip
    # the service-type port-range heuristics and trust the Nessus finding.
    if not allowed_ports:
        return True, None

    if service == "https":
        return _is_https_target(port)

    if service == "tls":
        return _is_tls_target(playbook, port)

    if service == "dns":
        return _is_dns_target(port)

    return True, None


def _is_https_target(port: int) -> tuple[bool, str | None]:
    if port in _KNOWN_HTTPS_PORTS:
        return True, None
    if 443 <= port <= 449:
        return True, None
    if 8000 <= port <= 9000:
        return True, None
    return False, "port_not_https_like"


def _is_tls_target(playbook: dict[str, object], port: int) -> tuple[bool, str | None]:
    starttls_map = {
        int(key): value
        for key, value in dict(playbook.get("starttls_protocol_map", {})).items()
    }
    if port in starttls_map:
        return True, None
    if port in _KNOWN_TLS_PORTS:
        return True, None
    if 443 <= port <= 449:
        return True, None
    if 4600 <= port <= 5500:
        return True, None
    if 8000 <= port <= 9000:
        return True, None
    return False, "port_not_tls_like"


def _is_dns_target(port: int) -> tuple[bool, str | None]:
    if port == 53:
        return True, None
    return False, "port_not_dns"


def _is_icmp_target(protocol: str | None) -> tuple[bool, str | None]:
    if (protocol or "").lower() == "icmp":
        return True, None
    return False, "unsupported_protocol"


def _build_openssl_tls_args(playbook: dict[str, object], port: int | None) -> str:
    if port is None:
        return ""
    starttls_map = {
        int(key): value
        for key, value in dict(playbook.get("starttls_protocol_map", {})).items()
    }
    protocol = starttls_map.get(port)
    if protocol:
        return f"-starttls {protocol}"
    return ""


def _build_sslscan_starttls_args(playbook: dict[str, object], port: int | None) -> str:
    if port is None:
        return ""
    protocol = dict(playbook.get("starttls_protocol_map", {})).get(str(port))
    mapping = {
        "ftp": "--starttls-ftp",
        "imap": "--starttls-imap",
        "ldap": "--starttls-ldap",
        "mysql": "--starttls-mysql",
        "pop3": "--starttls-pop3",
        "postgres": "--starttls-psql",
        "smtp": "--starttls-smtp",
        "xmpp": "--starttls-xmpp",
        "xmpp-server": "--starttls-xmpp --xmpp-server",
    }
    return mapping.get(str(protocol), "")


def _derive_version_rule_status(
    playbook: dict[str, object],
    haystack: str,
) -> tuple[str, str | None] | None:
    version_rule = dict(playbook.get("version_rule", {}))
    if not version_rule:
        return None

    product_terms = [str(item).lower() for item in version_rule.get("product_terms", [])]
    if product_terms and not any(term in haystack for term in product_terms):
        return None

    extracted_version = None
    for pattern in version_rule.get("version_patterns", []):
        match = re.search(str(pattern), haystack, re.IGNORECASE)
        if match:
            extracted_version = match.group(1)
            break

    if not extracted_version:
        return None

    affected_lt = version_rule.get("affected_lt")
    if affected_lt and _compare_versions(extracted_version, str(affected_lt)) < 0:
        return "validated", f"detected_version={extracted_version}"

    affected_lte = version_rule.get("affected_lte")
    if affected_lte and _compare_versions(extracted_version, str(affected_lte)) <= 0:
        return "validated", f"detected_version={extracted_version}"

    fixed_version = version_rule.get("fixed_version")
    if fixed_version and _compare_versions(extracted_version, str(fixed_version)) >= 0:
        return "not_validated", f"detected_version={extracted_version}"

    return "not_validated", f"detected_version={extracted_version}"


def _compare_versions(left: str, right: str) -> int:
    left_parts = _tokenize_version(left)
    right_parts = _tokenize_version(right)
    max_len = max(len(left_parts), len(right_parts))
    for index in range(max_len):
        left_part = left_parts[index] if index < len(left_parts) else 0
        right_part = right_parts[index] if index < len(right_parts) else 0
        if left_part == right_part:
            continue
        if isinstance(left_part, int) and isinstance(right_part, int):
            return -1 if left_part < right_part else 1
        return -1 if str(left_part) < str(right_part) else 1
    return 0


def _tokenize_version(version: str) -> list[int | str]:
    tokens = re.findall(r"\d+|[a-zA-Z]+", version)
    parsed: list[int | str] = []
    for token in tokens:
        if token.isdigit():
            parsed.append(int(token))
        else:
            parsed.append(token.lower())
    return parsed


def _build_testssl_starttls_args(playbook: dict[str, object], port: int | None) -> str:
    if port is None:
        return ""
    protocol = dict(playbook.get("starttls_protocol_map", {})).get(str(port))
    if protocol:
        return f"--starttls {protocol}"
    return ""


_KNOWN_HTTPS_PORTS = {
    443, 444, 445, 448, 449, 5443, 6443, 7443, 8443, 8843, 9443, 10443,
}

_KNOWN_TLS_PORTS = {
    443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 1311,
    2083, 2087, 2096, 2376, 3269, 3389, 5061, 5349, 5432, 5500, 5986,
    6363, 6443, 6514, 6697, 8172, 8443, 8531, 8883, 9200, 9443, 10443,
}
