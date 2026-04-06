from __future__ import annotations

import csv
import subprocess
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
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

    # Probe all targets concurrently — commands are I/O-bound subprocesses.
    # Pass plugin_output so targets resolvable from scan evidence skip live probing.
    with ThreadPoolExecutor(max_workers=_VALIDATION_MAX_WORKERS) as executor:
        futures = [
            (
                row[0],
                executor.submit(
                    _probe_target, playbook,
                    str(row[1]), row[2] or 0, row[3],
                    row[4] if len(row) > 4 else None,
                ),
            )
            for row in targets
        ]
        probes = [(fid, f.result()) for fid, f in futures]

    connection = connect(db_path)
    try:
        connection.execute(
            "DELETE FROM validation_runs WHERE plugin_id = ? AND project_name = ? AND source != 'manual'",
            (plugin_id, project_name),
        )
        for finding_id, probe in probes:
            host = str(probe["host"])
            port = probe.get("port")
            status = str(probe["status"])
            reason = probe.get("reason")
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
                    probe["command"],
                    status,
                    reason,
                    None,
                    str(probe.get("source", "automation")),
                    probe["stdout"],
                    probe["stderr"],
                    probe["exit_code"],
                    project_name,
                ),
            )
            if status == "skipped":
                skipped.append((host, port, reason or "not_applicable"))
            else:
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

    # Probe all targets concurrently — commands are I/O-bound subprocesses.
    # Pass plugin_output so targets resolvable from scan evidence skip live probing.
    with ThreadPoolExecutor(max_workers=_VALIDATION_MAX_WORKERS) as executor:
        futures = [
            executor.submit(
                _probe_target, playbook,
                str(t["host"]), int(t["port"]), t.get("protocol"),
                t.get("plugin_output"),
            )
            for t in scan_data["targets"]
        ]
        probes = [f.result() for f in futures]

    connection = connect(db_path) if persist_results else None
    try:
        if connection is not None:
            connection.execute(
                "DELETE FROM validation_runs WHERE plugin_id = ? AND project_name = ? AND source != 'manual'",
                (plugin_id, project_name),
            )
        for probe in probes:
            host = str(probe["host"])
            port = int(probe["port"])
            status = str(probe["status"])
            reason = probe.get("reason")
            command = str(probe["command"])
            stdout = str(probe["stdout"])
            stderr = str(probe["stderr"])
            exit_code = probe.get("exit_code")
            if connection is not None:
                _insert_validation_run(
                    connection,
                    plugin_id=plugin_id,
                    host=host,
                    port=port,
                    command=command,
                    status=status,
                    reason=reason,
                    stdout=stdout,
                    stderr=stderr,
                    exit_code=exit_code,
                    source=str(probe.get("source", "automation")),
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
                    "stdout": stdout,
                    "stderr": stderr,
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


def get_project_latest_results(
    db_path: Path,
    project_name: str,
) -> dict[tuple[int, str, int | None], str]:
    """Return the latest status per (plugin_id, host, port) for a project.

    Used by the diff report to compare two projects side-by-side.
    """
    connection = connect(db_path)
    try:
        rows = connection.execute(
            """
            SELECT vr.plugin_id, vr.host, vr.port, vr.status
            FROM validation_runs vr
            INNER JOIN (
                SELECT plugin_id, host, port, MAX(id) AS latest_id
                FROM validation_runs
                WHERE project_name = ?
                GROUP BY plugin_id, host, port
            ) latest ON vr.id = latest.latest_id
            """,
            (project_name,),
        ).fetchall()
        return {(int(r[0]), str(r[1]), r[2]): str(r[3]) for r in rows}
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


def bulk_override(
    db_path: Path,
    csv_path: Path,
    project_name: str = "default",
) -> tuple[int, list[str]]:
    """Apply manual overrides from a CSV file.

    Expected columns (in any order): plugin_id, host, port, status, reason, note
    The 'reason' and 'note' columns are optional.

    Returns (success_count, list_of_error_strings).
    """
    _VALID_STATUSES = {"validated", "not_validated", "inconclusive", "skipped", "error"}
    errors: list[str] = []
    rows: list[dict] = []

    with csv_path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for line_num, row in enumerate(reader, start=2):
            try:
                plugin_id = int(row["plugin_id"])
                host = row["host"].strip()
                port = int(row["port"]) if row.get("port", "").strip() else None
                status = row["status"].strip().lower()
                if status not in _VALID_STATUSES:
                    errors.append(f"line {line_num}: invalid status '{status}'")
                    continue
                reason = row.get("reason", "").strip() or None
                note = row.get("note", "").strip() or None
                rows.append({"plugin_id": plugin_id, "host": host, "port": port,
                             "status": status, "reason": reason, "note": note})
            except (KeyError, ValueError) as exc:
                errors.append(f"line {line_num}: {exc}")

    if not rows:
        return 0, errors

    connection = connect(db_path)
    try:
        for r in rows:
            _insert_validation_run(
                connection,
                plugin_id=r["plugin_id"],
                host=r["host"],
                port=r["port"],
                command="",
                status=r["status"],
                reason=r["reason"],
                stdout="",
                stderr="",
                exit_code=None,
                source="manual",
                analyst_note=r["note"],
                project_name=project_name,
            )
        connection.commit()
    finally:
        connection.close()

    return len(rows), errors


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


def persist_no_playbook_findings(
    db_path: Path,
    scan_path: Path,
    plugin_ids: list[int],
    project_name: str = "default",
) -> int:
    """Insert validation_runs with status='no_playbook' for scan findings that have no playbook.

    Also upserts plugin metadata so the HTML report can display name/severity.
    Returns the total number of host/port entries recorded.
    """
    connection = connect(db_path)
    recorded = 0
    try:
        for plugin_id in plugin_ids:
            scan_data = load_scan_targets(scan_path, plugin_id)
            if scan_data is None:
                continue
            connection.execute(
                "DELETE FROM validation_runs WHERE plugin_id = ? AND project_name = ? AND source != 'manual'",
                (plugin_id, project_name),
            )
            connection.execute(
                """
                INSERT INTO plugins (
                    plugin_id, plugin_name, severity, synopsis, description, solution, source
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(plugin_id) DO UPDATE SET
                    plugin_name = excluded.plugin_name,
                    severity    = COALESCE(excluded.severity,    plugins.severity),
                    synopsis    = COALESCE(excluded.synopsis,    plugins.synopsis),
                    description = COALESCE(excluded.description, plugins.description),
                    solution    = COALESCE(excluded.solution,    plugins.solution),
                    source      = excluded.source
                """,
                (
                    plugin_id,
                    scan_data["plugin_name"],
                    scan_data.get("severity"),
                    scan_data.get("synopsis"),
                    scan_data.get("description"),
                    scan_data.get("solution"),
                    f"scan:{scan_path.name}",
                ),
            )
            for target in list(scan_data["targets"]):
                _insert_validation_run(
                    connection,
                    plugin_id=plugin_id,
                    host=str(target["host"]),
                    port=int(target["port"]),
                    command="",
                    status="no_playbook",
                    reason="no_playbook",
                    stdout="",
                    stderr="",
                    exit_code=None,
                    source="automation",
                    project_name=project_name,
                )
                recorded += 1
        connection.commit()
    finally:
        connection.close()
    return recorded


def list_validated_plugin_ids(db_path: Path, project_name: str | None = None) -> list[int]:
    """Return all distinct plugin_ids that have at least one validation_run for the given project."""
    connection = connect(db_path)
    try:
        return [
            row[0]
            for row in connection.execute(
                """
                SELECT DISTINCT plugin_id
                FROM validation_runs
                WHERE (? IS NULL OR project_name = ?)
                ORDER BY plugin_id ASC
                """,
                (project_name, project_name),
            )
        ]
    finally:
        connection.close()


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


_VALIDATION_MAX_WORKERS = 10


def _probe_target(
    playbook: dict[str, object],
    host: str,
    port: int,
    protocol: str | None,
    plugin_output: str | None = None,
) -> dict[str, object]:
    """Run applicability check + playbook command for one target. Thread-safe.

    Always attempts a live network probe first to independently confirm the
    finding still exists.  Only falls back to *plugin_output* (Nessus scan data)
    when the live probe is inconclusive due to network conditions (host down,
    port filtered, SSL handshake failure, etc.) and plugin_output can provide
    a conclusive verdict.
    """
    applicable, skip_reason = _is_target_applicable(playbook, port, protocol)
    if not applicable:
        return {
            "host": host, "port": port,
            "status": "skipped", "reason": skip_reason or "not_applicable",
            "command": "", "stdout": "", "stderr": "", "exit_code": None,
            "source": "automation",
        }
    try:
        command, execution, status, reason = _execute_playbook_command(playbook, host, port, protocol)
    except Exception as exc:
        return {
            "host": host, "port": port,
            "status": "error", "reason": str(exc),
            "command": "", "stdout": "", "stderr": str(exc), "exit_code": None,
            "source": "automation",
        }

    # If the live probe was conclusive, use it.
    if status in ("validated", "not_validated"):
        return {
            "host": host, "port": port,
            "status": status, "reason": reason, "command": command,
            "stdout": str(execution["stdout"]),
            "stderr": str(execution["stderr"]),
            "exit_code": execution["exit_code"],
            "source": "automation",
        }

    # If the host or port is unreachable, mark as not_validated with the
    # network reason so it is clear the finding could not be re-tested.
    _UNREACHABLE = {"host_down", "port_filtered", "port_closed"}
    effective_reason = reason or status
    if status in _UNREACHABLE or (status == "inconclusive" and effective_reason in _UNREACHABLE):
        return {
            "host": host, "port": port,
            "status": "not_validated", "reason": effective_reason, "command": command,
            "stdout": str(execution["stdout"]),
            "stderr": str(execution["stderr"]),
            "exit_code": execution["exit_code"],
            "source": "automation",
        }

    # Live probe was inconclusive for other reasons (SSL error, empty reply, etc.).
    # Fall back to Nessus plugin_output if it can give a conclusive answer.
    if plugin_output and plugin_output.strip():
        pre_status, pre_reason = _derive_status(
            playbook, plugin_output.strip(), "", exit_code=None
        )
        if pre_status in ("validated", "not_validated"):
            return {
                "host": host, "port": port,
                "status": pre_status, "reason": pre_reason,
                "command": "", "stdout": plugin_output.strip(), "stderr": "",
                "exit_code": None, "source": "plugin_output",
            }

    # Return the live probe result (inconclusive/error) as-is.
    return {
        "host": host, "port": port,
        "status": status, "reason": reason, "command": command,
        "stdout": str(execution["stdout"]),
        "stderr": str(execution["stderr"]),
        "exit_code": execution["exit_code"],
        "source": "automation",
    }


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

    # Map well-known curl exit codes to structured statuses before falling back to "error".
    _CURL_EXIT_MAP: dict[int, tuple[str, str]] = {
        6:  ("inconclusive", "host_down"),       # Could not resolve host
        7:  ("port_closed",  "port_closed"),     # Failed to connect
        28: ("port_filtered", "port_filtered"),  # Timeout
        35: ("inconclusive", "ssl_handshake"),   # SSL connect error
        52: ("inconclusive", "empty_reply"),     # Empty reply from server
        56: ("inconclusive", "network_error"),   # Recv failure
    }
    if exit_code is not None and exit_code in _CURL_EXIT_MAP:
        mapped_status, mapped_reason = _CURL_EXIT_MAP[exit_code]
        return mapped_status, mapped_reason

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
        try:
            match = re.search(str(pattern), haystack, re.IGNORECASE)
        except re.error:
            continue
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
    if fixed_version:
        # fixed_version may be slash-separated for multi-branch products
        # (e.g. "7.4.17 / 7.13.7 / 7.18.1" for Confluence).  For each branch
        # fix, check whether the detected version is in the same major.minor
        # branch AND is >= that branch's fix.  If so, the installed version is
        # patched.  If no branch matched, fall through to a simple global
        # comparison against the highest listed fix.
        branch_fixes = [v.strip() for v in str(fixed_version).split("/") if v.strip()]
        for branch_fix in branch_fixes:
            if _same_version_branch(extracted_version, branch_fix):
                if _compare_versions(extracted_version, branch_fix) >= 0:
                    return "not_validated", f"detected_version={extracted_version}"
                # Same branch but older than the fix — confirmed vulnerable
                return "validated", f"detected_version={extracted_version}"
        # No branch matched (version outside every listed fix branch); compare
        # against the last (highest) listed fix as a fallback.
        if _compare_versions(extracted_version, branch_fixes[-1]) >= 0:
            return "not_validated", f"detected_version={extracted_version}"

    return "not_validated", f"detected_version={extracted_version}"


def _same_version_branch(detected: str, fixed: str, depth: int = 2) -> bool:
    """Return True if detected and fixed share the same major.minor (or major.update) branch.

    Uses the first `depth` tokenized components for the comparison so that
    e.g. "7.4.16" and "7.4.17" are in the same branch, while "7.4.16" and
    "7.13.7" are not.
    """
    d_parts = _tokenize_version(detected)
    f_parts = _tokenize_version(fixed)
    n = min(depth, min(len(d_parts), len(f_parts)))
    return n > 0 and all(d_parts[i] == f_parts[i] for i in range(n))


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


def get_scan_coverage(
    db_path: Path,
    scan_path: Path,
    project_name: str | None = None,
    min_severity: int | None = None,
    include_informational: bool = True,
) -> dict[str, object]:
    """Return coverage statistics for a scan file against the loaded playbooks.

    Returned dict keys
    ------------------
    total_plugins       int  — distinct plugin IDs in the scan
    total_targets       int  — total host:port findings
    has_playbook        int  — plugins with a playbook
    no_playbook         int  — plugins without a playbook
    coverage_pct        float
    pre_validatable     int  — targets already conclusive from plugin_output alone
    already_validated   int  — targets with a stored 'validated' result for this project
    already_not_validated int
    already_inconclusive  int
    not_yet_run         int  — targets in scan with playbook but no DB result yet
    per_plugin          list[dict] — one entry per plugin with playbook
    """
    from nessus_parser.services.playbooks import get_playbook, list_playbook_plugin_ids
    from nessus_parser.services.scans import (
        list_scan_plugin_ids,
        load_scan_targets,
    )

    scan_plugin_ids = list_scan_plugin_ids(
        scan_path,
        include_informational=include_informational,
        min_severity=min_severity,
    )
    playbook_ids = set(list_playbook_plugin_ids(db_path))
    existing_results = get_project_latest_results(db_path, project_name or "default")

    total_targets = 0
    pre_validatable = 0
    already: dict[str, int] = {"validated": 0, "not_validated": 0, "inconclusive": 0}
    not_yet_run = 0
    per_plugin: list[dict] = []

    has_playbook_ids = [pid for pid in scan_plugin_ids if pid in playbook_ids]
    no_playbook_ids  = [pid for pid in scan_plugin_ids if pid not in playbook_ids]

    for plugin_id in has_playbook_ids:
        scan_data = load_scan_targets(scan_path, plugin_id)
        if scan_data is None:
            continue
        playbook = get_playbook(db_path, plugin_id)
        plugin_targets = list(scan_data["targets"])
        plugin_pre = 0
        plugin_done: dict[str, int] = {"validated": 0, "not_validated": 0, "inconclusive": 0, "other": 0}
        plugin_pending = 0

        for t in plugin_targets:
            total_targets += 1
            key = (plugin_id, str(t["host"]), t["port"])
            db_status = existing_results.get(key)

            if db_status in already:
                already[db_status] += 1
                plugin_done[db_status] = plugin_done.get(db_status, 0) + 1
            elif db_status:
                plugin_done["other"] = plugin_done.get("other", 0) + 1
            else:
                not_yet_run += 1
                plugin_pending += 1

            po = t.get("plugin_output")
            if po and playbook:
                pre_status, _ = _derive_status(playbook, po.strip(), "", exit_code=None)
                if pre_status in ("validated", "not_validated"):
                    plugin_pre += 1
                    pre_validatable += 1

        per_plugin.append({
            "plugin_id": plugin_id,
            "plugin_name": str(scan_data["plugin_name"]),
            "severity": scan_data.get("severity"),
            "targets": len(plugin_targets),
            "pre_validatable": plugin_pre,
            "done": plugin_done,
            "pending": plugin_pending,
        })

    total_plugins = len(scan_plugin_ids)
    has_playbook  = len(has_playbook_ids)
    coverage_pct  = (has_playbook / total_plugins * 100) if total_plugins else 0.0

    return {
        "total_plugins": total_plugins,
        "total_targets": total_targets,
        "has_playbook": has_playbook,
        "no_playbook": len(no_playbook_ids),
        "no_playbook_ids": no_playbook_ids,
        "coverage_pct": coverage_pct,
        "pre_validatable": pre_validatable,
        "already_validated": already["validated"],
        "already_not_validated": already["not_validated"],
        "already_inconclusive": already["inconclusive"],
        "not_yet_run": not_yet_run,
        "per_plugin": per_plugin,
    }
