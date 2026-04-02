from __future__ import annotations

import csv
import html
import json
import re
from pathlib import Path

_REPORT_TEMPLATE = Path(__file__).parent.parent / "templates" / "report.html"

from nessus_parser.services.playbooks import get_playbook, list_playbook_plugin_ids
from nessus_parser.services.scans import get_plugin_details
from nessus_parser.services.validation import (
    get_latest_validation_results,
    get_validation_summary,
)


def _extract_underlying_items(trigger: str, stdout: str) -> list[str]:
    """For synthetic validation markers, extract the real items they represent.

    e.g. 'cbc_enabled' → actual CBC cipher names from the nmap output.
    Returns empty list if the trigger is not a known synthetic marker.
    """
    t = trigger.lower()
    if "cbc" in t:
        # Extract the specific CBC cipher algorithm names from nmap ssh2-enum-algos output
        found = re.findall(
            r'\b((?:aes(?:128|192|256)|3des|blowfish|cast128)-cbc)\b',
            stdout,
            re.IGNORECASE,
        )
        seen: set[str] = set()
        return [c.lower() for c in found if not (c.lower() in seen or seen.add(c.lower()))]  # type: ignore[func-returns-value]
    return []


def _extract_highlight_terms(stdout: str, playbook: dict) -> list[str]:
    """Return the specific strings in stdout that justify the validated verdict.

    Only includes what actually matched — version pattern captures and
    validated_if literal strings — so the report highlights precisely the
    evidence, nothing else.  Synthetic markers (e.g. CBC_ENABLED) are
    expanded into the actual underlying items they represent.
    """
    terms: list[str] = []
    stdout_lower = stdout.lower()

    version_rule = playbook.get("version_rule") or {}
    for pat in version_rule.get("version_patterns", []):
        try:
            m = re.search(pat, stdout, re.IGNORECASE)
            if m:
                term = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                if term:
                    terms.append(term)
        except re.error:
            pass

    for term in playbook.get("validated_if", []):
        if not term or term.lower() not in stdout_lower:
            continue
        underlying = _extract_underlying_items(term, stdout)
        if underlying:
            terms.extend(underlying)
        else:
            terms.append(term)

    seen2: set[str] = set()
    return [t for t in terms if not (t in seen2 or seen2.add(t))]  # type: ignore[func-returns-value]


def _relevant_lines(stdout: str, highlight_terms: list[str]) -> list[str]:
    """Return only the lines from stdout that contain at least one highlight term."""
    if not highlight_terms:
        return []
    lower_terms = [t.lower() for t in highlight_terms]
    return [
        line for line in stdout.splitlines()
        if any(lt in line.lower() for lt in lower_terms)
    ]


def build_plugin_report(db_path: Path, plugin_id: int, project_name: str | None = None) -> str:
    plugin = get_plugin_details(db_path, plugin_id)
    if plugin is None:
        return f"Plugin {plugin_id} not found in local database"

    lines = [
        f"plugin_id: {plugin[0]}",
        f"name: {plugin[1]}",
    ]

    summary = get_validation_summary(db_path, plugin_id, project_name=project_name)
    if not summary:
        lines.append("results: none")
        return "\n".join(lines)

    lines.append("summary:")
    for status, count in summary:
        lines.append(f"status\t{status}\tcount={count}")

    latest_results = get_latest_validation_results(db_path, plugin_id, project_name=project_name)
    lines.append(f"latest_results: {len(latest_results)}")
    for host, port, status, reason, analyst_note, command, executed_at, source in latest_results[:50]:
        lines.append(
            f"result\t{host}\tport={port}\tstatus={status}\treason={reason or '-'}\tnote={analyst_note or '-'}\tsource={source}\tat={executed_at}\tcommand={command}"
        )
    if len(latest_results) > 50:
        lines.append(f"... truncated {len(latest_results) - 50} additional results")
    return "\n".join(lines)


def export_plugin_report_csv(db_path: Path, plugin_id: int, output_path: Path, project_name: str | None = None) -> Path:
    latest_results = get_latest_validation_results(db_path, plugin_id, project_name=project_name)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["host", "port", "status", "reason", "analyst_note", "source", "executed_at", "command"])
        for row in latest_results:
            host, port, status, reason, analyst_note, command, executed_at, source = row[:8]
            writer.writerow([host, port, status, reason or "", analyst_note or "", source, executed_at, command])
    return output_path


def export_all_reports_csv(db_path: Path, output_path: Path, project_name: str | None = None) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plugin_ids = list_playbook_plugin_ids(db_path)
    with output_path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "plugin_id",
                "plugin_name",
                "host",
                "port",
                "status",
                "reason",
                "analyst_note",
                "source",
                "executed_at",
                "command",
            ]
        )
        for plugin_id in plugin_ids:
            plugin = get_plugin_details(db_path, plugin_id)
            plugin_name = plugin[1] if plugin is not None else ""
            for host, port, status, reason, analyst_note, command, executed_at, source in get_latest_validation_results(db_path, plugin_id, project_name=project_name):
                writer.writerow(
                    [
                        plugin_id,
                        plugin_name,
                        host,
                        port,
                        status,
                        reason or "",
                        analyst_note or "",
                        source,
                        executed_at,
                        command,
                    ]
                )
    return output_path


def export_all_reports_html(db_path: Path, output_path: Path, project_name: str | None = None) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plugin_ids = list_playbook_plugin_ids(db_path)
    dataset: list[dict[str, object]] = []

    for plugin_id in plugin_ids:
        plugin = get_plugin_details(db_path, plugin_id)
        plugin_name = plugin[1] if plugin is not None else str(plugin_id)
        plugin_summary = "-"
        plugin_severity = "-"
        if plugin is not None:
            plugin_summary = plugin[4] or plugin[5] or plugin[6] or "-"
            plugin_severity = plugin[3] or "-"
        summary = get_validation_summary(db_path, plugin_id, project_name=project_name)
        latest_results = get_latest_validation_results(db_path, plugin_id, project_name=project_name)

        if not latest_results:
            continue

        # Pick the first validated result as the evidence sample
        validated_sample = None
        for row in latest_results:
            if row[2] == "validated":
                stdout = (row[8] or "").strip()
                stderr = (row[9] or "").strip()
                playbook = get_playbook(db_path, plugin_id)
                output = stdout or stderr
                highlight_terms = (
                    _extract_highlight_terms(output, playbook)
                    if playbook else []
                )
                relevant = _relevant_lines(output, highlight_terms)
                validated_sample = {
                    "host": row[0],
                    "port": row[1],
                    "command": row[5],
                    "stdout": output,
                    "relevant_lines": relevant,
                    "highlight_terms": highlight_terms,
                }
                break

        dataset.append(
            {
                "plugin_id": plugin_id,
                "plugin_name": plugin_name,
                "plugin_summary": plugin_summary,
                "plugin_severity": plugin_severity,
                "summary": [{"status": status, "count": count} for status, count in summary],
                "validated_sample": validated_sample,
                "results": [
                    {
                        "host": row[0],
                        "port": row[1],
                        "status": row[2],
                        "reason": row[3] or "-",
                        "analyst_note": row[4] or "-",
                        "command": row[5],
                        "executed_at": row[6],
                        "source": row[7],
                    }
                    for row in latest_results
                ],
            }
        )

    report_title = f"Nessus Parser Report \u2014 {html.escape(project_name)}" if project_name else "Nessus Parser Report"
    # Escape "</" so "</script>" in tool output cannot break the embedded script tag
    safe_json = json.dumps(dataset).replace("</", "<\\/")
    output_path.write_text(
        _REPORT_TEMPLATE.read_text()
        .replace("DATA_JSON_PLACEHOLDER", safe_json)
        .replace("REPORT_TITLE_PLACEHOLDER", report_title)
    )
    return output_path
