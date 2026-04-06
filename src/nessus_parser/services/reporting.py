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
    get_project_latest_results,
    get_validation_summary,
    list_validated_plugin_ids,
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
    plugin_ids = list_validated_plugin_ids(db_path, project_name=project_name)
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

    display_project = project_name if project_name and project_name != "default" else None
    report_title = f"Nessus Parser Report \u2014 {html.escape(display_project)}" if display_project else "Nessus Parser Report"
    # Escape "</" so "</script>" in tool output cannot break the embedded script tag
    safe_json = json.dumps(dataset).replace("</", "<\\/")
    output_path.write_text(
        _REPORT_TEMPLATE.read_text()
        .replace("DATA_JSON_PLACEHOLDER", safe_json)
        .replace("REPORT_TITLE_PLACEHOLDER", report_title)
    )
    return output_path


# ---------------------------------------------------------------------------
# Diff / delta report
# ---------------------------------------------------------------------------

_CONCLUSIVE = {"validated", "not_validated"}


def build_diff_report(
    db_path: Path,
    before_project: str,
    after_project: str,
    output_path: Path | None = None,
) -> str:
    """Compare two projects and return a terminal-formatted diff summary.

    If *output_path* is given, also writes a self-contained HTML diff report.

    Categories
    ----------
    remediated       validated → not_validated  (client patched it)
    regressed        not_validated → validated  (new or reintroduced)
    still_vulnerable validated  → validated     (unpatched)
    still_clean      not_validated → not_validated
    new              only in after project (not in before)
    dropped          only in before project (rescoped / host removed)
    inconclusive     at least one side is inconclusive / error / skipped
    """
    before = get_project_latest_results(db_path, before_project)
    after = get_project_latest_results(db_path, after_project)

    all_keys = set(before) | set(after)

    buckets: dict[str, list[dict]] = {
        "remediated": [],
        "regressed": [],
        "still_vulnerable": [],
        "still_clean": [],
        "new": [],
        "dropped": [],
        "inconclusive": [],
    }

    for key in sorted(all_keys):
        plugin_id, host, port = key
        b_status = before.get(key)
        a_status = after.get(key)
        entry = {
            "plugin_id": plugin_id,
            "plugin_name": _plugin_name(db_path, plugin_id),
            "host": host,
            "port": port,
            "before": b_status or "-",
            "after": a_status or "-",
        }
        if b_status is None:
            buckets["new"].append(entry)
        elif a_status is None:
            buckets["dropped"].append(entry)
        elif b_status == "validated" and a_status == "not_validated":
            buckets["remediated"].append(entry)
        elif b_status == "not_validated" and a_status == "validated":
            buckets["regressed"].append(entry)
        elif b_status == "validated" and a_status == "validated":
            buckets["still_vulnerable"].append(entry)
        elif b_status == "not_validated" and a_status == "not_validated":
            buckets["still_clean"].append(entry)
        else:
            buckets["inconclusive"].append(entry)

    lines = _format_diff_terminal(before_project, after_project, buckets)
    result = "\n".join(lines)

    if output_path is not None:
        _write_diff_html(before_project, after_project, buckets, output_path)

    return result


def _plugin_name(db_path: Path, plugin_id: int) -> str:
    plugin = get_plugin_details(db_path, plugin_id)
    return plugin[1] if plugin else str(plugin_id)


def _format_diff_terminal(
    before_project: str,
    after_project: str,
    buckets: dict[str, list[dict]],
) -> list[str]:
    remediated     = buckets["remediated"]
    regressed      = buckets["regressed"]
    still_vuln     = buckets["still_vulnerable"]
    still_clean    = buckets["still_clean"]
    new_findings   = buckets["new"]
    dropped        = buckets["dropped"]
    inconclusive   = buckets["inconclusive"]

    total_before = len(remediated) + len(regressed) + len(still_vuln) + len(still_clean) + len(dropped) + len(inconclusive)
    total_after  = len(remediated) + len(regressed) + len(still_vuln) + len(still_clean) + len(new_findings) + len(inconclusive)

    lines = [
        "",
        "=" * 70,
        f"  DIFF REPORT  {before_project}  →  {after_project}",
        "=" * 70,
        f"  Before: {total_before} findings   After: {total_after} findings",
        "",
        f"  ✓  Remediated       {len(remediated):>5}  (was vulnerable, now clean)",
        f"  ✗  Regressed        {len(regressed):>5}  (was clean, now vulnerable)",
        f"  ⚠  Still vulnerable {len(still_vuln):>5}  (unpatched)",
        f"  ·  Still clean      {len(still_clean):>5}",
        f"  +  New findings     {len(new_findings):>5}  (only in after)",
        f"  -  Dropped          {len(dropped):>5}  (only in before)",
        f"  ?  Inconclusive     {len(inconclusive):>5}",
        "=" * 70,
    ]

    def _rows(entries: list[dict], limit: int = 50) -> list[str]:
        out = []
        for e in entries[:limit]:
            port_str = f":{e['port']}" if e["port"] is not None else ""
            out.append(
                f"    [{e['plugin_id']}] {e['host']}{port_str}  "
                f"{e['before']} → {e['after']}  {e['plugin_name']}"
            )
        if len(entries) > limit:
            out.append(f"    ... {len(entries) - limit} more")
        return out

    if remediated:
        lines += ["", f"REMEDIATED ({len(remediated)}):"] + _rows(remediated)
    if regressed:
        lines += ["", f"REGRESSED ({len(regressed)}):"] + _rows(regressed)
    if still_vuln:
        lines += ["", f"STILL VULNERABLE ({len(still_vuln)}):"] + _rows(still_vuln)
    if new_findings:
        lines += ["", f"NEW ({len(new_findings)}):"] + _rows(new_findings)
    if dropped:
        lines += ["", f"DROPPED ({len(dropped)}):"] + _rows(dropped)
    if inconclusive:
        lines += ["", f"INCONCLUSIVE ({len(inconclusive)}):"] + _rows(inconclusive)

    return lines


def _write_diff_html(
    before_project: str,
    after_project: str,
    buckets: dict[str, list[dict]],
    output_path: Path,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    def _rows_html(entries: list[dict]) -> str:
        if not entries:
            return "<tr><td colspan='5' style='color:var(--text-dim);font-style:italic'>None</td></tr>"
        rows = []
        for e in entries:
            port_str = str(e["port"]) if e["port"] is not None else "-"
            rows.append(
                f"<tr>"
                f"<td>{html.escape(str(e['plugin_id']))}</td>"
                f"<td>{html.escape(e['plugin_name'])}</td>"
                f"<td>{html.escape(e['host'])}</td>"
                f"<td>{html.escape(port_str)}</td>"
                f"<td><span class='before'>{html.escape(e['before'])}</span>"
                f" → <span class='after-{html.escape(e['after'])}'>{html.escape(e['after'])}</span></td>"
                f"</tr>"
            )
        return "\n".join(rows)

    def _section(title: str, css_class: str, entries: list[dict]) -> str:
        count = len(entries)
        return f"""
        <section class="diff-section {css_class}">
          <h2>{html.escape(title)} <span class="count">{count}</span></h2>
          <table>
            <thead><tr><th>Plugin ID</th><th>Finding</th><th>Host</th><th>Port</th><th>Status Change</th></tr></thead>
            <tbody>{_rows_html(entries)}</tbody>
          </table>
        </section>"""

    remediated  = buckets["remediated"]
    regressed   = buckets["regressed"]
    still_vuln  = buckets["still_vulnerable"]
    still_clean = buckets["still_clean"]
    new_f       = buckets["new"]
    dropped     = buckets["dropped"]
    inconc      = buckets["inconclusive"]

    body = (
        _section("Remediated", "sec-remediated", remediated)
        + _section("Regressed", "sec-regressed", regressed)
        + _section("Still Vulnerable", "sec-still-vuln", still_vuln)
        + _section("New Findings", "sec-new", new_f)
        + _section("Dropped", "sec-dropped", dropped)
        + _section("Still Clean", "sec-still-clean", still_clean)
        + _section("Inconclusive", "sec-inconclusive", inconc)
    )

    title = html.escape(f"Diff Report — {before_project} → {after_project}")
    output_path.write_text(f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{title}</title>
  <style>
    :root {{
      --bg:#0d1117;--bg-card:#161b22;--border:#30363d;--text:#c9d1d9;--text-dim:#8b949e;
      --accent:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;--orange:#f0883e;
    }}
    body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;padding:1.5rem 2rem;background:var(--bg);color:var(--text);line-height:1.5}}
    h1{{font-size:1.5rem;margin-bottom:.25rem}}
    .subtitle{{color:var(--text-dim);font-size:.9rem;margin-bottom:1.5rem}}
    .summary{{display:flex;flex-wrap:wrap;gap:.75rem;margin-bottom:2rem}}
    .card{{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:.75rem 1.25rem;min-width:130px;text-align:center}}
    .card .val{{font-size:1.8rem;font-weight:700;line-height:1.2}}
    .card .lbl{{font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:var(--text-dim)}}
    .card.remediated .val{{color:var(--green)}}
    .card.regressed .val{{color:var(--red)}}
    .card.still-vuln .val{{color:var(--orange)}}
    .card.new .val{{color:var(--yellow)}}
    .card.other .val{{color:var(--text-dim)}}
    .diff-section{{margin-bottom:2rem}}
    .diff-section h2{{font-size:1rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;border-bottom:2px solid var(--border);padding-bottom:.4rem;margin-bottom:.5rem}}
    .count{{font-size:.85rem;font-weight:400;color:var(--text-dim);margin-left:.5rem}}
    .sec-remediated h2{{color:var(--green);border-color:var(--green)}}
    .sec-regressed h2{{color:var(--red);border-color:var(--red)}}
    .sec-still-vuln h2{{color:var(--orange);border-color:var(--orange)}}
    .sec-new h2{{color:var(--yellow);border-color:var(--yellow)}}
    .sec-dropped h2,.sec-still-clean h2,.sec-inconclusive h2{{color:var(--text-dim)}}
    table{{width:100%;border-collapse:collapse;font-size:.8rem}}
    th,td{{border:1px solid var(--border);padding:.35rem .6rem;text-align:left;vertical-align:top}}
    th{{background:rgba(110,118,129,.1);font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:var(--text-dim)}}
    .after-validated{{color:var(--red);font-weight:600}}
    .after-not_validated{{color:var(--green);font-weight:600}}
    .after-inconclusive{{color:var(--yellow)}}
    .before{{color:var(--text-dim)}}
  </style>
</head>
<body>
  <h1>{title}</h1>
  <p class="subtitle">Before: <strong>{html.escape(before_project)}</strong> &nbsp;→&nbsp; After: <strong>{html.escape(after_project)}</strong></p>
  <div class="summary">
    <div class="card remediated"><div class="val">{len(remediated)}</div><div class="lbl">Remediated</div></div>
    <div class="card regressed"><div class="val">{len(regressed)}</div><div class="lbl">Regressed</div></div>
    <div class="card still-vuln"><div class="val">{len(still_vuln)}</div><div class="lbl">Still Vulnerable</div></div>
    <div class="card new"><div class="val">{len(new_f)}</div><div class="lbl">New Findings</div></div>
    <div class="card other"><div class="val">{len(dropped)}</div><div class="lbl">Dropped</div></div>
    <div class="card other"><div class="val">{len(inconc)}</div><div class="lbl">Inconclusive</div></div>
  </div>
  {body}
</body>
</html>""")

