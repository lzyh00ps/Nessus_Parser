from __future__ import annotations

import argparse
import sys
from pathlib import Path

from nessus_parser.core.paths import DB_PATH
from nessus_parser.db.schema import initialize_database
from nessus_parser.services.playbooks import (
    audit_playbooks,
    create_playbook_templates,
    create_playbook_template,
    get_playbook_summary,
    import_playbook,
    list_playbook_plugin_ids,
    list_playbooks,
)
from nessus_parser.services.plugins import (
    import_plugins_from_nasl_dir,
    import_plugins_from_zip,
    import_plugins_json,
    search_plugins,
)
from nessus_parser.services.privacy import sanitize_database
from nessus_parser.services.reporting import (
    build_diff_report,
    build_plugin_report,
    export_all_reports_csv,
    export_all_reports_html,
    export_plugin_report_csv,
)
from nessus_parser.services.scans import (
    get_finding_targets,
    list_finding_plugin_ids,
    list_scan_plugin_ids,
    get_plugin_details,
    import_nessus_scan,
    list_findings,
    list_plugins,
)
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
    yellow,
)
from nessus_parser.services.validation import (
    build_summary_banner,
    get_matching_scan_playbook_ids,
    list_projects,
    persist_no_playbook_findings,
    validate_plugin,
    validate_scan_file,
    validate_scan_file_all,
)
from nessus_parser.services.validation import (
    bulk_override,
    get_latest_validation_results,
    get_scan_coverage,
    get_validation_summary,
    override_result,
)


_SEVERITY_MAP = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Commands that write data — warn loudly when falling back to "default" project.
_WRITE_COMMANDS = {"import-scan", "validate", "validate-all", "override-result", "bulk-override"}


def _normalize_project(raw: str) -> str:
    """Return a clean, consistent project name.

    Rules: lowercase, strip whitespace, replace spaces and hyphens with
    underscores.  Prints a notice when the name was changed so the analyst
    always sees exactly what name was stored.
    """
    normalized = raw.strip().lower().replace(" ", "_").replace("-", "_")
    if normalized != raw:
        print(
            f"{bright_yellow('NOTICE:')} Project name normalised: '{raw}' → '{normalized}'",
            file=sys.stderr,
        )
    return normalized


def _resolve_project(raw: str | None, command: str) -> str:
    """Normalize the project name and warn when falling back to 'default'.

    Falls back to 'default' only when no -p flag was supplied.  Emits a
    visible warning on write commands so analysts are never silently mixing
    engagement data into the shared default bucket.
    """
    if raw:
        return _normalize_project(raw)
    if command in _WRITE_COMMANDS:
        print(
            f"\n{bright_yellow('WARNING:')} No project specified — using \"default\".\n"
            f"         Use {bold('-p <name>')} for real engagements, e.g.:\n"
            f"         {dim('nessus-parser import-scan scan.nessus --store-findings -p clientname_20260406')}\n",
            file=sys.stderr,
        )
    return "default"


def _project_finding_count(db_path: Path, project_name: str) -> int:
    """Return the number of findings already stored under *project_name*."""
    from nessus_parser.db.connection import connect  # local import to avoid circular deps
    conn = connect(db_path)
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE project_name = ?", (project_name,)
        ).fetchone()
        return row[0] if row else 0
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(prog="nessus-parser")
    parser.add_argument("-f", "--scan-file", type=Path)
    parser.add_argument("--validate", dest="validate_from_file", action="store_true")
    parser.add_argument("--validate-all", dest="validate_all_from_file", action="store_true")
    parser.add_argument("--plugin-id", dest="plugin_id_flag", type=int)
    parser.add_argument("--plugin-ids", dest="plugin_ids_filter")
    parser.add_argument("--plugin-limit", dest="plugin_limit", type=int)
    parser.add_argument("--include-informational", action="store_true", default=True)
    parser.add_argument(
        "--min-severity",
        dest="min_severity",
        choices=["low", "medium", "high", "critical"],
        help="Only process findings at or above this severity level (low=1, medium=2, high=3, critical=4)",
    )
    parser.add_argument("--persist-results", action="store_true", help=argparse.SUPPRESS)  # legacy no-op
    parser.add_argument("--dry-run", dest="dry_run", action="store_true",
                        help="Run validation without saving results to the database")
    parser.add_argument("--output", dest="output_path", type=Path)
    parser.add_argument("-o", "--html-report", dest="html_report_path", type=Path,
                        help="Generate an HTML report to this path after validation completes")
    parser.add_argument("-p", "--project", dest="project", default=None)

    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("init")

    import_scan = subparsers.add_parser("import-scan")
    import_scan.add_argument("scan_path", type=Path)
    import_scan.add_argument("--store-findings", action="store_true")
    import_scan.add_argument("-p", "--project", dest="project", default=None)

    import_plugins = subparsers.add_parser("import-plugins")
    import_plugins.add_argument("plugin_file", type=Path)

    import_plugins_nasl = subparsers.add_parser("import-plugins-nasl")
    import_plugins_nasl.add_argument("plugin_dir", type=Path)

    import_plugins_zip = subparsers.add_parser("import-plugins-zip")
    import_plugins_zip.add_argument("zip_path", type=Path)

    import_playbook_cmd = subparsers.add_parser("import-playbook")
    import_playbook_cmd.add_argument("playbook_path", type=Path)

    subparsers.add_parser("list-findings")
    subparsers.add_parser("list-plugins")

    search_plugins_cmd = subparsers.add_parser("search-plugins")
    search_plugins_cmd.add_argument("--plugin-id", type=int)
    search_plugins_cmd.add_argument("--name-contains")
    search_plugins_cmd.add_argument("--family")
    search_plugins_cmd.add_argument("--limit", type=int, default=50)

    subparsers.add_parser("list-playbooks")

    audit_playbooks_cmd = subparsers.add_parser(
        "audit-playbooks",
        help="Audit imported playbooks for missing validation criteria",
    )
    audit_playbooks_cmd.add_argument(
        "--no-conclusive-only",
        dest="no_conclusive_only",
        action="store_true",
        help="Only show playbooks that cannot produce a conclusive result",
    )

    show_finding = subparsers.add_parser("show-finding")
    show_finding.add_argument("--plugin-id", type=int, required=True)

    create_playbook_cmd = subparsers.add_parser("create-playbook")
    create_playbook_cmd.add_argument("--plugin-id", type=int, required=True)
    create_playbook_cmd.add_argument("--output", type=Path)

    create_playbooks_cmd = subparsers.add_parser("create-playbooks")
    create_playbooks_cmd.add_argument("--name-contains")
    create_playbooks_cmd.add_argument("--family")
    create_playbooks_cmd.add_argument("--limit", type=int, default=20)
    create_playbooks_cmd.add_argument("--output-dir", type=Path)
    create_playbooks_cmd.add_argument("--overwrite", action="store_true")

    validate = subparsers.add_parser("validate")
    validate.add_argument("--plugin-id", type=int, required=True)
    validate.add_argument("-p", "--project", dest="project", default=None)

    validate_all = subparsers.add_parser("validate-all")
    validate_all.add_argument("-p", "--project", dest="project", default=None)
    validate_all.add_argument("-o", "--html-report", dest="html_report_path", type=Path,
                              help="Generate an HTML report to this path after validation completes")
    validate_all.add_argument(
        "--min-severity",
        dest="min_severity",
        choices=["low", "medium", "high", "critical"],
        help="Only validate findings at or above this severity level",
    )
    validate_all.add_argument(
        "--include-informational",
        dest="include_informational",
        action="store_true",
        default=True,
    )

    sanitize_db = subparsers.add_parser("sanitize-db")
    sanitize_db.add_argument("-p", "--project", dest="project", default=None)

    subparsers.add_parser("list-projects")

    show_results = subparsers.add_parser("show-results")
    show_results.add_argument("--plugin-id", type=int, required=True)
    show_results.add_argument("-p", "--project", dest="project", default=None)

    report = subparsers.add_parser("report")
    report.add_argument("--plugin-id", type=int, required=True)
    report.add_argument("--output", type=Path)
    report.add_argument("-p", "--project", dest="project", default=None)

    report_all = subparsers.add_parser("report-all")
    report_all.add_argument("--output", type=Path, required=True)
    report_all.add_argument("-p", "--project", dest="project", default=None)

    report_html = subparsers.add_parser("report-html")
    report_html.add_argument("--output", type=Path, required=True)
    report_html.add_argument("-p", "--project", dest="project", default=None)

    diff_projects = subparsers.add_parser(
        "diff-projects",
        help="Compare validation results between two projects (before vs after patching)",
    )
    diff_projects.add_argument("--before", required=True, help="Project name for the baseline scan")
    diff_projects.add_argument("--after", required=True, help="Project name for the re-test scan")
    diff_projects.add_argument("-o", "--output", dest="output_path", type=Path,
                               help="Write an HTML diff report to this path")

    override = subparsers.add_parser("override-result")
    override.add_argument("--plugin-id", type=int, required=True)
    override.add_argument("--host", required=True)
    override.add_argument("--port", type=int, required=True)
    override.add_argument("--status", required=True)
    override.add_argument("--reason")
    override.add_argument("--note")
    override.add_argument("-p", "--project", dest="project", default=None)

    bulk_override_cmd = subparsers.add_parser(
        "bulk-override",
        help="Apply manual overrides from a CSV file (columns: plugin_id,host,port,status,reason,note)",
    )
    bulk_override_cmd.add_argument("--csv", dest="csv_path", type=Path, required=True,
                                   help="Path to CSV file with override rows")
    bulk_override_cmd.add_argument("-p", "--project", dest="project", default=None)

    coverage_cmd = subparsers.add_parser(
        "coverage",
        help="Show playbook coverage and pre-validation estimate for a scan file",
    )
    coverage_cmd.add_argument("-f", "--scan-file", dest="scan_file", type=Path, required=True)
    coverage_cmd.add_argument("-p", "--project", dest="project", default=None)
    coverage_cmd.add_argument(
        "--min-severity",
        dest="min_severity",
        choices=["low", "medium", "high", "critical"],
    )
    coverage_cmd.add_argument("--include-informational", dest="include_informational",
                               action="store_true", default=True)
    coverage_cmd.add_argument("--verbose", action="store_true",
                               help="Show per-plugin breakdown")

    args = parser.parse_args()

    if args.scan_file and (args.validate_from_file or args.validate_all_from_file):
        initialize_database(DB_PATH)
        project_name = _resolve_project(args.project, "validate-all")
        min_severity = _SEVERITY_MAP.get(args.min_severity) if args.min_severity else None
        if args.validate_from_file:
            if args.plugin_id_flag is None:
                parser.error("--plugin-id is required with -f/--scan-file --validate")
            output = validate_scan_file(
                DB_PATH,
                args.scan_file,
                args.plugin_id_flag,
                persist_results=not args.dry_run,
                project_name=project_name,
            )
        else:
            selected_plugin_ids = list_playbook_plugin_ids(DB_PATH)
            if args.plugin_ids_filter:
                requested_ids = [
                    int(item.strip())
                    for item in args.plugin_ids_filter.split(",")
                    if item.strip()
                ]
                selected_plugin_ids = [
                    plugin_id for plugin_id in selected_plugin_ids if plugin_id in requested_ids
                ]
            all_scan_plugin_ids = set(
                list_scan_plugin_ids(
                    args.scan_file,
                    include_informational=args.include_informational,
                    min_severity=min_severity,
                )
            )
            matching_plugin_ids = get_matching_scan_playbook_ids(
                DB_PATH,
                args.scan_file,
                selected_plugin_ids,
                include_informational=args.include_informational,
                min_severity=min_severity,
            )
            if args.plugin_limit is not None:
                matching_plugin_ids = matching_plugin_ids[:args.plugin_limit]
            # Record no_playbook status for scan findings that have no playbook
            unmatched_plugin_ids = sorted(all_scan_plugin_ids - set(matching_plugin_ids))
            if unmatched_plugin_ids:
                no_pb_recorded = persist_no_playbook_findings(
                    DB_PATH, args.scan_file, unmatched_plugin_ids, project_name=project_name
                )
                print(
                    f"{dim(f'  {len(unmatched_plugin_ids)} plugins have no playbook — recorded {no_pb_recorded} host/port entries as no_playbook')}",
                    file=sys.stderr,
                )
            if not matching_plugin_ids:
                output = f"No matching playbooks found for plugins present in {args.scan_file}"
            else:
                total = len(matching_plugin_ids)
                playbook_names = {pid: name for pid, name, _ in list_playbooks(DB_PATH)}
                reports: list[str] = []
                agg_status: dict[str, int] = {}
                agg_targets = 0
                for index, plugin_id in enumerate(matching_plugin_ids, start=1):
                    name = playbook_names.get(plugin_id, "")
                    label = f"{plugin_id} ({name})" if name else str(plugin_id)
                    pct = index / total * 100
                    print(
                        f"{bright_cyan(f'[{index}/{total}]')} {dim(f'({pct:.0f}%)')} validating {bold(label)}",
                        file=sys.stderr,
                        flush=True,
                    )
                    report = validate_scan_file(
                        DB_PATH,
                        args.scan_file,
                        plugin_id,
                        persist_results=True,
                        project_name=project_name,
                    )
                    reports.append(report)
                    # Collect aggregate stats from validation results
                    summary = get_validation_summary(DB_PATH, plugin_id, project_name=project_name)
                    for status, count in summary:
                        agg_status[status] = agg_status.get(status, 0) + count
                        agg_targets += count
                output = "\n\n".join(reports)
                output += build_summary_banner(total, agg_status, agg_targets)
        if args.output_path is not None:
            args.output_path.parent.mkdir(parents=True, exist_ok=True)
            args.output_path.write_text(output + "\n")
            print(f"Wrote validation output to {args.output_path}")
        else:
            print(output)
        if getattr(args, "html_report_path", None) is not None:
            html_path = export_all_reports_html(DB_PATH, args.html_report_path, project_name=project_name)
            print(f"Wrote HTML report to {html_path}")
        return

    if args.command is None:
        parser.error("a command is required unless using -f/--scan-file --validate or --validate-all")

    if args.command == "init":
        initialize_database(DB_PATH)
        print(f"Initialized database at {DB_PATH}")
        return

    initialize_database(DB_PATH)

    if args.command == "import-scan":
        project_name = _resolve_project(getattr(args, "project", None), "import-scan")
        if args.store_findings:
            existing_count = _project_finding_count(DB_PATH, project_name)
            if existing_count == 0:
                print(
                    f"{bright_cyan('INFO:')} Creating new project {bold(repr(project_name))}",
                    file=sys.stderr,
                )
            else:
                print(
                    f"{bright_cyan('INFO:')} Appending to existing project {bold(repr(project_name))} "
                    f"(currently {existing_count:,} findings)",
                    file=sys.stderr,
                )
        count = import_nessus_scan(DB_PATH, args.scan_path, store_findings=args.store_findings, project_name=project_name)
        if args.store_findings:
            print(f"Imported {count} plugin rows and stored findings from {args.scan_path} (project={project_name})")
        else:
            print(
                f"Imported {count} plugin rows from {args.scan_path} without storing host-level findings"
            )
        return

    if args.command == "import-plugins":
        count = import_plugins_json(DB_PATH, args.plugin_file)
        print(f"Imported {count} plugin records from {args.plugin_file}")
        return

    if args.command == "import-plugins-nasl":
        count = import_plugins_from_nasl_dir(DB_PATH, args.plugin_dir)
        print(f"Imported {count} plugin records from NASL directory {args.plugin_dir}")
        return

    if args.command == "import-plugins-zip":
        count = import_plugins_from_zip(DB_PATH, args.zip_path)
        print(f"Imported {count} plugin records from NASL ZIP {args.zip_path}")
        return

    if args.command == "import-playbook":
        import_playbook(DB_PATH, args.playbook_path)
        print(f"Imported playbook {args.playbook_path}")
        return

    if args.command == "list-findings":
        for plugin_id, plugin_name, affected_hosts, finding_rows in list_findings(DB_PATH):
            print(f"{plugin_id}\thosts={affected_hosts}\trows={finding_rows}\t{plugin_name}")
        return

    if args.command == "list-plugins":
        for plugin_id, plugin_name, family, severity in list_plugins(DB_PATH):
            print(f"{plugin_id}\tseverity={severity}\tfamily={family}\t{plugin_name}")
        return

    if args.command == "search-plugins":
        rows = search_plugins(
            DB_PATH,
            plugin_id=args.plugin_id,
            name_contains=args.name_contains,
            family=args.family,
            limit=args.limit,
        )
        for plugin_id, plugin_name, family, severity in rows:
            print(f"{plugin_id}\tseverity={severity}\tfamily={family}\t{plugin_name}")
        print(f"results={len(rows)}")
        return

    if args.command == "list-playbooks":
        for plugin_id, finding_name, source_path in list_playbooks(DB_PATH):
            print(f"{plugin_id}\t{finding_name}\t{source_path}")
        return

    if args.command == "audit-playbooks":
        entries = audit_playbooks(DB_PATH)
        if not entries:
            print("No playbooks found in local database")
            return

        if args.no_conclusive_only:
            entries = [e for e in entries if not e["conclusive"]]

        total = len(entries)
        conclusive_count = sum(1 for e in entries if e["conclusive"])
        no_conclusive_count = total - conclusive_count
        no_fallback_count = sum(1 for e in entries if not e["has_fallback_commands"])
        version_warning_count = sum(1 for e in entries if e.get("version_warning"))

        print(heavy_separator())
        print(bold(bright_cyan("  PLAYBOOK AUDIT")))
        print(heavy_separator())
        print(f"  {bold('Total playbooks:')}         {total}")
        print(f"  {bold('Conclusive criteria:')}     {green(str(conclusive_count))}")
        print(f"  {bold('No conclusive criteria:')}  {bright_red(str(no_conclusive_count))} — will always produce inconclusive/error results")
        print(f"  {bold('No fallback commands:')}    {yellow(str(no_fallback_count))}")
        if version_warning_count:
            print(f"  {bold('Version warnings:')}        {bright_yellow(str(version_warning_count))} — multi-branch fixed_version without affected_lt/lte")
        print(heavy_separator())

        for entry in entries:
            pid = entry["plugin_id"]
            name = entry["finding_name"]
            flags: list[str] = []
            if not entry["conclusive"]:
                flags.append(bright_red("NO_CONCLUSIVE_CRITERIA"))
            if not entry["has_fallback_commands"]:
                flags.append(yellow("NO_FALLBACK"))
            if not entry["has_not_validated_if"]:
                flags.append(dim("NO_FP_CRITERIA"))
            if entry.get("version_warning"):
                flags.append(bright_yellow(f"WARN:{entry['version_warning']}"))
            flag_str = "  ".join(flags) if flags else green("ok")
            print(f"  {bold(str(pid))}\t{dim(str(name)[:60])}\t{flag_str}")
        return

    if args.command == "show-finding":
        plugin = get_plugin_details(DB_PATH, args.plugin_id)
        if plugin is None:
            print(f"Plugin {args.plugin_id} not found in local database")
            return

        plugin_id, plugin_name, family, severity, synopsis, description, solution = plugin
        print(f"plugin_id: {plugin_id}")
        print(f"name: {plugin_name}")
        print(f"family: {family}")
        print(f"severity: {severity}")
        if synopsis:
            print(f"synopsis: {synopsis}")
        if description:
            print(f"description: {description[:400]}")
        if solution:
            print(f"solution: {solution[:400]}")

        playbook = get_playbook_summary(DB_PATH, plugin_id)
        if playbook is None:
            print("playbook: missing")
        else:
            _, finding_name, source_path = playbook
            print(f"playbook: {finding_name} ({source_path})")

        targets = get_finding_targets(DB_PATH, plugin_id)
        print(f"targets: {len(targets)}")
        for host, port, protocol, target_severity, scan_name in targets[:50]:
            print(
                f"target\t{host}\tport={port}\tproto={protocol}\tseverity={target_severity}\tscan={scan_name}"
            )
        if len(targets) > 50:
            print(f"... truncated {len(targets) - 50} additional targets")
        return

    if args.command == "create-playbook":
        plugin = get_plugin_details(DB_PATH, args.plugin_id)
        if plugin is None:
            print(f"Plugin {args.plugin_id} not found in local database")
            return
        playbook_path = create_playbook_template(args.plugin_id, plugin[1], args.output)
        import_playbook(DB_PATH, playbook_path)
        print(f"Created playbook template at {playbook_path}")
        return

    if args.command == "create-playbooks":
        rows = search_plugins(
            DB_PATH,
            name_contains=args.name_contains,
            family=args.family,
            limit=args.limit,
        )
        if not rows:
            print("No plugins matched the requested filters")
            return
        created = create_playbook_templates(rows, args.output_dir, overwrite=args.overwrite)
        if not created:
            print("No new playbooks created; matching files already exist")
            return
        for path in created:
            import_playbook(DB_PATH, path)
            print(f"Created playbook template at {path}")
        print(f"created={len(created)}")
        return

    if args.command == "validate":
        project_name = _resolve_project(getattr(args, "project", None), "validate")
        print(validate_plugin(DB_PATH, args.plugin_id, project_name=project_name))
        return

    if args.command == "validate-all":
        project_name = _resolve_project(getattr(args, "project", None), "validate-all")
        min_severity = _SEVERITY_MAP.get(args.min_severity) if args.min_severity else None
        plugin_ids = list_playbook_plugin_ids(DB_PATH)
        finding_plugin_ids = set(
            list_finding_plugin_ids(
                DB_PATH,
                include_informational=args.include_informational,
                min_severity=min_severity,
            )
        )
        plugin_ids = [plugin_id for plugin_id in plugin_ids if plugin_id in finding_plugin_ids]
        if not plugin_ids:
            print("No playbooks found in local database")
            return
        playbook_names = {pid: name for pid, name, _ in list_playbooks(DB_PATH)}
        total = len(plugin_ids)
        agg_status: dict[str, int] = {}
        agg_targets = 0
        for index, plugin_id in enumerate(plugin_ids, start=1):
            name = playbook_names.get(plugin_id, "")
            label = f"{plugin_id} ({name})" if name else str(plugin_id)
            pct = index / total * 100
            print(f"{bright_cyan(f'[{index}/{total}]')} {dim(f'({pct:.0f}%)')} validating {bold(label)}", file=sys.stderr, flush=True)
            print(separator())
            print(validate_plugin(DB_PATH, plugin_id, project_name=project_name))
            summary = get_validation_summary(DB_PATH, plugin_id, project_name=project_name)
            for status, count in summary:
                agg_status[status] = agg_status.get(status, 0) + count
                agg_targets += count
        print(build_summary_banner(total, agg_status, agg_targets))
        if getattr(args, "html_report_path", None) is not None:
            html_path = export_all_reports_html(DB_PATH, args.html_report_path, project_name=project_name)
            print(f"Wrote HTML report to {html_path}")
        return

    if args.command == "sanitize-db":
        project_name = getattr(args, "project", None)
        result = sanitize_database(DB_PATH, project_name=project_name)
        scope = f" (project={project_name})" if project_name else ""
        print(
            f"Sanitized database{scope}: "
            f"deleted {result['findings_deleted']} findings rows and "
            f"{result['validation_runs_deleted']} validation rows"
        )
        return

    if args.command == "list-projects":
        rows = list_projects(DB_PATH)
        if not rows:
            print("No projects found")
            return
        for project, run_count, last_run in rows:
            print(f"{project}\truns={run_count}\tlast_run={last_run}")
        return

    if args.command == "show-results":
        project_name = getattr(args, "project", None)
        plugin = get_plugin_details(DB_PATH, args.plugin_id)
        if plugin is None:
            print(f"Plugin {args.plugin_id} not found in local database")
            return

        print(f"plugin_id: {plugin[0]}")
        print(f"name: {plugin[1]}")

        summary = get_validation_summary(DB_PATH, args.plugin_id, project_name=project_name)
        if not summary:
            print("results: none")
            return

        print("summary:")
        for status, count in summary:
            print(f"status\t{status}\tcount={count}")

        latest_results = get_latest_validation_results(DB_PATH, args.plugin_id, project_name=project_name)
        print(f"latest_results: {len(latest_results)}")
        for host, port, status, reason, analyst_note, command, executed_at, source in latest_results[:50]:
            reason_text = reason if reason is not None else "-"
            note_text = analyst_note if analyst_note is not None else "-"
            print(
                f"result\t{host}\tport={port}\tstatus={status}\treason={reason_text}\tnote={note_text}\tsource={source}\tat={executed_at}\tcommand={command}"
            )
        if len(latest_results) > 50:
            print(f"... truncated {len(latest_results) - 50} additional results")
        return

    if args.command == "override-result":
        project_name = _resolve_project(getattr(args, "project", None), "override-result")
        success = override_result(
            DB_PATH,
            args.plugin_id,
            args.host,
            args.port,
            args.status,
            args.reason,
            args.note,
            project_name=project_name,
        )
        if not success:
            print(f"No finding found for plugin {args.plugin_id} host {args.host} port {args.port}")
            return
        print(f"Recorded manual override for plugin {args.plugin_id} host {args.host} port {args.port}")
        return

    if args.command == "bulk-override":
        project_name = _resolve_project(getattr(args, "project", None), "bulk-override")
        count, errors = bulk_override(DB_PATH, args.csv_path, project_name=project_name)
        for err in errors:
            print(f"  SKIP  {err}", file=sys.stderr)
        print(f"Applied {count} override(s) to project '{project_name}'")
        if errors:
            print(f"{len(errors)} row(s) skipped — see above for details", file=sys.stderr)
        return

    if args.command == "coverage":
        project_name = getattr(args, "project", None)
        min_severity = _SEVERITY_MAP.get(args.min_severity) if args.min_severity else None
        stats = get_scan_coverage(
            DB_PATH,
            args.scan_file,
            project_name=project_name,
            min_severity=min_severity,
            include_informational=args.include_informational,
        )
        scope = f" (project={project_name})" if project_name else ""
        print(heavy_separator())
        print(bold(bright_cyan(f"  COVERAGE REPORT{scope}")))
        print(dim(f"  Scan: {args.scan_file}"))
        print(heavy_separator())
        print(f"  {bold('Total plugins:    ')} {stats['total_plugins']}")
        print(f"  {bold('Total targets:    ')} {stats['total_targets']}")
        print(f"  {bold('Have playbook:    ')} {green(str(stats['has_playbook']))}  ({stats['coverage_pct']:.1f}%)")
        print(f"  {bold('No playbook:      ')} {dim(str(stats['no_playbook']))}")
        print()
        print(f"  {bold('Pre-validatable:  ')} {bright_cyan(str(stats['pre_validatable']))}  (conclusive from Nessus plugin_output, no probe needed)")
        print()
        print(f"  {bold('Already run:')}")
        print(f"    {status_badge('validated')}      {stats['already_validated']}")
        print(f"    {status_badge('not_validated')}  {stats['already_not_validated']}")
        print(f"    {status_badge('inconclusive')}   {stats['already_inconclusive']}")
        print(f"    {dim('Not yet run:    ')} {stats['not_yet_run']}")
        print(heavy_separator())
        if args.verbose and stats["per_plugin"]:
            print(bold("  PER-PLUGIN BREAKDOWN"))
            print(heavy_separator())
            for p in stats["per_plugin"]:
                sev = p.get("severity") or "-"
                done = p["done"]
                pre  = p["pre_validatable"]
                pend = p["pending"]
                detail = (
                    f"  tp={done.get('validated',0)}"
                    f"  fp={done.get('not_validated',0)}"
                    f"  inc={done.get('inconclusive',0)}"
                    f"  pending={pend}"
                    f"  pre={pre}"
                )
                print(f"  {severity_badge(sev)} {bold(str(p['plugin_id']))}  {dim(str(p['plugin_name'])[:55])}  {dim(detail)}")
        return

    if args.command == "diff-projects":
        output = build_diff_report(
            DB_PATH,
            args.before,
            args.after,
            output_path=getattr(args, "output_path", None),
        )
        print(output)
        if getattr(args, "output_path", None):
            print(f"Wrote HTML diff report to {args.output_path}")
        return

    if args.command == "report":
        project_name = getattr(args, "project", None)
        if args.output is not None:
            output_path = export_plugin_report_csv(DB_PATH, args.plugin_id, args.output, project_name=project_name)
            print(f"Wrote CSV report to {output_path}")
            return
        print(build_plugin_report(DB_PATH, args.plugin_id, project_name=project_name))
        return

    if args.command == "report-all":
        project_name = getattr(args, "project", None)
        output_path = export_all_reports_csv(DB_PATH, args.output, project_name=project_name)
        print(f"Wrote combined CSV report to {output_path}")
        return

    if args.command == "report-html":
        project_name = getattr(args, "project", None)
        output_path = export_all_reports_html(DB_PATH, args.output, project_name=project_name)
        print(f"Wrote HTML report to {output_path}")
        return


if __name__ == "__main__":
    main()
