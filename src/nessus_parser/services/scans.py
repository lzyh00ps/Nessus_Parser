from __future__ import annotations

from collections import OrderedDict
import xml.etree.ElementTree as etree
from pathlib import Path

from nessus_parser.db.connection import connect


def import_nessus_scan(db_path: Path, scan_path: Path, store_findings: bool = False, project_name: str = "default") -> int:
    processed = 0
    current_host = ""
    connection = connect(db_path)
    try:
        for event, elem in etree.iterparse(scan_path, events=("start", "end")):
            if event == "start" and elem.tag == "ReportHost":
                current_host = elem.attrib.get("name", "")
            elif event == "end" and elem.tag == "ReportItem":
                _upsert_plugin_from_report_item(connection, elem, scan_path)
                if store_findings:
                    connection.execute(
                        """
                        INSERT INTO findings (
                            scan_name,
                            host,
                            port,
                            protocol,
                            plugin_id,
                            plugin_name,
                            severity,
                            plugin_output,
                            project_name
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            scan_path.name,
                            current_host,
                            int(elem.attrib.get("port", "0") or 0),
                            elem.attrib.get("protocol"),
                            int(elem.attrib["pluginID"]),
                            elem.attrib.get("pluginName", ""),
                            elem.attrib.get("severity"),
                            _child_text(elem, "plugin_output"),
                            project_name,
                        ),
                    )
                processed += 1
                elem.clear()
            elif event == "end" and elem.tag == "ReportHost":
                elem.clear()
        connection.commit()
        return processed
    finally:
        connection.close()


def list_findings(db_path: Path) -> list[tuple[int, str, int, int]]:
    connection = connect(db_path)
    try:
        return list(
            connection.execute(
                """
                SELECT
                    plugin_id,
                    plugin_name,
                    COUNT(DISTINCT host) AS affected_hosts,
                    COUNT(*) AS finding_rows
                FROM findings
                GROUP BY plugin_id, plugin_name
                ORDER BY affected_hosts DESC, finding_rows DESC, plugin_id ASC
                """
            )
        )
    finally:
        connection.close()


def list_plugins(db_path: Path) -> list[tuple[int, str, str | None, str | None]]:
    connection = connect(db_path)
    try:
        return list(
            connection.execute(
                """
                SELECT plugin_id, plugin_name, family, severity
                FROM plugins
                ORDER BY plugin_id ASC
                """
            )
        )
    finally:
        connection.close()


def get_plugin_details(
    db_path: Path,
    plugin_id: int,
) -> tuple[int, str, str | None, str | None, str | None, str | None, str | None] | None:
    connection = connect(db_path)
    try:
        return connection.execute(
            """
            SELECT
                plugin_id,
                plugin_name,
                family,
                severity,
                synopsis,
                description,
                solution
            FROM plugins
            WHERE plugin_id = ?
            """,
            (plugin_id,),
        ).fetchone()
    finally:
        connection.close()


def get_finding_targets(
    db_path: Path,
    plugin_id: int,
) -> list[tuple[str, int | None, str | None, str | None, str | None]]:
    connection = connect(db_path)
    try:
        return list(
            connection.execute(
                """
                SELECT
                    host,
                    port,
                    protocol,
                    severity,
                    scan_name
                FROM findings
                WHERE plugin_id = ?
                GROUP BY host, port, protocol, severity, scan_name
                ORDER BY host ASC, port ASC
                """,
                (plugin_id,),
            )
        )
    finally:
        connection.close()


def get_finding_ids_for_plugin(db_path: Path, plugin_id: int, project_name: str | None = None) -> list[tuple[int, str, int | None, str | None, str | None]]:
    connection = connect(db_path)
    try:
        return list(
            connection.execute(
                """
                SELECT MIN(id) AS id, host, port, protocol, plugin_output
                FROM findings
                WHERE plugin_id = ?
                AND (? IS NULL OR project_name = ?)
                GROUP BY host, port, protocol
                ORDER BY host ASC, port ASC, id ASC
                """,
                (plugin_id, project_name, project_name),
            )
        )
    finally:
        connection.close()


def load_scan_targets(
    scan_path: Path,
    plugin_id: int,
) -> dict[str, object] | None:
    metadata: dict[str, object] | None = None
    targets: OrderedDict[tuple[str, int, str | None], dict[str, object]] = OrderedDict()
    current_host = ""

    for event, elem in etree.iterparse(scan_path, events=("start", "end")):
        if event == "start" and elem.tag == "ReportHost":
            current_host = elem.attrib.get("name", "")
        elif event == "end" and elem.tag == "ReportItem":
            if int(elem.attrib["pluginID"]) == plugin_id:
                port = int(elem.attrib.get("port", "0") or 0)
                protocol = elem.attrib.get("protocol")
                if metadata is None:
                    metadata = {
                        "plugin_id": plugin_id,
                        "plugin_name": elem.attrib.get("pluginName", ""),
                        "severity": elem.attrib.get("severity"),
                        "description": _child_text(elem, "description"),
                        "synopsis": _child_text(elem, "synopsis"),
                        "solution": _child_text(elem, "solution"),
                    }
                key = (current_host, port, protocol)
                if key not in targets:
                    targets[key] = {
                        "host": current_host,
                        "port": port,
                        "protocol": protocol,
                        "severity": elem.attrib.get("severity"),
                        "plugin_output": _child_text(elem, "plugin_output"),
                    }
            elem.clear()
        elif event == "end" and elem.tag == "ReportHost":
            elem.clear()

    if metadata is None:
        return None

    metadata["targets"] = list(targets.values())
    return metadata


def list_scan_plugin_ids(
    scan_path: Path,
    include_informational: bool = False,
    min_severity: int | None = None,
) -> list[int]:
    plugin_ids: set[int] = set()
    for event, elem in etree.iterparse(scan_path, events=("end",)):
        if elem.tag == "ReportItem":
            severity_val = elem.attrib.get("severity")
            skip = False
            if min_severity is not None:
                try:
                    if severity_val is not None and int(severity_val) < min_severity:
                        skip = True
                except ValueError:
                    pass
            elif not include_informational and severity_val == "0":
                skip = True
            if not skip:
                plugin_ids.add(int(elem.attrib["pluginID"]))
            elem.clear()
    return sorted(plugin_ids)


def list_finding_plugin_ids(
    db_path: Path,
    include_informational: bool = False,
    min_severity: int | None = None,
) -> list[int]:
    connection = connect(db_path)
    try:
        if min_severity is not None:
            rows = connection.execute(
                """
                SELECT DISTINCT plugin_id
                FROM findings
                WHERE severity IS NULL OR CAST(severity AS INTEGER) >= ?
                ORDER BY plugin_id ASC
                """,
                (min_severity,),
            )
        elif include_informational:
            rows = connection.execute(
                """
                SELECT DISTINCT plugin_id
                FROM findings
                ORDER BY plugin_id ASC
                """
            )
        else:
            rows = connection.execute(
                """
                SELECT DISTINCT plugin_id
                FROM findings
                WHERE severity IS NULL OR severity != '0'
                ORDER BY plugin_id ASC
                """
            )
        return [row[0] for row in rows]
    finally:
        connection.close()


def upsert_plugin_from_scan(db_path: Path, scan_path: Path, plugin_id: int) -> bool:
    scan_data = load_scan_targets(scan_path, plugin_id)
    if scan_data is None:
        return False

    connection = connect(db_path)
    try:
        connection.execute(
            """
            INSERT INTO plugins (
                plugin_id,
                plugin_name,
                severity,
                synopsis,
                description,
                solution,
                source
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(plugin_id) DO UPDATE SET
                plugin_name = excluded.plugin_name,
                severity = COALESCE(excluded.severity, plugins.severity),
                synopsis = COALESCE(excluded.synopsis, plugins.synopsis),
                description = COALESCE(excluded.description, plugins.description),
                solution = COALESCE(excluded.solution, plugins.solution),
                source = excluded.source
            """,
            (
                scan_data["plugin_id"],
                scan_data["plugin_name"],
                scan_data.get("severity"),
                scan_data.get("synopsis"),
                scan_data.get("description"),
                scan_data.get("solution"),
                f"scan:{scan_path.name}",
            ),
        )
        connection.commit()
        return True
    finally:
        connection.close()


def _upsert_plugin_from_report_item(
    connection,
    report_item: etree.Element,
    scan_path: Path,
) -> None:
    connection.execute(
        """
        INSERT INTO plugins (
            plugin_id,
            plugin_name,
            family,
            severity,
            synopsis,
            description,
            solution,
            source
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(plugin_id) DO UPDATE SET
            plugin_name = excluded.plugin_name,
            family = COALESCE(excluded.family, plugins.family),
            severity = COALESCE(excluded.severity, plugins.severity),
            synopsis = COALESCE(excluded.synopsis, plugins.synopsis),
            description = COALESCE(excluded.description, plugins.description),
            solution = COALESCE(excluded.solution, plugins.solution),
            source = excluded.source
        """,
        (
            int(report_item.attrib["pluginID"]),
            report_item.attrib.get("pluginName", ""),
            _child_text(report_item, "plugin_family"),
            report_item.attrib.get("severity"),
            _child_text(report_item, "synopsis"),
            _child_text(report_item, "description"),
            _child_text(report_item, "solution"),
            f"scan:{scan_path.name}",
        ),
    )


def _child_text(node: etree.Element, tag: str) -> str | None:
    child = node.find(tag)
    return child.text if child is not None else None
