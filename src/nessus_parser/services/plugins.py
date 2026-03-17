from __future__ import annotations

import json
import re
from pathlib import Path
from zipfile import ZipFile

from nessus_parser.db.connection import connect


def import_plugins_json(db_path: Path, plugin_file: Path) -> int:
    records = json.loads(plugin_file.read_text())
    connection = connect(db_path)
    try:
        connection.executemany(
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
                family = excluded.family,
                severity = excluded.severity,
                synopsis = excluded.synopsis,
                description = excluded.description,
                solution = excluded.solution,
                source = excluded.source
            """,
            [
                (
                    item["plugin_id"],
                    item["plugin_name"],
                    item.get("family"),
                    item.get("severity"),
                    item.get("synopsis"),
                    item.get("description"),
                    item.get("solution"),
                    str(plugin_file),
                )
                for item in records
            ],
        )
        connection.commit()
        return len(records)
    finally:
        connection.close()


def search_plugins(
    db_path: Path,
    plugin_id: int | None = None,
    name_contains: str | None = None,
    family: str | None = None,
    limit: int = 100,
) -> list[tuple[int, str, str | None, str | None]]:
    connection = connect(db_path)
    try:
        clauses: list[str] = []
        params: list[object] = []

        if plugin_id is not None:
            clauses.append("plugin_id = ?")
            params.append(plugin_id)
        if name_contains:
            normalized = name_contains.lower().replace(" ", "")
            clauses.append("REPLACE(LOWER(plugin_name), ' ', '') LIKE ?")
            params.append(f"%{normalized}%")
        if family:
            clauses.append("LOWER(COALESCE(family, '')) = ?")
            params.append(family.lower())

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        return list(
            connection.execute(
                f"""
                SELECT plugin_id, plugin_name, family, severity
                FROM plugins
                {where_sql}
                ORDER BY plugin_id ASC
                LIMIT ?
                """,
                params,
            )
        )
    finally:
        connection.close()


def import_plugins_from_nasl_dir(db_path: Path, plugin_dir: Path) -> int:
    plugin_files = sorted(plugin_dir.glob("*.nasl"))
    connection = connect(db_path)
    imported = 0
    try:
        for plugin_file in plugin_files:
            record = _extract_nasl_metadata(plugin_file)
            if record is None:
                continue
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
                    plugin_name = COALESCE(excluded.plugin_name, plugins.plugin_name),
                    family = COALESCE(excluded.family, plugins.family),
                    severity = COALESCE(excluded.severity, plugins.severity),
                    synopsis = COALESCE(excluded.synopsis, plugins.synopsis),
                    description = COALESCE(excluded.description, plugins.description),
                    solution = COALESCE(excluded.solution, plugins.solution),
                    source = excluded.source
                """,
                (
                    record["plugin_id"],
                    record["plugin_name"],
                    record.get("family"),
                    record.get("severity"),
                    record.get("synopsis"),
                    record.get("description"),
                    record.get("solution"),
                    str(plugin_file),
                ),
            )
            imported += 1
        connection.commit()
        return imported
    finally:
        connection.close()


def import_plugins_from_zip(db_path: Path, zip_path: Path) -> int:
    connection = connect(db_path)
    imported = 0
    try:
        with ZipFile(zip_path) as archive:
            for member_name in archive.namelist():
                if not member_name.endswith(".nasl"):
                    continue
                text = archive.read(member_name).decode(errors="ignore")
                record = _extract_nasl_metadata_from_text(text, member_name)
                if record is None:
                    continue
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
                        plugin_name = COALESCE(excluded.plugin_name, plugins.plugin_name),
                        family = COALESCE(excluded.family, plugins.family),
                        severity = COALESCE(excluded.severity, plugins.severity),
                        synopsis = COALESCE(excluded.synopsis, plugins.synopsis),
                        description = COALESCE(excluded.description, plugins.description),
                        solution = COALESCE(excluded.solution, plugins.solution),
                        source = excluded.source
                    """,
                    (
                        record["plugin_id"],
                        record["plugin_name"],
                        record.get("family"),
                        record.get("severity"),
                        record.get("synopsis"),
                        record.get("description"),
                        record.get("solution"),
                        f"{zip_path}:{member_name}",
                    ),
                )
                imported += 1
                if imported % 1000 == 0:
                    connection.commit()
        connection.commit()
        return imported
    finally:
        connection.close()


def _extract_nasl_metadata(plugin_file: Path) -> dict[str, object] | None:
    text = plugin_file.read_text(errors="ignore")
    return _extract_nasl_metadata_from_text(text, plugin_file.name)


def _extract_nasl_metadata_from_text(text: str, source_name: str) -> dict[str, object] | None:
    plugin_id = _extract_plugin_id_from_text(text, source_name)
    if plugin_id is None:
        return None

    record: dict[str, object] = {
        "plugin_id": plugin_id,
        "plugin_name": _capture_nasl_string(text, "script_name"),
        "family": _capture_nasl_string(text, "script_family"),
        "synopsis": _capture_nasl_string(text, "script_synopsis"),
        "description": _capture_nasl_string(text, "script_description"),
        "solution": _capture_nasl_string(text, "script_solution"),
    }

    severity = _capture_nasl_severity(text)
    if severity is not None:
        record["severity"] = severity

    if not record["plugin_name"]:
        record["plugin_name"] = Path(source_name).stem

    return record


def _extract_plugin_id(plugin_file: Path) -> int | None:
    if plugin_file.stem.isdigit():
        return int(plugin_file.stem)
    text = plugin_file.read_text(errors="ignore")
    return _extract_plugin_id_from_text(text, plugin_file.name)


def _extract_plugin_id_from_text(text: str, source_name: str) -> int | None:
    stem = Path(source_name).stem
    if stem.isdigit():
        return int(stem)
    match = re.search(r"script_id\s*\(\s*(\d+)\s*\)\s*;", text)
    if match is None:
        return None
    return int(match.group(1))


def _capture_nasl_string(text: str, function_name: str) -> str | None:
    match = re.search(
        rf'{function_name}\s*\(\s*(?:"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\')\s*\)\s*;',
        text,
        re.DOTALL,
    )
    if match is None:
        return None
    value = match.group(1) if match.group(1) is not None else match.group(2)
    return bytes(value, "utf-8").decode("unicode_escape").strip()


def _capture_nasl_severity(text: str) -> str | None:
    risk_factor = _capture_nasl_string(text, "script_risk_factor")
    if risk_factor:
        return risk_factor.lower()

    cvss_base = _capture_nasl_string(text, "script_cvss_base")
    if cvss_base:
        return cvss_base

    return None
