from __future__ import annotations

import sqlite3
from pathlib import Path

from nessus_parser.db.connection import connect


SCHEMA = """
CREATE TABLE IF NOT EXISTS plugins (
    plugin_id INTEGER PRIMARY KEY,
    plugin_name TEXT NOT NULL,
    family TEXT,
    severity TEXT,
    synopsis TEXT,
    description TEXT,
    solution TEXT,
    source TEXT,
    imported_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_name TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER,
    protocol TEXT,
    plugin_id INTEGER NOT NULL,
    plugin_name TEXT NOT NULL,
    severity TEXT,
    plugin_output TEXT,
    imported_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS playbooks (
    plugin_id INTEGER PRIMARY KEY,
    finding_name TEXT NOT NULL,
    service TEXT,
    port_logic TEXT,
    command_template TEXT NOT NULL,
    timeout_seconds INTEGER NOT NULL DEFAULT 30,
    allowed_ports_json TEXT NOT NULL DEFAULT '[]',
    blocked_ports_json TEXT NOT NULL DEFAULT '[]',
    starttls_protocol_map_json TEXT NOT NULL DEFAULT '{}',
    fallback_commands_json TEXT NOT NULL DEFAULT '[]',
    version_rule_json TEXT NOT NULL DEFAULT '{}',
    validated_if_json TEXT NOT NULL,
    validated_if_absent_json TEXT NOT NULL DEFAULT '[]',
    not_validated_if_json TEXT NOT NULL,
    not_validated_if_present_json TEXT NOT NULL DEFAULT '[]',
    inconclusive_if_json TEXT NOT NULL,
    failure_reason_map_json TEXT NOT NULL,
    references_json TEXT NOT NULL,
    reviewed_by TEXT,
    last_verified TEXT,
    source_path TEXT,
    imported_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS validation_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    plugin_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    port INTEGER,
    command TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT,
    analyst_note TEXT,
    source TEXT NOT NULL DEFAULT 'automation',
    stdout TEXT,
    stderr TEXT,
    exit_code INTEGER,
    executed_at TEXT DEFAULT CURRENT_TIMESTAMP
);
"""


def initialize_database(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = connect(db_path)
    try:
        connection.executescript(SCHEMA)
        _ensure_column(connection, "playbooks", "timeout_seconds", "INTEGER NOT NULL DEFAULT 30")
        _ensure_column(connection, "playbooks", "allowed_ports_json", "TEXT NOT NULL DEFAULT '[]'")
        _ensure_column(connection, "playbooks", "blocked_ports_json", "TEXT NOT NULL DEFAULT '[]'")
        _ensure_column(connection, "playbooks", "starttls_protocol_map_json", "TEXT NOT NULL DEFAULT '{}'")
        _ensure_column(connection, "playbooks", "fallback_commands_json", "TEXT NOT NULL DEFAULT '[]'")
        _ensure_column(connection, "playbooks", "version_rule_json", "TEXT NOT NULL DEFAULT '{}'")
        _ensure_column(connection, "playbooks", "validated_if_absent_json", "TEXT NOT NULL DEFAULT '[]'")
        _ensure_column(connection, "playbooks", "not_validated_if_present_json", "TEXT NOT NULL DEFAULT '[]'")
        _ensure_column(connection, "validation_runs", "analyst_note", "TEXT")
        _ensure_column(connection, "validation_runs", "source", "TEXT NOT NULL DEFAULT 'automation'")
        connection.commit()
    finally:
        connection.close()


def _ensure_column(connection: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    existing_columns = {
        row[1]
        for row in connection.execute(f"PRAGMA table_info({table})")
    }
    if column not in existing_columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
