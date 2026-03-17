from __future__ import annotations

from pathlib import Path

from nessus_parser.db.connection import connect


def sanitize_database(db_path: Path) -> dict[str, int]:
    connection = connect(db_path)
    try:
        findings_count = connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        validation_runs_count = connection.execute("SELECT COUNT(*) FROM validation_runs").fetchone()[0]
        connection.execute("DELETE FROM findings")
        connection.execute("DELETE FROM validation_runs")
        connection.commit()
        connection.execute("VACUUM")
        return {
            "findings_deleted": findings_count,
            "validation_runs_deleted": validation_runs_count,
        }
    finally:
        connection.close()
