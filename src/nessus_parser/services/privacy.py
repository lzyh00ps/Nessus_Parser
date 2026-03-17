from __future__ import annotations

from pathlib import Path

from nessus_parser.db.connection import connect


def sanitize_database(db_path: Path, project_name: str | None = None) -> dict[str, int]:
    connection = connect(db_path)
    try:
        if project_name is None:
            findings_count = connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            validation_runs_count = connection.execute("SELECT COUNT(*) FROM validation_runs").fetchone()[0]
            connection.execute("DELETE FROM findings")
            connection.execute("DELETE FROM validation_runs")
        else:
            findings_count = connection.execute(
                "SELECT COUNT(*) FROM findings WHERE project_name = ?", (project_name,)
            ).fetchone()[0]
            validation_runs_count = connection.execute(
                "SELECT COUNT(*) FROM validation_runs WHERE project_name = ?", (project_name,)
            ).fetchone()[0]
            connection.execute("DELETE FROM findings WHERE project_name = ?", (project_name,))
            connection.execute("DELETE FROM validation_runs WHERE project_name = ?", (project_name,))
        connection.commit()
    finally:
        connection.close()

    # VACUUM requires an exclusive lock with no other connections open.
    # Open a fresh connection after the previous one is fully closed.
    vacuum_conn = connect(db_path)
    try:
        vacuum_conn.execute("VACUUM")
    finally:
        vacuum_conn.close()

    return {
        "findings_deleted": findings_count,
        "validation_runs_deleted": validation_runs_count,
    }
