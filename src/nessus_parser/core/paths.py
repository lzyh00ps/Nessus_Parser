from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = ROOT / "data" / "runtime"
DB_PATH = DATA_DIR / "nessus_parser.sqlite3"
PLAYBOOKS_DIR = ROOT / "playbooks"

# Ensure consumers can safely open the default SQLite path even when invoked
# before explicit initialization.
DATA_DIR.mkdir(parents=True, exist_ok=True)
