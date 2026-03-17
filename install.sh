#!/usr/bin/env bash
# nessus-parser installer
# Creates a virtual environment, installs the package, initialises the
# database, and imports all bundled playbooks.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

# ── colour helpers ────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*" >&2; }

# ── Python version check ──────────────────────────────────────────────────────
PYTHON=""
for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" &>/dev/null; then
        version=$("$candidate" -c 'import sys; print(sys.version_info[:2])')
        if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)' 2>/dev/null; then
            PYTHON="$candidate"
            break
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    error "Python 3.11 or later is required but was not found."
    error "Install it with:  sudo apt install python3.11"
    exit 1
fi
info "Using Python: $PYTHON ($($PYTHON --version))"

# ── System tool check (advisory only) ────────────────────────────────────────
MISSING_TOOLS=()
for tool in nmap curl openssl; do
    if ! command -v "$tool" &>/dev/null; then
        MISSING_TOOLS+=("$tool")
    fi
done
if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
    warn "The following system tools are not installed: ${MISSING_TOOLS[*]}"
    warn "Install them with:  sudo apt install ${MISSING_TOOLS[*]}"
    warn "Some playbooks will not function without these tools."
else
    info "System tools present: nmap, curl, openssl"
fi

# ── Create virtual environment ────────────────────────────────────────────────
if [[ -d "$VENV_DIR" ]]; then
    info "Virtual environment already exists at .venv — skipping creation"
else
    info "Creating virtual environment at .venv"
    "$PYTHON" -m venv "$VENV_DIR"
fi

VENV_PYTHON="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

# ── Upgrade pip inside the venv (silent) ─────────────────────────────────────
info "Upgrading pip inside virtual environment"
"$VENV_PIP" install --upgrade pip --quiet

# ── Install nessus-parser into the venv ──────────────────────────────────────
info "Installing nessus-parser (editable) into virtual environment"
"$VENV_PIP" install -e "$SCRIPT_DIR" --quiet

NESSUS_PARSER="$VENV_DIR/bin/nessus-parser"

# ── Initialise the database ───────────────────────────────────────────────────
info "Initialising database"
"$NESSUS_PARSER" init

# ── Import all bundled playbooks ──────────────────────────────────────────────
PLAYBOOK_DIR="$SCRIPT_DIR/playbooks"
PLAYBOOK_COUNT=$(ls "$PLAYBOOK_DIR"/*.json 2>/dev/null | wc -l)

if [[ "$PLAYBOOK_COUNT" -eq 0 ]]; then
    warn "No playbooks found in $PLAYBOOK_DIR — skipping import"
else
    info "Importing $PLAYBOOK_COUNT playbooks (this may take a moment)"
    imported=0
    failed=0
    for f in "$PLAYBOOK_DIR"/*.json; do
        if "$NESSUS_PARSER" import-playbook "$f" &>/dev/null; then
            imported=$((imported + 1))
        else
            failed=$((failed + 1))
            warn "Failed to import: $(basename "$f")"
        fi
    done
    info "Imported: $imported  Failed: $failed"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}Installation complete.${NC}"
echo ""
echo "Activate the virtual environment before use:"
echo "  source .venv/bin/activate"
echo ""
echo "Then run:"
echo "  nessus-parser -f scan.nessus --validate-all"
echo "  nessus-parser -f scan.nessus --validate-all --min-severity high"
echo "  nessus-parser report-html --output report.html"
echo ""
