# nessus-parser

A local-first CLI for validating Nessus vulnerability findings through active verification. Instead of trusting scanner output at face value, each finding is re-probed using targeted commands (curl, nmap, banner grabs) to confirm whether the vulnerability is real, patched, or unreachable — producing a triage-ready report.

**2,890 validation playbooks** included out of the box, covering critical through low severity findings across MySQL, GitLab, Apache Tomcat, Fortinet, Splunk, WordPress, Confluence, Jenkins, PHP, SAP, WebSphere, and hundreds more.

---

## How it works

```
scan.nessus ──► extract findings ──► match playbook ──► run command ──► status
                                           │
                               curl / nmap / banner grab
                               on the actual host:port
                               from the Nessus finding
```

For each finding Nessus reported, the tool:
1. Looks up the playbook for that plugin ID
2. Runs the detection command against the actual host and port from the scan
3. Falls back through alternative commands if the primary is inconclusive
4. Compares the extracted version against the vulnerability threshold
5. Returns one of: `validated` / `not_validated` / `inconclusive` / `port_closed` / `host_down` / etc.

---

## Requirements

**Python:** 3.11 or later

**System tools** (used by playbooks at runtime):

```bash
# Debian / Ubuntu / Kali
sudo apt install nmap curl openssl

# nmap   — required for banner-based playbooks (MySQL, MongoDB, DB2, DNS, etc.)
# curl   — required for HTTP/HTTPS-based playbooks
# openssl — required for TLS/STARTTLS playbooks
```

Verify tools are available:

```bash
which nmap curl openssl && echo "All tools present"
```

---

## Installation

### 1. Clone the repository

```bash
git clone <repo-url> nessus-parser
cd nessus-parser
```

### 2. Run the installer

```bash
bash install.sh
```

The script automatically:

1. Checks for Python 3.11+ and warns about any missing system tools (`nmap`, `curl`, `openssl`)
2. Creates a virtual environment at `.venv/`
3. Installs `nessus-parser` and all dependencies inside the virtual environment (nothing is installed globally)
4. Initialises the SQLite database
5. Imports all 2,890 bundled playbooks

### 3. Activate the virtual environment

```bash
source .venv/bin/activate
```

You need to activate the environment each time you open a new terminal before running `nessus-parser`.

> **Tip — skip activation:** You can also call the binary directly without activating:
> ```bash
> .venv/bin/nessus-parser -f scan.nessus --validate-all
> ```

---

### Manual installation (alternative)

If you prefer to set up manually:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
nessus-parser init
for f in playbooks/*.json; do nessus-parser import-playbook "$f"; done
```

---

## Quick start

### Validate a scan file (nothing stored)

```bash
nessus-parser -f scan.nessus --validate-all
```

Runs every matching playbook, prints results to the terminal, writes nothing to the database.

### Validate a single plugin

```bash
nessus-parser -f scan.nessus --validate --plugin-id 155999
```

### Filter by minimum severity

```bash
# Critical and high only
nessus-parser -f scan.nessus --validate-all --min-severity high

# Critical only
nessus-parser -f scan.nessus --validate-all --min-severity critical
```

### Persist results and generate a report

```bash
# Store findings in DB (opt-in)
nessus-parser import-scan scan.nessus --store-findings

# Run validation and persist results
nessus-parser -f scan.nessus --validate-all --persist-results

# HTML report
nessus-parser report-html --output data/runtime/reports/report.html

# CSV export
nessus-parser report-all --output data/runtime/reports/results.csv
```

---

## Validation statuses

| Status | Meaning |
|---|---|
| `validated` | Finding confirmed — detected version is in the vulnerable range |
| `not_validated` | Likely false positive — version is patched or product mismatch detected |
| `inconclusive` | Command ran but output could not determine status |
| `port_closed` | TCP connection refused — service not listening on that port |
| `port_filtered` | Connection timed out — port is blocked or host is firewalled |
| `host_down` | Host unreachable (ICMP / routing failure) |
| `host_unreachable` | No route to host |
| `dns_failure` | Hostname could not be resolved |
| `auth_required` | Service returned 401/403 — credentials needed to verify |
| `error` | Command failed with no specific reason mapped |

---

## Full command reference

### Database management

```bash
nessus-parser init                  # Create schema (run once)
nessus-parser sanitize-db           # Remove all host-level data
```

### Importing data

```bash
# Plugin metadata only (no host data)
nessus-parser import-scan scan.nessus

# Plugin metadata + host findings (opt-in)
nessus-parser import-scan scan.nessus --store-findings

# Import plugins from NASL directory
nessus-parser import-plugins-nasl /opt/nessus/lib/nessus/plugins

# Import plugins from ZIP archive
nessus-parser import-plugins-zip plugins.zip

# Import a single playbook
nessus-parser import-playbook playbooks/155999.json
```

### Listing and searching

```bash
nessus-parser list-findings
nessus-parser list-plugins
nessus-parser list-playbooks
nessus-parser search-plugins --name-contains "Apache Tomcat"
nessus-parser search-plugins --family "Web Servers" --limit 20
nessus-parser show-finding --plugin-id 155999
```

### Validation

```bash
# Validate from scan file (nothing persisted)
nessus-parser -f scan.nessus --validate-all
nessus-parser -f scan.nessus --validate --plugin-id 155999
nessus-parser -f scan.nessus --validate-all --min-severity critical
nessus-parser -f scan.nessus --validate-all --persist-results

# Validate against findings already stored in DB
nessus-parser validate --plugin-id 155999
nessus-parser validate-all

# Show stored results
nessus-parser show-results --plugin-id 155999
```

### Playbook management

```bash
# Generate a playbook template for a plugin
nessus-parser create-playbook --plugin-id 84502 --output playbooks/84502.json

# Bulk generate templates
nessus-parser create-playbooks --name-contains "Apache" --output-dir playbooks/

# Manual analyst override
nessus-parser override-result \
    --plugin-id 155999 \
    --host 10.0.0.5 \
    --port 8080 \
    --status not_validated \
    --note "Vendor confirmed upgrade applied 2026-01-15"
```

### Reporting

```bash
# Interactive HTML report
nessus-parser report-html --output report.html

# CSV of all results
nessus-parser report-all --output results.csv

# CSV for a single plugin
nessus-parser report --plugin-id 155999 --output cve-2021-44228.csv
```

---

## Playbook format

Each playbook is a JSON file named `<plugin_id>.json`:

```json
{
  "plugin_id": 155999,
  "finding_name": "Apache Log4Shell RCE (CVE-2021-44228)",
  "service": "https",
  "port_logic": "any",
  "command_template": "curl -k -s -m 20 https://{host}:{port}/",
  "timeout_seconds": 30,
  "allowed_ports_json": "[]",
  "blocked_ports_json": "[]",
  "fallback_commands_json": [
    "curl -k -s -m 20 http://{host}:{port}/",
    "nmap -Pn --script http-headers,http-generator,http-server-header,http-title -p {port} {host}",
    "nmap -Pn -sV --version-light -p {port} {host}"
  ],
  "validated_if": [],
  "validated_if_absent_json": [],
  "not_validated_if": [],
  "not_validated_if_present_json": [],
  "inconclusive_if": [
    "failed to resolve", "0 hosts up", "host seems down", "timed out",
    "connection refused", "no route to host", "network is unreachable"
  ],
  "failure_reason_map": {
    "failed to resolve": "dns_failure",
    "0 hosts up": "host_down",
    "timed out": "port_filtered",
    "connection refused": "port_closed",
    "no route to host": "host_unreachable",
    "network is unreachable": "host_unreachable"
  },
  "version_rule": {
    "product_terms": ["log4j"],
    "version_patterns": ["log4j[- /]([0-9]+\\.[0-9]+\\.[0-9]+)"],
    "affected_lt": "2.17.1",
    "fixed_version": "2.17.1"
  },
  "analyst_note": "Log4Shell RCE via JNDI injection. Fixed: 2.17.1.",
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
  "reviewed_by": "analyst",
  "last_verified": "2026-03-16"
}
```

### Key fields

| Field | Description |
|---|---|
| `command_template` | Primary command. `{host}` and `{port}` are substituted from the Nessus finding. |
| `fallback_commands_json` | Tried in order when primary returns `error` or `inconclusive`. |
| `allowed_ports_json` | `"[]"` = accept any port from the finding (default). Explicit list restricts to those ports. |
| `version_rule.affected_lt` | Versions **below** this threshold → `validated`. |
| `version_rule.fixed_version` | Versions **at or above** this → `not_validated`. |
| `validated_if` | Strings — any match in output → `validated`. |
| `not_validated_if` | Strings — any match in output → `not_validated` (use for product exclusions like `MariaDB`). |
| `inconclusive_if` | Strings — match triggers `failure_reason_map` lookup for a specific status. |
| `failure_reason_map` | Maps output substrings → status codes (`port_closed`, `host_down`, etc.). |

### Detection command chain

Commands are tried in sequence. The chain stops at the first non-error result:

```
1. command_template       → purpose-specific endpoint (version API, banner, config file)
2. fallback_commands[0]   → alternative protocol/path variant
3. fallback_commands[1]   → nmap NSE scripts (http-headers, mysql-info, etc.)
4. fallback_commands[2]   → nmap -sV --version-light
```

---

## Port handling

`{port}` in every command is replaced with the **exact port Nessus reported** for that finding. With `allowed_ports_json: "[]"` (the default for all included playbooks), no port filtering is applied — if Nessus found MySQL on port 13306, the validation runs against 13306.

---

## Privacy defaults

Host-level data is never stored unless you explicitly opt in:

| Action | Stores host data? |
|---|---|
| `nessus-parser import-scan scan.nessus` | No |
| `nessus-parser import-scan scan.nessus --store-findings` | Yes |
| `nessus-parser -f scan.nessus --validate-all` | No — prints only |
| `nessus-parser -f scan.nessus --validate-all --persist-results` | Yes |
| `nessus-parser sanitize-db` | Removes all stored host data |

---

## Deployment

### Single analyst workstation

```bash
git clone <repo> nessus-parser && cd nessus-parser
bash install.sh
source .venv/bin/activate
```

Per engagement:

```bash
nessus-parser -f client_scan.nessus --validate-all --min-severity medium
nessus-parser report-html --output reports/$(date +%Y%m%d)_report.html
nessus-parser sanitize-db    # clean up after engagement
```

### Offline / air-gapped environments

The tool has **zero Python package dependencies**. Transfer the repo directory to the target machine and run the installer. Ensure `nmap` and `curl` are available locally.

```bash
# Package on internet-connected machine
tar czf nessus-parser.tar.gz nessus-parser/

# On air-gapped machine
tar xzf nessus-parser.tar.gz && cd nessus-parser
bash install.sh
source .venv/bin/activate
```

---

## Included playbook coverage

| Severity | Count | Key products |
|---|---|---|
| Critical | ~34 | Log4Shell, GitLab RCE, Pulse Secure, Citrix ADC, FortiOS, PAN-OS, Ivanti, Exchange ProxyLogon, Spring4Shell, Confluence RCE, SAP RECON |
| High | ~129 | Jenkins, Splunk, Nagios XI, WordPress, Drupal, Joomla, GitLab, MySQL, MariaDB, PostgreSQL, phpMyAdmin, Webmin, Zimbra, ManageEngine, SonicWall, Shellshock |
| Medium | ~2,551 | GitLab (606), Fortinet (142), Apache Tomcat (130), MariaDB (129), Atlassian JIRA (102), IBM WebSphere (97), MySQL (94), Splunk (93), SAP (75), Mattermost (64), OpenSSL (63), IBM DB2 (53), PHP (43), and more |
| Low | ~176 | GitLab, Splunk, Mattermost, Tomcat, MySQL/MariaDB, Fortinet, TYPO3, nginx, MongoDB, PostgreSQL, SAP, Grafana |

All playbooks use a 3-tier detection chain:
1. Purpose-specific endpoint (version API, banner, known config path)
2. nmap NSE scripts (`http-headers`, `http-generator`, `mysql-info`, `pgsql-info`, etc.)
3. `nmap -sV --version-light`

---

## Known limitations

- **Multi-branch version ranges**: Plugins covering multiple affected branches (e.g., "MySQL 5.6.x < 5.6.36 OR 5.7.x < 5.7.18") use the highest fixed version as the threshold. A patched 5.6.x install may still show `validated` because its version number falls below the 5.7.x fix boundary. Review `validated` results for multi-branch CVEs manually.

- **Version suppression**: Products configured to hide version info (PHP `expose_php = Off`, Apache `ServerTokens Prod`, Tomcat server hardening) may return `inconclusive` even when vulnerable. The fallback chain attempts NSE scripts and nmap -sV, but a fully hardened target may not disclose a version.

- **Auth-required endpoints**: REST APIs for JIRA, GitLab, Splunk, and Confluence may require authentication. These return `auth_required` status. For unauthenticated targets, the fallback commands check login page content instead.

- **Network scope**: The tool runs commands from the analyst machine. The target host must be reachable on the finding's port from where the tool is executed.

---

## Development

```bash
# Run the test suite
python -m pytest tests/ -v

# Smoke test
nessus-parser init
nessus-parser import-playbook playbooks/155999.json
nessus-parser list-playbooks
```

---

## Project layout

```
src/nessus_parser/
  cli/           CLI entry points (main.py)
  core/          Path configuration
  db/            SQLite schema and connection helpers
  services/
    scans.py         Nessus .nessus XML parsing and import
    playbooks.py     Playbook CRUD
    validation.py    Command execution and status derivation
    reporting.py     CSV and HTML report generation
    privacy.py       Database sanitization
playbooks/       2,890 analyst-authored validation playbooks (JSON)
data/runtime/    SQLite database and generated reports
tests/           Integration tests
```
