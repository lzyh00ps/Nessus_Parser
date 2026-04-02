from __future__ import annotations

import json
from pathlib import Path

from nessus_parser.core.paths import PLAYBOOKS_DIR
from nessus_parser.db.connection import connect


def _pb_list(payload: dict, key: str) -> list:
    """Read a list field from a playbook payload, accepting both 'key' and 'key_json' variants.

    Some older playbook files store list fields under a 'key_json' name (e.g.
    'fallback_commands_json') rather than the canonical plain name.  When the
    plain key is absent or None this helper falls back to the '_json' variant
    and, if that value is a raw JSON string, parses it first.
    """
    for k in (key, key + "_json"):
        val = payload.get(k)
        if val is None:
            continue
        if isinstance(val, list):
            return val
        if isinstance(val, str):
            try:
                parsed = json.loads(val)
                return parsed if isinstance(parsed, list) else []
            except (json.JSONDecodeError, ValueError):
                pass
    return []


def _pb_dict(payload: dict, key: str) -> dict:
    """Read a dict field from a playbook payload, accepting both 'key' and 'key_json' variants."""
    for k in (key, key + "_json"):
        val = payload.get(k)
        if val is None:
            continue
        if isinstance(val, dict):
            return val
        if isinstance(val, str):
            try:
                parsed = json.loads(val)
                return parsed if isinstance(parsed, dict) else {}
            except (json.JSONDecodeError, ValueError):
                pass
    return {}


def import_playbook(db_path: Path, playbook_path: Path) -> None:
    payload = json.loads(playbook_path.read_text())
    connection = connect(db_path)
    try:
        connection.execute(
            """
            INSERT INTO playbooks (
                plugin_id,
                finding_name,
                service,
                port_logic,
                command_template,
                timeout_seconds,
                allowed_ports_json,
                blocked_ports_json,
                starttls_protocol_map_json,
                fallback_commands_json,
                version_rule_json,
                validated_if_json,
                validated_if_absent_json,
                not_validated_if_json,
                not_validated_if_present_json,
                inconclusive_if_json,
                failure_reason_map_json,
                references_json,
                reviewed_by,
                last_verified,
                source_path
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(plugin_id) DO UPDATE SET
                finding_name = excluded.finding_name,
                service = excluded.service,
                port_logic = excluded.port_logic,
                command_template = excluded.command_template,
                timeout_seconds = excluded.timeout_seconds,
                allowed_ports_json = excluded.allowed_ports_json,
                blocked_ports_json = excluded.blocked_ports_json,
                starttls_protocol_map_json = excluded.starttls_protocol_map_json,
                fallback_commands_json = excluded.fallback_commands_json,
                version_rule_json = excluded.version_rule_json,
                validated_if_json = excluded.validated_if_json,
                validated_if_absent_json = excluded.validated_if_absent_json,
                not_validated_if_json = excluded.not_validated_if_json,
                not_validated_if_present_json = excluded.not_validated_if_present_json,
                inconclusive_if_json = excluded.inconclusive_if_json,
                failure_reason_map_json = excluded.failure_reason_map_json,
                references_json = excluded.references_json,
                reviewed_by = excluded.reviewed_by,
                last_verified = excluded.last_verified,
                source_path = excluded.source_path
            """,
            (
                payload["plugin_id"],
                payload["finding_name"],
                payload.get("service"),
                payload.get("port_logic"),
                payload["command_template"],
                payload.get("timeout_seconds", 30),
                json.dumps(_pb_list(payload, "allowed_ports")),
                json.dumps(_pb_list(payload, "blocked_ports")),
                json.dumps(_pb_dict(payload, "starttls_protocol_map")),
                json.dumps(_pb_list(payload, "fallback_commands")),
                json.dumps(_pb_dict(payload, "version_rule")),
                json.dumps(_pb_list(payload, "validated_if")),
                json.dumps(_pb_list(payload, "validated_if_absent")),
                json.dumps(_pb_list(payload, "not_validated_if")),
                json.dumps(_pb_list(payload, "not_validated_if_present")),
                json.dumps(_pb_list(payload, "inconclusive_if")),
                json.dumps(_pb_dict(payload, "failure_reason_map")),
                json.dumps(_pb_list(payload, "references")),
                payload.get("reviewed_by"),
                payload.get("last_verified"),
                str(playbook_path),
            ),
        )
        connection.commit()
    finally:
        connection.close()


def list_playbooks(db_path: Path) -> list[tuple[int, str, str | None]]:
    connection = connect(db_path)
    try:
        return list(
            connection.execute(
                """
                SELECT plugin_id, finding_name, source_path
                FROM playbooks
                ORDER BY plugin_id
                """
            )
        )
    finally:
        connection.close()


def list_playbook_plugin_ids(db_path: Path) -> list[int]:
    connection = connect(db_path)
    try:
        return [
            row[0]
            for row in connection.execute(
                """
                SELECT plugin_id
                FROM playbooks
                ORDER BY plugin_id ASC
                """
            )
        ]
    finally:
        connection.close()


def get_playbook_summary(db_path: Path, plugin_id: int) -> tuple[int, str, str | None] | None:
    connection = connect(db_path)
    try:
        return connection.execute(
            """
            SELECT plugin_id, finding_name, source_path
            FROM playbooks
            WHERE plugin_id = ?
            """,
            (plugin_id,),
        ).fetchone()
    finally:
        connection.close()


def get_playbook(db_path: Path, plugin_id: int) -> dict[str, object] | None:
    connection = connect(db_path)
    try:
        row = connection.execute(
            """
            SELECT
                plugin_id,
                finding_name,
                service,
                port_logic,
                command_template,
                timeout_seconds,
                allowed_ports_json,
                blocked_ports_json,
                starttls_protocol_map_json,
                fallback_commands_json,
                version_rule_json,
                validated_if_json,
                validated_if_absent_json,
                not_validated_if_json,
                not_validated_if_present_json,
                inconclusive_if_json,
                failure_reason_map_json,
                references_json,
                reviewed_by,
                last_verified,
                source_path
            FROM playbooks
            WHERE plugin_id = ?
            """,
            (plugin_id,),
        ).fetchone()
    finally:
        connection.close()

    if row is None:
        return None

    return {
        "plugin_id": row[0],
        "finding_name": row[1],
        "service": row[2],
        "port_logic": row[3],
        "command_template": row[4],
        "timeout_seconds": row[5],
        "allowed_ports": json.loads(row[6]),
        "blocked_ports": json.loads(row[7]),
        "starttls_protocol_map": json.loads(row[8]),
        "fallback_commands": json.loads(row[9]),
        "version_rule": json.loads(row[10]),
        "validated_if": json.loads(row[11]),
        "validated_if_absent": json.loads(row[12]),
        "not_validated_if": json.loads(row[13]),
        "not_validated_if_present": json.loads(row[14]),
        "inconclusive_if": json.loads(row[15]),
        "failure_reason_map": json.loads(row[16]),
        "references": json.loads(row[17]),
        "reviewed_by": row[18],
        "last_verified": row[19],
        "source_path": row[20],
    }


def create_playbook_template(
    plugin_id: int,
    finding_name: str,
    output_path: Path | None = None,
) -> Path:
    PLAYBOOKS_DIR.mkdir(parents=True, exist_ok=True)
    target_path = output_path or PLAYBOOKS_DIR / f"{plugin_id}.json"
    target_path.write_text(
        json.dumps(_build_template(plugin_id, finding_name), indent=2) + "\n"
    )
    return target_path


def create_playbook_templates(
    plugin_rows: list[tuple[int, str, str | None, str | None]],
    output_dir: Path | None = None,
    overwrite: bool = False,
) -> list[Path]:
    target_dir = output_dir or PLAYBOOKS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []
    for plugin_id, finding_name, _family, _severity in plugin_rows:
        path = target_dir / f"{plugin_id}.json"
        if path.exists() and not overwrite:
            continue
        path.write_text(
            json.dumps(_build_template(plugin_id, finding_name), indent=2) + "\n"
        )
        created.append(path)
    return created


def _build_template(plugin_id: int, finding_name: str) -> dict[str, object]:
    lowered = finding_name.lower()
    if "cve-" in lowered or " outdated" in lowered or "unsupported" in lowered or "end of life" in lowered:
        return {
            "plugin_id": plugin_id,
            "finding_name": finding_name,
            "service": "banner",
            "port_logic": "use_scan_port",
            "command_template": "nmap -Pn -sV --version-light -p {port} {host}",
            "timeout_seconds": 45,
            "allowed_ports": [],
            "blocked_ports": [],
            "starttls_protocol_map": {},
            "fallback_commands": [],
            "version_rule": {},
            "validated_if": [],
            "validated_if_absent": [],
            "not_validated_if": [],
            "not_validated_if_present": [],
            "inconclusive_if": ["filtered", "closed", "host seems down", "failed to resolve"],
            "failure_reason_map": {
                "filtered": "port_filtered",
                "closed": "port_closed",
                "host seems down": "host_down",
                "failed to resolve": "host_down"
            },
            "references": [],
            "reviewed_by": None,
            "last_verified": None
        }

    if "hsts" in lowered:
        return {
            "plugin_id": plugin_id,
            "finding_name": finding_name,
            "service": "https",
            "port_logic": "use_scan_port",
            "command_template": "curl -k -I --max-time 15 https://{host}:{port}/",
            "timeout_seconds": 20,
            "allowed_ports": [443, 444, 445, 448, 449, 5443, 6443, 7443, 8443, 8843, 9443, 10443],
            "blocked_ports": [],
            "starttls_protocol_map": {},
            "validated_if": [],
            "validated_if_absent": ["strict-transport-security:"],
            "not_validated_if": [],
            "not_validated_if_present": ["strict-transport-security:"],
            "inconclusive_if": ["connection refused", "timed out", "could not resolve host"],
            "failure_reason_map": {
                "connection refused": "port_closed",
                "timed out": "port_filtered",
                "could not resolve host": "host_down"
            },
            "references": [],
            "reviewed_by": None,
            "last_verified": None
        }

    if "tls version 1.3" in lowered:
        return {
            "plugin_id": plugin_id,
            "finding_name": finding_name,
            "service": "tls",
            "port_logic": "use_scan_port",
            "command_template": "sslscan --no-colour --tls13 {sslscan_starttls_args} {host}:{port}",
            "timeout_seconds": 30,
            "allowed_ports": [443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 1311, 2083, 2087, 2096, 2376, 3269, 3389, 5061, 5349, 5432, 5986, 6443, 6514, 6697, 8172, 8443, 8531, 8883, 9200, 9443, 10443],
            "blocked_ports": [],
            "starttls_protocol_map": {
                "21": "ftp",
                "25": "smtp",
                "110": "pop3",
                "143": "imap",
                "389": "ldap",
                "5222": "xmpp",
                "5269": "xmpp-server",
                "5432": "postgres",
                "587": "smtp"
            },
            "fallback_commands": [
                "nmap -Pn --script ssl-enum-ciphers -p {port} {host}",
                "openssl s_client -connect {host}:{port} {openssl_tls_args} -tls1_3 -brief </dev/null 2>&1"
            ],
            "validated_if": ["tlsv1.3", "protocol version: tlsv1.3", "ciphersuite:"],
            "validated_if_absent": [],
            "not_validated_if": ["unsupported protocol", "tlsv1 alert protocol version", "handshake failure"],
            "not_validated_if_present": [],
            "inconclusive_if": ["connection refused", "timed out", "no route to host", "temporary failure in name resolution", "bio_lookup_ex:system lib", "could not open a socket", "operation not permitted", "cannot create af_netlink socket"],
            "failure_reason_map": {
                "connection refused": "port_closed",
                "timed out": "port_filtered",
                "no route to host": "host_down",
                "temporary failure in name resolution": "host_down",
                "bio_lookup_ex:system lib": "host_down",
                "could not open a socket": "inconclusive",
                "operation not permitted": "inconclusive",
                "cannot create af_netlink socket": "inconclusive"
            },
            "references": [],
            "reviewed_by": None,
            "last_verified": None
        }

    if "tls version 1.2" in lowered:
        return {
            "plugin_id": plugin_id,
            "finding_name": finding_name,
            "service": "tls",
            "port_logic": "use_scan_port",
            "command_template": "sslscan --no-colour --tls12 {sslscan_starttls_args} {host}:{port}",
            "timeout_seconds": 30,
            "allowed_ports": [443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 1311, 2083, 2087, 2096, 2376, 3269, 3389, 5061, 5349, 5432, 5986, 6443, 6514, 6697, 8172, 8443, 8531, 8883, 9200, 9443, 10443],
            "blocked_ports": [],
            "starttls_protocol_map": {
                "21": "ftp",
                "25": "smtp",
                "110": "pop3",
                "143": "imap",
                "389": "ldap",
                "5222": "xmpp",
                "5269": "xmpp-server",
                "5432": "postgres",
                "587": "smtp"
            },
            "fallback_commands": [
                "nmap -Pn --script ssl-enum-ciphers -p {port} {host}",
                "openssl s_client -connect {host}:{port} {openssl_tls_args} -tls1_2 -brief </dev/null 2>&1"
            ],
            "validated_if": ["tlsv1.2", "protocol version: tlsv1.2", "ciphersuite:"],
            "validated_if_absent": [],
            "not_validated_if": ["unsupported protocol", "tlsv1 alert protocol version", "handshake failure"],
            "not_validated_if_present": [],
            "inconclusive_if": ["connection refused", "timed out", "no route to host", "temporary failure in name resolution", "bio_lookup_ex:system lib", "could not open a socket", "operation not permitted", "cannot create af_netlink socket"],
            "failure_reason_map": {
                "connection refused": "port_closed",
                "timed out": "port_filtered",
                "no route to host": "host_down",
                "temporary failure in name resolution": "host_down",
                "bio_lookup_ex:system lib": "host_down",
                "could not open a socket": "inconclusive",
                "operation not permitted": "inconclusive",
                "cannot create af_netlink socket": "inconclusive"
            },
            "references": [],
            "reviewed_by": None,
            "last_verified": None
        }

    if "certificate" in lowered:
        return {
            "plugin_id": plugin_id,
            "finding_name": finding_name,
            "service": "tls",
            "port_logic": "use_scan_port",
            "command_template": "sslscan --no-colour --show-certificate {sslscan_starttls_args} {host}:{port}",
            "timeout_seconds": 45,
            "allowed_ports": [],
            "blocked_ports": [],
            "starttls_protocol_map": {
                "21": "ftp",
                "25": "smtp",
                "110": "pop3",
                "143": "imap",
                "389": "ldap",
                "5222": "xmpp",
                "5269": "xmpp-server",
                "5432": "postgres",
                "587": "smtp"
            },
            "fallback_commands": [],
            "validated_if": ["subject:", "issuer:"],
            "validated_if_absent": [],
            "not_validated_if": [],
            "not_validated_if_present": [],
            "inconclusive_if": ["failed to resolve", "connection timed out", "connection refused"],
            "failure_reason_map": {
                "failed to resolve": "host_down",
                "connection timed out": "port_filtered",
                "connection refused": "port_closed"
            },
            "references": [],
            "reviewed_by": None,
            "last_verified": None
        }

    if "cipher" in lowered or "ssl" in lowered or "tls" in lowered:
        return {
            "plugin_id": plugin_id,
            "finding_name": finding_name,
            "service": "tls",
            "port_logic": "use_scan_port",
            "command_template": "sslscan --no-colour --show-ciphers {sslscan_starttls_args} {host}:{port}",
            "timeout_seconds": 60,
            "allowed_ports": [],
            "blocked_ports": [],
            "starttls_protocol_map": {
                "21": "ftp",
                "25": "smtp",
                "110": "pop3",
                "143": "imap",
                "389": "ldap",
                "5222": "xmpp",
                "5269": "xmpp-server",
                "5432": "postgres",
                "587": "smtp"
            },
            "validated_if": ["accepted", "preferred"],
            "validated_if_absent": [],
            "not_validated_if": [],
            "not_validated_if_present": [],
            "inconclusive_if": ["failed to resolve", "connection timed out", "connection refused"],
            "failure_reason_map": {
                "failed to resolve": "host_down",
                "connection timed out": "port_filtered",
                "connection refused": "port_closed"
            },
            "references": [],
            "reviewed_by": None,
            "last_verified": None
        }

    return {
        "plugin_id": plugin_id,
        "finding_name": finding_name,
        "service": None,
        "port_logic": "use_scan_port",
        "command_template": "nmap -Pn -sV --version-light -p {port} {host}",
        "timeout_seconds": 30,
        "allowed_ports": [],
        "blocked_ports": [],
        "starttls_protocol_map": {},
        "fallback_commands": [],
        "version_rule": {},
        "validated_if": [],
        "validated_if_absent": [],
        "not_validated_if": [],
        "not_validated_if_present": [],
        "inconclusive_if": [],
        "failure_reason_map": {},
        "references": [],
        "reviewed_by": None,
        "last_verified": None
    }


def audit_playbooks(db_path: Path) -> list[dict[str, object]]:
    """Return an audit report for every imported playbook.

    Each entry contains:
      plugin_id, finding_name, source_path,
      has_validated_if (bool), has_version_rule (bool), has_validated_if_absent (bool),
      has_not_validated_if (bool), has_fallback_commands (bool),
      conclusive (bool)  – True when the playbook can produce a definitive result.
    """
    connection = connect(db_path)
    try:
        rows = list(
            connection.execute(
                """
                SELECT
                    plugin_id,
                    finding_name,
                    source_path,
                    validated_if_json,
                    validated_if_absent_json,
                    not_validated_if_json,
                    not_validated_if_present_json,
                    version_rule_json,
                    fallback_commands_json
                FROM playbooks
                ORDER BY plugin_id
                """
            )
        )
    finally:
        connection.close()

    results: list[dict[str, object]] = []
    for row in rows:
        (
            plugin_id,
            finding_name,
            source_path,
            validated_if_raw,
            validated_if_absent_raw,
            not_validated_if_raw,
            not_validated_if_present_raw,
            version_rule_raw,
            fallback_commands_raw,
        ) = row

        validated_if = json.loads(validated_if_raw or "[]")
        validated_if_absent = json.loads(validated_if_absent_raw or "[]")
        not_validated_if = json.loads(not_validated_if_raw or "[]")
        not_validated_if_present = json.loads(not_validated_if_present_raw or "[]")
        version_rule = json.loads(version_rule_raw or "{}")
        fallback_commands = json.loads(fallback_commands_raw or "[]")

        has_validated_if = bool(validated_if)
        has_validated_if_absent = bool(validated_if_absent)
        has_not_validated_if = bool(not_validated_if) or bool(not_validated_if_present)
        has_version_rule = bool(version_rule.get("version_patterns") or version_rule.get("affected_lt") or version_rule.get("affected_lte"))
        has_fallback_commands = bool(fallback_commands)

        conclusive = has_validated_if or has_validated_if_absent or has_version_rule

        results.append({
            "plugin_id": plugin_id,
            "finding_name": finding_name,
            "source_path": source_path,
            "has_validated_if": has_validated_if,
            "has_version_rule": has_version_rule,
            "has_validated_if_absent": has_validated_if_absent,
            "has_not_validated_if": has_not_validated_if,
            "has_fallback_commands": has_fallback_commands,
            "conclusive": conclusive,
        })

    return results
