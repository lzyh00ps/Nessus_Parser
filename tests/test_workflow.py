from __future__ import annotations

import csv
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from nessus_parser.db.schema import initialize_database
from nessus_parser.services.playbooks import get_playbook, import_playbook
from nessus_parser.services.playbooks import create_playbook_templates
from nessus_parser.services.privacy import sanitize_database
from nessus_parser.services.plugins import search_plugins
from nessus_parser.services.reporting import export_all_reports_html, export_plugin_report_csv
from nessus_parser.services.scans import (
    get_plugin_details,
    import_nessus_scan,
    list_findings,
    list_scan_plugin_ids,
)
from nessus_parser.services.validation import (
    _build_openssl_tls_args,
    _build_sslscan_starttls_args,
    _build_testssl_starttls_args,
    _derive_status,
    get_matching_scan_playbook_ids,
    get_latest_validation_results,
    get_validation_summary,
    list_projects,
    override_result,
    validate_scan_file,
)


class WorkflowTests(unittest.TestCase):
    def test_import_scan_defaults_to_plugin_metadata_only(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = tmp_path / "test.sqlite3"
            scan_path = tmp_path / "sample.nessus"
            initialize_database(db_path)
            scan_path.write_text(
                """
                <NessusClientData_v2>
                  <Report name="Example">
                    <ReportHost name="host1.example">
                      <ReportItem port="443" protocol="tcp" pluginID="84502" pluginName="HSTS Missing From HTTPS Server" severity="1">
                        <description>The remote HTTPS server is not enforcing HSTS.</description>
                        <solution>Configure HSTS.</solution>
                        <synopsis>The remote web server is not enforcing HSTS.</synopsis>
                      </ReportItem>
                    </ReportHost>
                  </Report>
                </NessusClientData_v2>
                """.strip()
            )

            count = import_nessus_scan(db_path, scan_path)

            self.assertEqual(count, 1)
            self.assertEqual(list_findings(db_path), [])
            plugin = get_plugin_details(db_path, 84502)
            self.assertIsNotNone(plugin)
            self.assertEqual(plugin[1], "HSTS Missing From HTTPS Server")

    def test_import_scan_can_store_findings_when_explicitly_enabled(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = tmp_path / "test.sqlite3"
            scan_path = tmp_path / "sample.nessus"
            initialize_database(db_path)
            scan_path.write_text(
                """
                <NessusClientData_v2>
                  <Report name="Example">
                    <ReportHost name="host1.example">
                      <ReportItem port="443" protocol="tcp" pluginID="84502" pluginName="HSTS Missing From HTTPS Server" severity="1" />
                    </ReportHost>
                  </Report>
                </NessusClientData_v2>
                """.strip()
            )

            count = import_nessus_scan(db_path, scan_path, store_findings=True)

            self.assertEqual(count, 1)
            self.assertEqual(list_findings(db_path), [(84502, "HSTS Missing From HTTPS Server", 1, 1)])

    def test_import_playbook_and_classification(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = tmp_path / "test.sqlite3"
            playbook_path = tmp_path / "84502.json"
            initialize_database(db_path)
            playbook_path.write_text(
                """
                {
                  "plugin_id": 84502,
                  "finding_name": "HSTS Missing From HTTPS Server",
                  "service": "https",
                  "port_logic": "use_scan_port",
                  "command_template": "curl -I https://{host}:{port}/",
                  "timeout_seconds": 20,
                  "allowed_ports": [443],
                  "blocked_ports": [],
                  "validated_if": [],
                  "validated_if_absent": ["strict-transport-security:"],
                  "not_validated_if": [],
                  "not_validated_if_present": ["strict-transport-security:"],
                  "inconclusive_if": ["connection refused"],
                  "failure_reason_map": {"connection refused": "port_closed"},
                  "references": []
                }
                """.strip()
            )

            import_playbook(db_path, playbook_path)
            playbook = get_playbook(db_path, 84502)

            self.assertIsNotNone(playbook)
            self.assertEqual(playbook["allowed_ports"], [443])
            self.assertEqual(
                _derive_status(playbook, "HTTP/1.1 200 OK\nserver: nginx\n", "", 0),
                ("validated", None),
            )
            self.assertEqual(
                _derive_status(
                    playbook,
                    "HTTP/1.1 200 OK\nStrict-Transport-Security: max-age=31536000\n",
                    "",
                    0,
                ),
                ("not_validated", "not_validated"),
            )
            self.assertEqual(
                _derive_status(playbook, "", "connection refused", 1),
                ("port_closed", "port_closed"),
            )

    def test_manual_override_is_latest_result(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = tmp_path / "test.sqlite3"
            scan_path = tmp_path / "sample.nessus"
            initialize_database(db_path)
            scan_path.write_text(
                """
                <NessusClientData_v2>
                  <Report name="Example">
                    <ReportHost name="host1.example">
                      <ReportItem port="0" protocol="tcp" pluginID="19506" pluginName="Nessus Scan Information" severity="0" />
                    </ReportHost>
                  </Report>
                </NessusClientData_v2>
                """.strip()
            )
            import_nessus_scan(db_path, scan_path)

            self.assertTrue(
                override_result(
                    db_path,
                    19506,
                    "host1.example",
                    0,
                    "not_validated",
                    "false_positive",
                    "informational plugin",
                )
            )

            summary = get_validation_summary(db_path, 19506)
            results = get_latest_validation_results(db_path, 19506)

            self.assertEqual(summary, [("not_validated", 1)])
            self.assertEqual(results[0][0], "host1.example")
            self.assertEqual(results[0][2], "not_validated")
            self.assertEqual(results[0][3], "false_positive")
            self.assertEqual(results[0][4], "informational plugin")
            self.assertEqual(results[0][7], "manual")

    def test_csv_report_export(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = tmp_path / "test.sqlite3"
            scan_path = tmp_path / "sample.nessus"
            output_path = tmp_path / "report.csv"
            initialize_database(db_path)
            scan_path.write_text(
                """
                <NessusClientData_v2>
                  <Report name="Example">
                    <ReportHost name="host1.example">
                      <ReportItem port="0" protocol="tcp" pluginID="19506" pluginName="Nessus Scan Information" severity="0" />
                    </ReportHost>
                  </Report>
                </NessusClientData_v2>
                """.strip()
            )
            import_nessus_scan(db_path, scan_path)
            override_result(
                db_path,
                19506,
                "host1.example",
                0,
                "not_validated",
                "false_positive",
                "informational plugin",
            )

            export_plugin_report_csv(db_path, 19506, output_path)

            with output_path.open() as handle:
                rows = list(csv.reader(handle))

            self.assertEqual(
                rows[0],
                [
                    "host",
                    "port",
                    "status",
                    "reason",
                    "analyst_note",
                    "source",
                    "executed_at",
                    "command",
                ],
            )
            self.assertEqual(rows[1][0], "host1.example")
            self.assertEqual(rows[1][2], "not_validated")
            self.assertEqual(rows[1][3], "false_positive")
            self.assertEqual(rows[1][4], "informational plugin")
            self.assertEqual(rows[1][5], "manual")

    def test_starttls_argument_rendering_and_html_report(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = tmp_path / "test.sqlite3"
            playbook_path = tmp_path / "56984.json"
            scan_path = tmp_path / "sample.nessus"
            output_path = tmp_path / "report.html"
            initialize_database(db_path)
            scan_path.write_text(
                """
                <NessusClientData_v2>
                  <Report name="Example">
                    <ReportHost name="mail.example">
                      <ReportItem port="25" protocol="tcp" pluginID="56984" pluginName="SSL / TLS Versions Supported" severity="0" />
                    </ReportHost>
                  </Report>
                </NessusClientData_v2>
                """.strip()
            )
            import_nessus_scan(db_path, scan_path)
            playbook_path.write_text(
                """
                {
                  "plugin_id": 56984,
                  "finding_name": "SSL / TLS Versions Supported",
                  "service": "tls",
                  "port_logic": "use_scan_port",
                  "command_template": "openssl s_client -connect {host}:{port} {openssl_tls_args} -brief </dev/null",
                  "timeout_seconds": 30,
                  "allowed_ports": [25, 443, 587],
                  "blocked_ports": [],
                  "starttls_protocol_map": {"25": "smtp", "587": "smtp"},
                  "validated_if": ["connection established"],
                  "validated_if_absent": [],
                  "not_validated_if": [],
                  "not_validated_if_present": [],
                  "inconclusive_if": [],
                  "failure_reason_map": {},
                  "references": []
                }
                """.strip()
            )
            import_playbook(db_path, playbook_path)
            playbook = get_playbook(db_path, 56984)

            self.assertEqual(_build_openssl_tls_args(playbook, 25), "-starttls smtp")
            self.assertEqual(_build_openssl_tls_args(playbook, 587), "-starttls smtp")
            self.assertEqual(_build_openssl_tls_args(playbook, 443), "")
            self.assertEqual(_build_sslscan_starttls_args(playbook, 25), "--starttls-smtp")
            self.assertEqual(_build_testssl_starttls_args(playbook, 25), "--starttls smtp")
            self.assertEqual(_build_sslscan_starttls_args(playbook, 443), "")

            # Seed a validation run so the HTML report includes this plugin.
            override_result(db_path, 56984, "mail.example", 25, "validated", None, None)

            export_all_reports_html(db_path, output_path)
            html_text = output_path.read_text()
            self.assertIn("Nessus Parser Report", html_text)
            self.assertIn('"plugin_name": "SSL / TLS Versions Supported"', html_text)

    def test_matching_scan_playbook_ids(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = tmp_path / "test.sqlite3"
            scan_path = tmp_path / "sample.nessus"
            playbook_path = tmp_path / "84502.json"
            initialize_database(db_path)
            scan_path.write_text(
                """
                <NessusClientData_v2>
                  <Report name="Example">
                    <ReportHost name="host1.example">
                      <ReportItem port="443" protocol="tcp" pluginID="84502" pluginName="HSTS Missing From HTTPS Server" severity="1" />
                      <ReportItem port="22" protocol="tcp" pluginID="269984" pluginName="OpenSSH &lt; 10.1 / 10.1p1 Multiple Vulnerabilities" severity="1" />
                    </ReportHost>
                  </Report>
                </NessusClientData_v2>
                """.strip()
            )
            playbook_path.write_text(
                """
                {
                  "plugin_id": 84502,
                  "finding_name": "HSTS Missing From HTTPS Server",
                  "service": "https",
                  "port_logic": "use_scan_port",
                  "command_template": "curl -I https://{host}:{port}/",
                  "timeout_seconds": 20,
                  "allowed_ports": [443],
                  "blocked_ports": [],
                  "starttls_protocol_map": {},
                  "fallback_commands": [],
                  "version_rule": {},
                  "validated_if": [],
                  "validated_if_absent": ["strict-transport-security:"],
                  "not_validated_if": [],
                  "not_validated_if_present": ["strict-transport-security:"],
                  "inconclusive_if": ["connection refused"],
                  "failure_reason_map": {"connection refused": "port_closed"},
                  "references": []
                }
                """.strip()
            )
            import_playbook(db_path, playbook_path)

            matched = get_matching_scan_playbook_ids(db_path, scan_path, [84502, 269984])
            self.assertEqual(matched, [84502, 269984])

    def test_file_validation_does_not_persist_results_by_default(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = tmp_path / "test.sqlite3"
            scan_path = tmp_path / "sample.nessus"
            playbook_path = tmp_path / "84502.json"
            initialize_database(db_path)
            scan_path.write_text(
                """
                <NessusClientData_v2>
                  <Report name="Example">
                    <ReportHost name="host1.example">
                      <ReportItem port="443" protocol="tcp" pluginID="84502" pluginName="HSTS Missing From HTTPS Server" severity="1" />
                    </ReportHost>
                  </Report>
                </NessusClientData_v2>
                """.strip()
            )
            playbook_path.write_text(
                """
                {
                  "plugin_id": 84502,
                  "finding_name": "HSTS Missing From HTTPS Server",
                  "service": "https",
                  "port_logic": "use_scan_port",
                  "command_template": "printf 'HTTP/1.1 200 OK\\nserver: nginx\\n'",
                  "timeout_seconds": 20,
                  "allowed_ports": [443],
                  "blocked_ports": [],
                  "starttls_protocol_map": {},
                  "fallback_commands": [],
                  "version_rule": {},
                  "validated_if": [],
                  "validated_if_absent": ["strict-transport-security:"],
                  "not_validated_if": [],
                  "not_validated_if_present": ["strict-transport-security:"],
                  "inconclusive_if": [],
                  "failure_reason_map": {},
                  "references": []
                }
                """.strip()
            )
            import_playbook(db_path, playbook_path)

            output = validate_scan_file(db_path, scan_path, 84502)

            self.assertIn("persisted: no", output)
            self.assertEqual(get_latest_validation_results(db_path, 84502), [])

    def test_sanitize_database_removes_client_rows(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = tmp_path / "test.sqlite3"
            scan_path = tmp_path / "sample.nessus"
            initialize_database(db_path)
            scan_path.write_text(
                """
                <NessusClientData_v2>
                  <Report name="Example">
                    <ReportHost name="host1.example">
                      <ReportItem port="0" protocol="tcp" pluginID="19506" pluginName="Nessus Scan Information" severity="0" />
                    </ReportHost>
                  </Report>
                </NessusClientData_v2>
                """.strip()
            )
            import_nessus_scan(db_path, scan_path, store_findings=True)
            override_result(
                db_path,
                19506,
                "host1.example",
                0,
                "not_validated",
                "false_positive",
                "informational plugin",
            )

            result = sanitize_database(db_path)

            self.assertEqual(result["findings_deleted"], 1)
            self.assertEqual(result["validation_runs_deleted"], 1)
            self.assertEqual(list_findings(db_path), [])
            self.assertEqual(get_latest_validation_results(db_path, 19506), [])

    def test_scan_plugin_ids_exclude_informational_by_default(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            scan_path = tmp_path / "sample.nessus"
            scan_path.write_text(
                """
                <NessusClientData_v2>
                  <Report name="Example">
                    <ReportHost name="host1.example">
                      <ReportItem port="0" protocol="tcp" pluginID="19506" pluginName="Nessus Scan Information" severity="0" />
                      <ReportItem port="443" protocol="tcp" pluginID="84502" pluginName="HSTS Missing From HTTPS Server" severity="1" />
                    </ReportHost>
                  </Report>
                </NessusClientData_v2>
                """.strip()
            )

            self.assertEqual(list_scan_plugin_ids(scan_path), [84502])
            self.assertEqual(
                list_scan_plugin_ids(scan_path, include_informational=True),
                [19506, 84502],
            )

    def test_plugin_search_and_no_overwrite_playbook_generation(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = tmp_path / "test.sqlite3"
            scan_path = tmp_path / "sample.nessus"
            playbook_dir = tmp_path / "playbooks"
            initialize_database(db_path)
            scan_path.write_text(
                """
                <NessusClientData_v2>
                  <Report name="Example">
                    <ReportHost name="host1.example">
                      <ReportItem port="443" protocol="tcp" pluginID="21643" pluginName="SSL Cipher Suites Supported" severity="0" />
                    </ReportHost>
                  </Report>
                </NessusClientData_v2>
                """.strip()
            )
            import_nessus_scan(db_path, scan_path)

            rows = search_plugins(db_path, name_contains="cipher", limit=10)
            self.assertEqual(rows[0][0], 21643)

            playbook_dir.mkdir()
            existing = playbook_dir / "21643.json"
            existing.write_text('{"existing": true}\n')
            created = create_playbook_templates(rows, playbook_dir, overwrite=False)
            self.assertEqual(created, [])
            self.assertEqual(existing.read_text(), '{"existing": true}\n')


    def test_project_isolation_validation(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = tmp_path / "test.sqlite3"
            initialize_database(db_path)

            override_result(db_path, 84502, "host-a.example", 443, "validated", None, "project A", project_name="project_a")
            override_result(db_path, 84502, "host-b.example", 443, "not_validated", None, "project B", project_name="project_b")

            results_a = get_latest_validation_results(db_path, 84502, project_name="project_a")
            results_b = get_latest_validation_results(db_path, 84502, project_name="project_b")
            results_all = get_latest_validation_results(db_path, 84502, project_name=None)

            self.assertEqual(len(results_a), 1)
            self.assertEqual(results_a[0][0], "host-a.example")
            self.assertEqual(results_a[0][2], "validated")

            self.assertEqual(len(results_b), 1)
            self.assertEqual(results_b[0][0], "host-b.example")
            self.assertEqual(results_b[0][2], "not_validated")

            self.assertEqual(len(results_all), 2)

    def test_sanitize_db_project_scoped(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = tmp_path / "test.sqlite3"
            scan_path = tmp_path / "sample.nessus"
            initialize_database(db_path)
            scan_path.write_text(
                """
                <NessusClientData_v2>
                  <Report name="Example">
                    <ReportHost name="host1.example">
                      <ReportItem port="0" protocol="tcp" pluginID="19506" pluginName="Nessus Scan Information" severity="0" />
                    </ReportHost>
                  </Report>
                </NessusClientData_v2>
                """.strip()
            )
            import_nessus_scan(db_path, scan_path, store_findings=True, project_name="eng")
            import_nessus_scan(db_path, scan_path, store_findings=True, project_name="corp")
            override_result(db_path, 19506, "host1.example", 0, "validated", None, None, project_name="eng")
            override_result(db_path, 19506, "host1.example", 0, "not_validated", None, None, project_name="corp")

            result = sanitize_database(db_path, project_name="eng")
            self.assertEqual(result["findings_deleted"], 1)
            self.assertEqual(result["validation_runs_deleted"], 1)

            # corp data must be intact
            corp_results = get_latest_validation_results(db_path, 19506, project_name="corp")
            self.assertEqual(len(corp_results), 1)
            self.assertEqual(corp_results[0][2], "not_validated")

    def test_list_projects(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = tmp_path / "test.sqlite3"
            initialize_database(db_path)

            override_result(db_path, 84502, "host-a.example", 443, "validated", None, None, project_name="alpha")
            override_result(db_path, 84502, "host-b.example", 443, "not_validated", None, None, project_name="beta")

            projects = list_projects(db_path)
            project_names = [row[0] for row in projects]

            self.assertIn("alpha", project_names)
            self.assertIn("beta", project_names)
            self.assertEqual(len(projects), 2)
            for name, run_count, last_run in projects:
                self.assertEqual(run_count, 1)
                self.assertIsNotNone(last_run)


if __name__ == "__main__":
    unittest.main()
