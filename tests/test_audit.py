"""Offline regressions for the audit gate and encrypted report contents."""

import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from functools import partial
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "code"))

import requests
from rich.console import Console
from rich.progress import Progress

import main
from detector import TyposquatDetector
from input_requirements import package_name, parse_requirements_file
from protos.audit_schema_pb2 import AuditReport
from pypi_client import PyPIClient
from secure_logger import SecureLogger


def response(status=200, data=None):
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(data).encode()
    return result


def metadata(days=120):
    uploaded = datetime.now(timezone.utc) - timedelta(days=days)
    return {"info": {"version": "1.0"}, "urls": [
        {"upload_time_iso_8601": uploaded.isoformat()}
    ]}


class RequirementsTests(unittest.TestCase):
    def test_names_are_canonical_and_pep508_is_supported(self):
        self.assertEqual(package_name('Python._Dateutil[extra]>=2; python_version>"3"'),
                         "python-dateutil")

    def test_file_comments_and_blank_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requirements.txt"
            path.write_text('# comment\n\nRequests[socks]>=2 # note\nNumPy\n')
            self.assertEqual(parse_requirements_file(str(path)), ["requests", "numpy"])

    def test_unsupported_inputs_fail_with_file_and_line(self):
        for value in ("-r other.txt", "--index-url https://example.com", "./local",
                      "pkg @ https://example.com/pkg.whl", "requests nonsense"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "requirements.txt"
                path.write_text(f"# input\n{value}\n")
                with self.assertRaisesRegex(ValueError, r"requirements.txt:2:"):
                    parse_requirements_file(str(path))

    def test_missing_file_is_an_error(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "Cannot read requirements file"):
                parse_requirements_file(str(Path(directory) / "missing.txt"))

    def test_invalid_encoding_is_an_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requirements.txt"
            path.write_bytes(b"\xff")
            with self.assertRaisesRegex(ValueError, "Cannot read requirements file"):
                parse_requirements_file(str(path))


class DetectorTests(unittest.TestCase):
    def test_separator_aliases_of_popular_packages_are_not_typos(self):
        detector = TyposquatDetector()
        for name in ("scikit.learn", "SCIKIT___LEARN", "python.dateutil"):
            with self.subTest(name=name):
                self.assertIsNone(detector.check_typo(name))

    def test_nearest_target_wins_over_set_iteration_order(self):
        detector = TyposquatDetector()
        detector.POPULAR_PACKAGES = {"abcde", "abcedf"}
        self.assertEqual(detector.check_typo("abcdef"), "abcde")

    def test_common_misspelling_is_flagged(self):
        self.assertEqual(TyposquatDetector().check_typo("requsets"), "requests")


class ClientTests(unittest.TestCase):
    def test_only_404_means_missing(self):
        with patch("requests.Session.get", return_value=response(404)):
            self.assertIsNone(PyPIClient().get_metadata("not-a-real-package"))
        for status in (403, 429, 500):
            with self.subTest(status=status):
                with patch("requests.Session.get", return_value=response(status)):
                    with self.assertRaises(requests.HTTPError):
                        PyPIClient().get_metadata("requests")

    def test_invalid_metadata_is_rejected(self):
        for data in ([], None, {}, {"info": []}, {"info": {"version": None}},
                     {"info": {"version": ""}}):
            with self.subTest(data=data):
                with patch("requests.Session.get", return_value=response(data=data)):
                    with self.assertRaises(ValueError):
                        PyPIClient().get_metadata("requests")

    def test_earliest_file_determines_release_age(self):
        data = {"urls": [
            {"upload_time_iso_8601": "2026-10-22T00:00:00Z"},
            {"upload_time_iso_8601": "2026-01-01T02:00:00+02:00"},
        ]}
        self.assertEqual(PyPIClient().get_upload_time(data),
                         datetime(2026, 1, 1, tzinfo=timezone.utc))

    def test_current_release_fallback_ignores_malformed_dates(self):
        data = {"info": {"version": "1"}, "releases": {"1": [
            None, {}, {"upload_time_iso_8601": "not-a-date"},
            {"upload_time_iso_8601": "2026-01-01T00:00:00"},
            {"upload_time_iso_8601": "2026-01-02T00:00:00Z"},
        ]}}
        self.assertEqual(PyPIClient().get_upload_time(data),
                         datetime(2026, 1, 2, tzinfo=timezone.utc))

    def test_missing_or_invalid_dates_return_unknown(self):
        for data in ({}, {"urls": "invalid"}, {"releases": []},
                     {"urls": [{"upload_time_iso_8601": None}]}):
            with self.subTest(data=data):
                self.assertIsNone(PyPIClient().get_upload_time(data))


class AuditGateTests(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        console = Console(file=self.output, force_terminal=False, width=140)
        self.enterContext(patch.object(main, "console", console))
        self.enterContext(patch.object(main, "Progress", partial(Progress, console=console)))
        self.get = self.enterContext(patch("requests.Session.get"))
        self.get.return_value = response(data=metadata())

    def test_existing_old_release_passes(self):
        self.assertEqual(main.run_audit(["requests"], None, None), 0)
        self.assertIn("LOW", self.output.getvalue())

    def test_missing_package_blocks_gate(self):
        self.get.return_value = response(404)
        self.assertEqual(main.run_audit(["missing-project-example"], None, None), 1)

    def test_typo_blocks_gate_even_for_an_old_registered_package(self):
        self.assertEqual(main.run_audit(["requsets"], None, None), 1)

    def test_fresh_release_blocks_gate(self):
        self.get.return_value = response(data=metadata(days=1))
        self.assertEqual(main.run_audit(["requests"], None, None), 1)

    def test_unknown_age_does_not_pass_as_low_risk(self):
        self.get.return_value = response(data={"info": {"version": "1"}})
        self.assertEqual(main.run_audit(["requests"], None, None), 1)
        self.assertIn("WARNING", self.output.getvalue())

    def test_network_failure_returns_operational_error(self):
        self.get.side_effect = requests.Timeout("fixture timeout")
        self.assertEqual(main.run_audit(["requests"], None, None), 2)

    def test_bad_registry_payload_returns_operational_error(self):
        self.get.return_value = response(data={"info": []})
        self.assertEqual(main.run_audit(["requests"], None, None), 2)

    def test_equivalent_requirements_are_audited_once(self):
        self.assertEqual(main.run_audit(
            ["Python.Dateutil>=2", "python_dateutil", "PYTHON--DATEUTIL"], None, None), 0)
        self.get.assert_called_once_with(
            "https://pypi.org/pypi/python-dateutil/json", timeout=5)

    def test_invalid_input_is_rejected_before_any_lookup(self):
        for packages in ([], ["requests", "../local"], ["pkg @ https://example.com/pkg"]):
            with self.subTest(packages=packages):
                self.assertEqual(main.run_audit(packages, None, None), 2)
        self.get.assert_not_called()

    def test_missing_report_password_is_rejected_before_lookup(self):
        self.assertEqual(main.run_audit(["requests"], "report.gsbom", None), 2)
        self.get.assert_not_called()

    def test_registry_errors_survive_encryption_and_scan_continues(self):
        self.get.side_effect = [response(404), requests.Timeout("fixture timeout"),
                                response(data=metadata())]
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "report.gsbom")
            self.assertEqual(main.run_audit(["aaa-missing", "bbb-unavailable", "requests"],
                                            path, "test-password"), 2)
            payload = SecureLogger("test-password").load(path)
            report = AuditReport.FromString(payload)
            self.assertEqual([package.name for package in report.packages],
                             ["aaa-missing", "bbb-unavailable", "requests"])
            self.assertEqual([(alert.risk_type, alert.severity) for alert in report.alerts],
                             [("Slopsquatting", "CRITICAL"), ("Registry Error", "ERROR")])
            self.assertTrue(report.packages[-1].exists_in_registry)
            with self.assertRaisesRegex(ValueError, "Decryption failed"):
                SecureLogger("wrong-password").load(path)
            contents = bytearray(Path(path).read_bytes())
            contents[-1] ^= 1
            Path(path).write_bytes(contents)
            with self.assertRaisesRegex(ValueError, "Decryption failed"):
                SecureLogger("test-password").load(path)

    def test_report_write_failure_returns_error(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(main.run_audit(["requests"], directory, "password"), 2)

    def test_cli_uses_password_environment_variable(self):
        with patch.dict(os.environ, {"SLOPSHIELD_PASSWORD": "fixture-secret"}):
            with patch.object(main, "run_audit", return_value=1) as audit:
                self.assertEqual(main.main(["requests", "--save", "out.gsbom"]), 1)
                audit.assert_called_once_with(["requests"], "out.gsbom", "fixture-secret")

    def test_cli_explicit_password_overrides_environment(self):
        with patch.dict(os.environ, {"SLOPSHIELD_PASSWORD": "fixture-secret"}):
            with patch.object(main, "run_audit", return_value=0) as audit:
                self.assertEqual(main.main(["requests", "--password", "explicit"]), 0)
                audit.assert_called_once_with(["requests"], None, "explicit")

    def test_process_returns_error_for_empty_input_and_missing_file(self):
        script = str(Path(main.__file__).resolve())
        for arguments in ([], ["--file", "does-not-exist-fixture.txt"],
                          ["requests", "--save", "out.gsbom"]):
            with self.subTest(arguments=arguments):
                environment = dict(os.environ)
                environment.pop("SLOPSHIELD_PASSWORD", None)
                process = subprocess.run([sys.executable, script, *arguments],
                                         check=False, capture_output=True, env=environment, timeout=15)
                self.assertEqual(process.returncode, 2, process.stderr.decode())


if __name__ == "__main__":
    unittest.main()
