
# Uspector – Copyright (c) 2026 Menahem Levinski

import contextlib
import io
import json
import sys
import unittest
from unittest.mock import Mock, patch

from uspector.cli import main


class TestCLI(unittest.TestCase):

    def run_cli(self, arguments):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            patch.object(sys, "argv", ["uspector", *arguments]),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            try:
                exit_code = main()
            except SystemExit as exc:
                exit_code = exc.code

        return exit_code, stdout.getvalue(), stderr.getvalue()

    @patch("uspector.cli.TLSScanner")
    def test_tls_command(self, mock_scanner_class):
        mock_scanner = mock_scanner_class.return_value
        mock_scanner.check_tls.return_value = {
            "hostname": "example.com",
            "error": None,
        }

        code, stdout, _ = self.run_cli(["tls", "example.com"])

        self.assertEqual(code, 0)
        self.assertIn("Uspector TLS Scan", stdout)
        mock_scanner.check_tls.assert_called_once_with("example.com", 443)

    @patch("uspector.cli.WebScanner")
    def test_web_command(self, mock_scanner_class):
        mock_scanner = mock_scanner_class.return_value
        mock_scanner.scan.return_value = {
            "target": "https://example.com",
            "error": None,
        }

        code, stdout, _ = self.run_cli(
            ["web", "https://example.com"]
        )

        self.assertEqual(code, 0)
        self.assertIn("Uspector Web Scan", stdout)
        mock_scanner.scan.assert_called_once_with(
            "https://example.com"
        )

    @patch("uspector.cli.DNSScanner")
    def test_dns_command(self, mock_scanner_class):
        mock_scanner = mock_scanner_class.return_value
        mock_scanner.scan.return_value = {
            "target": "example.com",
            "records": {},
            "email_security": {},
            "dnssec": {},
            "findings": [],
            "error": None,
        }

        code, stdout, _ = self.run_cli(["dns", "example.com"])

        self.assertEqual(code, 0)
        self.assertIn("Uspector DNS Scan", stdout)
        mock_scanner.scan.assert_called_once_with(
            "example.com",
            dkim_selector=None,
            include_dnssec=True,
        )

    @patch("uspector.cli.DNSScanner")
    def test_dns_json_output(self, mock_scanner_class):
        expected = {
            "target": "example.com",
            "records": {"A": ["192.0.2.1"]},
            "error": None,
        }
        mock_scanner_class.return_value.scan.return_value = expected

        code, stdout, _ = self.run_cli(
            ["dns", "example.com", "--json"]
        )

        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout), expected)

    @patch("uspector.cli.DNSScanner")
    def test_dns_options(self, mock_scanner_class):
        mock_scanner_class.return_value.scan.return_value = {
            "target": "example.com",
            "error": None,
        }

        code, _, _ = self.run_cli([
            "dns",
            "example.com",
            "--dkim-selector",
            "default",
            "--no-dnssec",
        ])

        self.assertEqual(code, 0)
        mock_scanner_class.return_value.scan.assert_called_once_with(
            "example.com",
            dkim_selector="default",
            include_dnssec=False,
        )

    @patch("uspector.cli.TLSScanner")
    def test_tls_json_output(self, mock_scanner_class):
        expected = {"hostname": "example.com", "error": None}
        mock_scanner_class.return_value.check_tls.return_value = expected

        code, stdout, _ = self.run_cli(
            ["tls", "example.com", "--json"]
        )

        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout), expected)

    @patch("uspector.cli.WebScanner")
    def test_web_error_returns_nonzero(self, mock_scanner_class):
        mock_scanner_class.return_value.scan.return_value = {
            "target": "https://example.com",
            "error": "Connection failed",
        }

        code, _, _ = self.run_cli(
            ["web", "https://example.com"]
        )

        self.assertEqual(code, 1)

    def test_missing_command_returns_error(self):
        code, _, stderr = self.run_cli([])

        self.assertNotEqual(code, 0)
        self.assertIn("command", stderr.lower())


if __name__ == "__main__":
    unittest.main()
