
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
        expected = {
            "domain": "example.com",
            "error": None,
        }
        mock_scanner.check_tls.return_value = expected
        mock_scanner.format_scan.return_value = "Uspector TLS Scan: example.com:443"

        code, stdout, _ = self.run_cli(["tls", "example.com"])

        self.assertEqual(code, 0)
        self.assertIn("Uspector TLS Scan", stdout)
        mock_scanner.check_tls.assert_called_once_with("example.com", 443)
        mock_scanner.format_scan.assert_called_once_with(expected)

    @patch("uspector.cli.WebScanner")
    def test_web_command(self, mock_scanner_class):
        mock_scanner = mock_scanner_class.return_value
        expected = {
            "target": "https://example.com",
            "error": None,
        }
        mock_scanner.scan.return_value = expected
        mock_scanner.format_scan.return_value = "Uspector Web Scan: https://example.com"

        code, stdout, _ = self.run_cli(
            ["web", "https://example.com"]
        )

        self.assertEqual(code, 0)
        self.assertIn("Uspector Web Scan", stdout)
        mock_scanner.scan.assert_called_once_with(
            "https://example.com"
        )
        mock_scanner.format_scan.assert_called_once_with(expected)

    @patch("uspector.cli.DNSScanner")
    def test_dns_command(self, mock_scanner_class):
        mock_scanner = mock_scanner_class.return_value
        expected = {
            "target": "example.com",
            "records": {},
            "email_security": {},
            "dnssec": {},
            "findings": [],
            "error": None,
        }
        mock_scanner.scan.return_value = expected
        mock_scanner.format_scan.return_value = "Uspector DNS Scan: example.com"

        code, stdout, _ = self.run_cli(["dns", "example.com"])

        self.assertEqual(code, 0)
        self.assertIn("Uspector DNS Scan", stdout)
        mock_scanner.scan.assert_called_once_with(
            "example.com",
            dkim_selector=None,
            include_dnssec=True,
        )
        mock_scanner.format_scan.assert_called_once_with(expected)

    @patch("uspector.cli.PHPScanner")
    def test_php_command(self, mock_scanner_class):
        mock_scanner = mock_scanner_class.return_value
        expected = {
            "target": "https://example.com",
            "verdict": "NO ISSUES DETECTED",
        }
        mock_scanner.scan.return_value = expected
        mock_scanner.format_scan.return_value = (
            "Uspector PHP Security Scan: https://example.com"
        )

        code, stdout, _ = self.run_cli(["php", "https://example.com"])

        self.assertEqual(code, 0)
        self.assertIn("Uspector PHP Security Scan", stdout)
        mock_scanner.scan.assert_called_once_with("https://example.com")
        mock_scanner.format_scan.assert_called_once_with(expected)

    @patch("uspector.cli.PHPScanner")
    def test_php_json_output(self, mock_scanner_class):
        expected = {
            "target": "https://example.com",
            "php_detected": True,
            "verdict": "INFORMATIONAL",
        }
        mock_scanner_class.return_value.scan.return_value = expected

        code, stdout, _ = self.run_cli(
            ["php", "https://example.com", "--json"]
        )

        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout), expected)

    @patch("uspector.cli.PHPScanner")
    def test_php_error_returns_nonzero(self, mock_scanner_class):
        mock_scanner_class.return_value.scan.return_value = {
            "target": "https://example.com",
            "error": "Connection failed",
        }

        code, _, _ = self.run_cli(["php", "https://example.com"])

        self.assertEqual(code, 1)

    @patch("uspector.cli.TLSScanner")
    def test_tls_handshake_failure_returns_nonzero(self, mock_scanner_class):
        mock_scanner = mock_scanner_class.return_value
        mock_scanner.check_tls.return_value = {
            "domain": "example.com",
            "connection_status": "Failed",
            "diagnostic_handshake": "Failed",
            "verdict": "INCONCLUSIVE",
            "error": None,
        }
        mock_scanner.format_scan.return_value = "TLS failed"

        code, _, _ = self.run_cli(["tls", "example.com"])

        self.assertEqual(code, 1)

    @patch("uspector.cli.DNSScanner")
    def test_dns_all_queries_failed_returns_nonzero(self, mock_scanner_class):
        mock_scanner = mock_scanner_class.return_value
        mock_scanner.scan.return_value = {
            "target": "example.com",
            "records": {
                "A": {"status": "DNS_ERROR", "records": []},
                "AAAA": {"status": "DNS_ERROR", "records": []},
            },
            "error": None,
        }
        mock_scanner.format_scan.return_value = "DNS failed"

        code, _, _ = self.run_cli(["dns", "example.com"])

        self.assertEqual(code, 1)

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

    @patch("uspector.cli.WebScanner")
    @patch("uspector.cli.TLSScanner")
    @patch("uspector.cli.DNSScanner")
    def test_extended_cli_flags(self, mock_dns_cls, mock_tls_cls, mock_web_cls):
        mock_dns_cls.return_value.scan.return_value = {"target": "example.com", "error": None}
        mock_dns_cls.return_value.format_scan.return_value = "DNS ok"
        code, _, _ = self.run_cli(["dns", "example.com", "-t", "4", "--no-extended"])
        self.assertEqual(code, 0)
        mock_dns_cls.assert_called_once_with(timeout=4.0)
        mock_dns_cls.return_value.scan.assert_called_once_with(
            "example.com",
            dkim_selector=None,
            include_dnssec=True,
            check_extended=False,
        )

        mock_tls_cls.return_value.check_tls.return_value = {"domain": "example.com", "error": None}
        mock_tls_cls.return_value.format_scan.return_value = "TLS ok"
        code, _, _ = self.run_cli([
            "tls",
            "example.com",
            "-p",
            "587",
            "--starttls",
            "smtp",
            "--probe-weak-ciphers",
        ])
        self.assertEqual(code, 0)
        mock_tls_cls.return_value.check_tls.assert_called_once_with(
            "example.com",
            587,
            starttls="smtp",
            probe_weak_ciphers=True,
        )

        mock_web_cls.return_value.scan.return_value = {"target": "https://example.com", "error": None}
        mock_web_cls.return_value.format_scan.return_value = "Web ok"
        code, _, _ = self.run_cli([
            "web",
            "https://example.com",
            "--no-private",
            "--check-metadata",
        ])
        self.assertEqual(code, 0)
        mock_web_cls.assert_called_once_with(
            timeout=15.0,
            allow_private=False,
            check_metadata=True,
        )


if __name__ == "__main__":
    unittest.main()
