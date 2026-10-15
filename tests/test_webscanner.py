# Uspector – Copyright (c) 2026 Menahem Levinski

import unittest
from unittest.mock import Mock, patch

from uspector import WebScanner


class TestWebScanner(unittest.TestCase):

    def test_default_timeout(self):
        scanner = WebScanner()
        self.assertEqual(scanner.timeout, 15.0)

    def test_custom_timeout(self):
        scanner = WebScanner(timeout=10.0)
        self.assertEqual(scanner.timeout, 10.0)

    def test_rejects_zero_timeout(self):
        with self.assertRaises(ValueError):
            WebScanner(timeout=0)

    def test_rejects_negative_timeout(self):
        with self.assertRaises(ValueError):
            WebScanner(timeout=-1)

    def test_rejects_invalid_timeout(self):
        with self.assertRaises((TypeError, ValueError)):
            WebScanner(timeout="invalid")

    @patch("uspector.webscanner.requests.get")
    def test_successful_scan_returns_dictionary(self, mock_get):
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.headers = {
            "Content-Type": "text/html; charset=utf-8",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
        }
        response.cookies = []
        response.text = "<html><title>Example</title><body>Hello</body></html>"
        response.history = []
        mock_get.return_value = response

        scanner = WebScanner()
        result = scanner.scan("https://example.com")

        self.assertIsInstance(result, dict)
        self.assertIn("target", result)
        self.assertIn("findings", result)
        self.assertIn("error", result)
        self.assertEqual(result["target"], "https://example.com")

    @patch("uspector.webscanner.requests.get")
    def test_http_failure_is_reported(self, mock_get):
        mock_get.side_effect = OSError("Simulated connection failure")

        scanner = WebScanner()
        result = scanner.scan("https://example.com")

        self.assertIsInstance(result, dict)
        self.assertTrue(
            result.get("error") or result.get("findings") is not None,
            f"Unexpected result: {result}",
        )

    @patch("uspector.webscanner.requests.get")
    def test_request_uses_configured_timeout(self, mock_get):
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.headers = {"Content-Type": "text/html"}
        response.cookies = []
        response.text = "<html></html>"
        response.history = []
        mock_get.return_value = response

        scanner = WebScanner(timeout=7.0)
        scanner.scan("https://example.com")

        mock_get.assert_called_once()
        self.assertEqual(
            mock_get.call_args.kwargs.get("timeout"),
            7.0,
        )


if __name__ == "__main__":
    unittest.main()
