# Uspector – Copyright (c) 2026 Menahem Levinski

import unittest
from unittest.mock import patch

from uspector import TLSScanner

class TestTLSScanner(unittest.TestCase):

    def test_default_timeout(self):
        scanner = TLSScanner()
        self.assertEqual(scanner.timeout, 5.0)

    def test_custom_timeout(self):
        scanner = TLSScanner(timeout=10.0)
        self.assertEqual(scanner.timeout, 10.0)

    def test_rejects_zero_timeout(self):
        with self.assertRaises(ValueError):
            TLSScanner(timeout=0)

    def test_rejects_negative_timeout(self):
        with self.assertRaises(ValueError):
            TLSScanner(timeout=-1)

    def test_rejects_invalid_timeout(self):
        with self.assertRaises((TypeError, ValueError)):
            TLSScanner(timeout="invalid")

    def test_rejects_invalid_hostname(self):
        scanner = TLSScanner()
        with self.assertRaises(ValueError):
            scanner.check_tls("https://example.com")

    def test_rejects_invalid_port(self):
        scanner = TLSScanner()
        with self.assertRaises((ValueError, TypeError)):
            scanner.check_tls("example.com", 70000)

    @patch("uspector.tlsscanner.socket.getaddrinfo")
    def test_dns_resolution_failure(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = OSError("DNS lookup failed")

        scanner = TLSScanner()
        result = scanner.check_tls("example.com")

        self.assertIsInstance(result, dict)
        self.assertTrue(
            any(
                word in str(result).lower()
                for word in ("dns", "resolve", "error", "failed")
            ),
            f"Unexpected result: {result}",
        )

# --- Output ---
if __name__ == "__main__":
    unittest.main()
