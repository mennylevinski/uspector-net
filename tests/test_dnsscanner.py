
# Uspector – Copyright (c) 2026 Menahem Levinski

import unittest
from unittest.mock import patch

from uspector import DNSScanner


class TestDNSScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = DNSScanner()

    def test_encode_name(self):
        encoded = self.scanner._encode_name("example.com")

        self.assertEqual(
            encoded,
            b"\x07example\x03com\x00",
        )

    def test_encode_name_with_trailing_dot(self):
        encoded = self.scanner._encode_name("example.com.")

        self.assertEqual(
            encoded,
            b"\x07example\x03com\x00",
        )

    def test_reverse_lookup_name_ipv4(self):
        result = self.scanner._reverse_name("8.8.8.8")

        self.assertEqual(result, "8.8.8.8.in-addr.arpa")

    def test_scan_returns_dictionary(self):
        # Prevent network access. The query results are intentionally
        # supplied by the mock; this test checks the public result structure.
        with patch.object(
            self.scanner,
            "query",
            side_effect=OSError("Simulated DNS failure"),
        ):
            result = self.scanner.scan(
                "example.com",
                include_dnssec=False,
            )

        self.assertIsInstance(result, dict)
        self.assertIn("target", result)
        self.assertIn("records", result)
        self.assertIn("email_security", result)
        self.assertIn("dnssec", result)
        self.assertIn("findings", result)
        self.assertIn("error", result)

    def test_scan_reports_target(self):
        with patch.object(
            self.scanner,
            "query",
            side_effect=OSError("Simulated DNS failure"),
        ):
            result = self.scanner.scan(
                "example.com",
                include_dnssec=False,
            )

        self.assertEqual(result["target"], "example.com")

    def test_invalid_target(self):
        # Adjust this test if the scanner reports invalid input in its
        # result dictionary rather than raising ValueError.
        with self.assertRaises((ValueError, TypeError)):
            self.scanner.scan("")

    def test_dns_query_failure_does_not_escape_as_unhandled_error(self):
        with patch.object(
            self.scanner,
            "query",
            side_effect=OSError("Simulated DNS failure"),
        ):
            result = self.scanner.scan(
                "example.com",
                include_dnssec=False,
            )

        self.assertIsInstance(result, dict)
        self.assertTrue(
            result.get("error") or result.get("findings") is not None,
            f"Unexpected result: {result}",
        )


if __name__ == "__main__":
    unittest.main()
