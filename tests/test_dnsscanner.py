
# Uspector – Copyright (c) 2026 Menahem Levinski

import struct
import unittest
from unittest.mock import MagicMock, patch

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

        self.assertEqual(result, "8.8.8.8.in-addr.arpa.")

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
        result = self.scanner.scan("")
        self.assertTrue(result.get("error"))

        non_string = self.scanner.scan(None)
        self.assertTrue(non_string.get("error"))

    def test_explicit_empty_nameservers_preserved(self):
        scanner = DNSScanner(nameservers=[])
        self.assertEqual(scanner.nameservers, [])
        result = scanner.query("example.com", "A")
        self.assertEqual(result["status"], "DNS_ERROR")

    def test_parse_rr_preserves_root_dot_and_checks_rdata_bounds(self):
        # Null MX RR: name="example.com", type=15, class=1, ttl=60, rdlength=3, pref=0, exchange="."
        name_wire = b"\x07example\x03com\x00"
        rdata = struct.pack("!H", 0) + b"\x00"
        packet = name_wire + struct.pack("!HHIH", 15, 1, 60, len(rdata)) + rdata
        record, next_off = DNSScanner._parse_rr(packet, 0)
        self.assertEqual(record["exchange"], ".")
        self.assertEqual(next_off, len(packet))

        # Truncated RDATA (rdlength=3, but name needs 5 bytes) must raise ValueError
        bad_rdata = b"\x03abc\x00"
        bad_packet = name_wire + struct.pack("!HHIH", 5, 1, 60, 3) + bad_rdata
        with self.assertRaises(ValueError):
            DNSScanner._parse_rr(bad_packet, 0)

    def test_exchange_ignores_wrong_source_ip_and_txid(self):
        txid = 0x1234
        valid_resp = struct.pack("!HHHHHH", txid, 0x8180, 0, 0, 0, 0)
        wrong_ip_resp = struct.pack("!HHHHHH", txid, 0x8180, 0, 0, 0, 0)
        wrong_txid_resp = struct.pack("!HHHHHH", 0x9999, 0x8180, 0, 0, 0, 0)

        mock_sock = MagicMock()
        mock_sock.__enter__.return_value = mock_sock
        mock_sock.__exit__.return_value = False
        mock_sock.recvfrom.side_effect = [
            (wrong_ip_resp, ("192.0.2.99", 53)),
            (wrong_txid_resp, ("1.1.1.1", 53)),
            (valid_resp, ("1.1.1.1", 53)),
        ]

        scanner = DNSScanner(nameservers=["1.1.1.1"], timeout=1.0, retries=1)
        with patch("uspector.dnsscanner.socket.socket", return_value=mock_sock):
            packet, _ = scanner._exchange("1.1.1.1", b"\x12\x34" + b"\x00" * 10, txid)

        self.assertEqual(packet, valid_resp)
        self.assertEqual(mock_sock.recvfrom.call_count, 3)

    def test_scan_deduplicates_cname_and_tightens_email_checks(self):
        cname_rec = {"name": "sub.example.com", "type": "CNAME", "value": "target.example.com"}

        def fake_query(name, rtype="A", dnssec=True):
            if name == "_dmarc.sub.example.com" and rtype == "TXT":
                return {
                    "status": "NOERROR",
                    "records": [{"type": "TXT", "value": "v=DMARC1; p=NONE"}],
                }
            if rtype in ("A", "AAAA"):
                return {"status": "NOERROR", "records": [dict(cname_rec)]}
            if rtype == "CNAME":
                return {"status": "NO_RECORDS", "records": []}
            if rtype == "TXT":
                return {
                    "status": "NOERROR",
                    "records": [{"type": "TXT", "value": "v=spf10 invalid"}],
                }
            if rtype == "MX":
                return {"status": "NOERROR", "records": [dict(cname_rec)]}
            return {"status": "NO_RECORDS", "records": []}

        scanner = DNSScanner(nameservers=["1.1.1.1"])
        with patch.object(scanner, "query", side_effect=fake_query):
            result = scanner.scan("sub.example.com", include_dnssec=False)

        self.assertEqual(len(result["records"]["CNAME"]["records"]), 1)
        self.assertEqual(result["email_security"]["spf"]["status"], "MISSING")
        self.assertIn("Missing SPF record", result["findings"])
        self.assertIn("DMARC policy is set to none", result["findings"])
        self.assertIn("No MX records found", result["findings"])
        formatted = scanner.format_scan(result)
        self.assertNotIn("priority ?", formatted)

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
