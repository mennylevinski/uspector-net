
# Uspector – Copyright (c) 2026 Menahem Levinski

import base64
import struct
import time
import unittest
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

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
        mock_sock.sendto.assert_called_once()

    def test_init_parameter_validation(self):
        for bad_timeout in (0, -1, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                DNSScanner(timeout=bad_timeout)
        for bad_type in ("2", True, None):
            with self.assertRaises(TypeError):
                DNSScanner(timeout=bad_type)
        with self.assertRaises(ValueError):
            DNSScanner(retries=0)
        with self.assertRaises(TypeError):
            DNSScanner(retries=True)
        for bad_port in (0, 65536, -5):
            with self.assertRaises(ValueError):
                DNSScanner(port=bad_port)
        with self.assertRaises(TypeError):
            DNSScanner(port=False)

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

    def test_email_zone_and_dnssec_evaluations(self):
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        spki_der = rsa_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        dkim_b64 = base64.b64encode(spki_der).decode("ascii")
        spf_many = (
            "v=spf1 ptr include:a.example include:b.example include:c.example "
            "include:d.example include:e.example include:f.example include:g.example "
            "include:h.example include:i.example include:j.example +all"
        )

        def fake_query(name, rtype="A", dnssec=True):
            if name == "_dmarc.example.com" and rtype == "TXT":
                return {
                    "status": "NOERROR",
                    "records": [{"type": "TXT", "value": "v=DMARC1; p=quarantine; sp=none; pct=50"}],
                }
            if name == "sel._domainkey.example.com" and rtype == "TXT":
                return {
                    "status": "NOERROR",
                    "records": [{"type": "TXT", "value": f"v=DKIM1; t=y; p={dkim_b64}"}],
                }
            if rtype == "TXT":
                return {"status": "NOERROR", "records": [{"type": "TXT", "value": spf_many}]}
            if rtype == "NS":
                return {"status": "NOERROR", "records": [{"type": "NS", "value": "ns1.example.com"}]}
            if rtype == "MX":
                return {"status": "NOERROR", "records": [{"type": "MX", "preference": 10, "exchange": "192.0.2.10"}]}
            if rtype == "SOA":
                return {"status": "NOERROR", "records": [{"type": "SOA", "refresh": 600, "retry": 600, "expire": 3600}]}
            if rtype == "CAA":
                return {"status": "NOERROR", "records": [{"type": "CAA", "tag": "contactemail", "value": "sec@example.com"}]}
            if rtype == "DNSKEY":
                return {"status": "NOERROR", "records": [{"type": "DNSKEY", "algorithm": 5}]}
            if rtype == "RRSIG":
                return {"status": "NOERROR", "records": [{"type": "RRSIG", "expiration": int(time.time()) - 10}]}
            return {"status": "NO_RECORDS", "records": []}

        scanner = DNSScanner(nameservers=["1.1.1.1"])
        with patch.object(scanner, "query", side_effect=fake_query):
            result = scanner.scan("example.com", dkim_selector="sel", include_dnssec=True)

        findings = result["findings"]
        self.assertIn("SPF record uses permissive '+all' policy", findings)
        self.assertIn("SPF record uses deprecated 'ptr' mechanism", findings)
        self.assertTrue(any("exceeds the 10-DNS-lookup limit" in f for f in findings))
        self.assertIn("DMARC subdomain policy (sp) is set to none", findings)
        self.assertIn("DMARC enforcement percentage (pct=50) is below 100%", findings)
        self.assertIn("DMARC record has no aggregate/forensic reporting URI (rua/ruf)", findings)
        self.assertIn("DKIM RSA key is below 2048 bits (1024 bits)", findings)
        self.assertIn("DKIM record is in test mode (t=y)", findings)
        self.assertIn("CAA records do not specify 'issue' or 'issuewild'", findings)
        self.assertIn("CAA records do not specify an 'iodef' reporting contact", findings)
        self.assertIn("Single NS record found; redundant nameservers recommended", findings)
        self.assertIn("MX target 192.0.2.10 appears to be an IP address", findings)
        self.assertIn("SOA retry timer is greater than or equal to refresh", findings)
        self.assertIn("SOA expire timer is below 7 days", findings)
        self.assertIn("Deprecated DNSSEC DNSKEY algorithm detected (5)", findings)
        self.assertIn("Expired DNSSEC RRSIG signature detected", findings)

    def test_parse_rr_tlsa_and_https_and_extended_checks(self):
        name_wire = b"\x07example\x03com\x00"
        tlsa_rdata = struct.pack("!BBB", 3, 1, 1) + b"\xaa\xbb"
        tlsa_pkt = name_wire + struct.pack("!HHIH", 52, 1, 60, len(tlsa_rdata)) + tlsa_rdata
        tlsa_rec, _ = DNSScanner._parse_rr(tlsa_pkt, 0)
        self.assertEqual((tlsa_rec["usage"], tlsa_rec["selector"], tlsa_rec["matching_type"]), (3, 1, 1))

        https_rdata = struct.pack("!H", 1) + b"\x00" + struct.pack("!HH", 1, 2) + b"h2"
        https_pkt = name_wire + struct.pack("!HHIH", 65, 1, 60, len(https_rdata)) + https_rdata
        https_rec, _ = DNSScanner._parse_rr(https_pkt, 0)
        self.assertEqual(https_rec["priority"], 1)
        self.assertEqual(https_rec["target"], ".")

        def fake_query(name, rtype="A", dnssec=True):
            if name == "example.com" and rtype == "CNAME":
                return {"status": "NOERROR", "records": [{"type": "CNAME", "value": "dead.example.net"}]}
            if name == "dead.example.net":
                return {"status": "NXDOMAIN", "records": []}
            if name == "_mta-sts.example.com" and rtype == "TXT":
                return {"status": "NOERROR", "records": [{"type": "TXT", "value": "v=STSv1; id=1"}]}
            if rtype == "A":
                return {"status": "NOERROR", "records": [{"type": "A", "value": "93.184.216.34"}]}
            return {"status": "NO_RECORDS", "records": []}

        scanner = DNSScanner(nameservers=["1.1.1.1"])
        with patch.object(scanner, "query", side_effect=fake_query):
            result = scanner.scan("example.com", include_dnssec=False, check_extended=True)

        self.assertTrue(result["extended"]["email_transport"]["mta_sts_found"])
        self.assertIn("Dangling CNAME target dead.example.net resolves to NXDOMAIN", result["findings"])


if __name__ == "__main__":
    unittest.main()
