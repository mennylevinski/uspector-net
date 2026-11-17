# Uspector – Copyright (c) 2026 Menahem Levinski

import datetime
import ipaddress
import socket
import ssl
import unittest
from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

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

    @staticmethod
    def _build_cert(
        common_name="example.com",
        san_dns=None,
        san_ips=None,
        aia_ocsp=None,
        aia_ca_issuers=None,
        issuer_name=None,
        key=None,
    ):
        key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        issuer = issuer_name or subject
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=60))
        )
        san_entries = [x509.DNSName(name) for name in (san_dns or [])]
        san_entries.extend(
            x509.IPAddress(ipaddress.ip_address(ip)) for ip in (san_ips or [])
        )
        if san_entries:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_entries),
                critical=False,
            )
        aia_entries = []
        if aia_ocsp:
            aia_entries.append(
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier(aia_ocsp),
                )
            )
        if aia_ca_issuers:
            aia_entries.append(
                x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier(aia_ca_issuers),
                )
            )
        if aia_entries:
            builder = builder.add_extension(
                x509.AuthorityInformationAccess(aia_entries),
                critical=False,
            )
        return builder.sign(key, hashes.SHA256()), key

    def test_rejects_single_label_wildcard_san(self):
        cert, _ = self._build_cert(san_dns=["*.com"])
        self.assertFalse(
            TLSScanner._certificate_hostname_matches(cert, "example.com")
        )

    def test_ocsp_blocks_private_and_metadata_urls(self):
        issuer_cert, _ = self._build_cert(common_name="Test CA")
        leaf_cert, _ = self._build_cert(
            common_name="example.com",
            issuer_name=issuer_cert.subject,
            aia_ocsp="http://169.254.169.254/latest/meta-data/",
        )
        scanner = TLSScanner()
        with patch("uspector.tlsscanner.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", 80))
            ]
            with patch("uspector.tlsscanner.requests.Session") as mock_session:
                res = scanner._check_ocsp(leaf_cert, [leaf_cert, issuer_cert])

        self.assertEqual(res["status"], "Blocked Non-Public URL")
        mock_session.return_value.__enter__.return_value.request.assert_not_called()

    def test_ocsp_uses_aia_ca_issuers_fallback_when_chain_incomplete(self):
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        issuer_cert, _ = self._build_cert(common_name="Test CA", key=ca_key)
        leaf_cert, _ = self._build_cert(
            common_name="example.com",
            issuer_name=issuer_cert.subject,
            aia_ocsp="http://ocsp.example.test/ocsp",
            aia_ca_issuers="http://ca.example.test/ca.der",
        )
        issuer_der = issuer_cert.public_bytes(serialization.Encoding.DER)

        scanner = TLSScanner()
        with patch.object(
            scanner,
            "_fetch_public_http_bytes",
            side_effect=[issuer_der, ValueError("stop after issuer fetch")],
        ) as mock_fetch:
            res = scanner._check_ocsp(leaf_cert, [leaf_cert])

        self.assertEqual(mock_fetch.call_count, 2)
        self.assertEqual(mock_fetch.call_args_list[0].args[0], "http://ca.example.test/ca.der")
        self.assertEqual(mock_fetch.call_args_list[1].args[0], "http://ocsp.example.test/ocsp")
        self.assertEqual(res["status"], "Unavailable")

    def test_self_signed_not_duplicated_and_diagnostic_verdict_is_warning(self):
        cert, _ = self._build_cert(common_name="example.com", san_dns=["example.com"])
        scanner = TLSScanner()
        inspected = {
            "tls_version": "TLSv1.3",
            "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
            "alpn": "h2",
            "certificate_obj": cert,
            "certificate_chain": [cert],
            "fingerprint": "AA",
            "peer_ip": "93.184.216.34",
        }
        with (
            patch(
                "uspector.tlsscanner.socket.getaddrinfo",
                return_value=[(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))],
            ),
            patch.object(
                scanner,
                "_inspect_connection",
                side_effect=[ssl.SSLCertVerificationError("self-signed certificate"), inspected],
            ),
            patch.object(scanner, "_check_ocsp", return_value={"status": "URL Not Available", "url": None, "response_validated": False}),
            patch.object(scanner, "_check_tls_protocol_support", return_value=["TLSv1.3"]),
        ):
            result = scanner.check_tls("example.com")

        self.assertEqual(result["verdict"], "WARNING")
        self.assertIn("TLS certificate is self-signed and not trusted", result["findings"])
        self.assertNotIn("Certificate subject and issuer are identical", result["findings"])

    def test_ip_literal_omits_sni_server_hostname(self):
        cert, _ = self._build_cert(common_name="1.1.1.1", san_ips=["1.1.1.1"])
        cert_der = cert.public_bytes(serialization.Encoding.DER)

        raw_sock = MagicMock()
        tls_sock = MagicMock()
        tls_sock.__enter__.return_value = tls_sock
        tls_sock.__exit__.return_value = False
        tls_sock.getpeercert.return_value = cert_der
        tls_sock.version.return_value = "TLSv1.3"
        tls_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        tls_sock.selected_alpn_protocol.return_value = None
        tls_sock.getpeername.return_value = ("1.1.1.1", 443)

        context = MagicMock()
        context.wrap_socket.return_value = tls_sock

        scanner = TLSScanner()
        with patch("uspector.tlsscanner.socket.create_connection", return_value=raw_sock):
            scanner._inspect_connection("1.1.1.1", 443, context)

        context.wrap_socket.assert_called_once_with(raw_sock, server_hostname=None)

# --- Output ---
if __name__ == "__main__":
    unittest.main()
