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
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

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

    def test_certificate_hygiene_chain_quality_cipher_and_protocol_posture(self):
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        now = datetime.datetime.now(datetime.timezone.utc)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Weak Int CA")])
        root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])
        intermediate_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(root_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=10))
            .not_valid_after(now - datetime.timedelta(days=1))
            .sign(ca_key, hashes.SHA256())
        )

        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]))
            .issuer_name(ca_name)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=500))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(
                x509.CRLDistributionPoints([
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier("http://crl.example.test/ca.crl")],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        class _WeakHashCertProxy:
            def __init__(self, wrapped):
                self._wrapped = wrapped

            @property
            def signature_hash_algorithm(self):
                return hashes.SHA1()

            def __getattr__(self, name):
                return getattr(self._wrapped, name)

        proxied_leaf = _WeakHashCertProxy(leaf_cert)
        proxied_intermediate = _WeakHashCertProxy(intermediate_cert)

        scanner = TLSScanner()
        inspected = {
            "tls_version": "TLSv1.2",
            "cipher": ("AES256-GCM-SHA384", "TLSv1.2", 256),
            "alpn": "http/1.1",
            "certificate_obj": proxied_leaf,
            "certificate_chain": [proxied_leaf, proxied_intermediate],
            "has_chain_api": True,
            "fingerprint": "BB",
            "peer_ip": "93.184.216.34",
        }
        with (
            patch(
                "uspector.tlsscanner.socket.getaddrinfo",
                return_value=[(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))],
            ),
            patch.object(scanner, "_inspect_connection", return_value=inspected),
            patch.object(
                scanner,
                "_check_ocsp",
                return_value={"status": "URL Not Available", "url": None, "response_validated": False},
            ),
            patch.object(scanner, "_check_tls_protocol_support", return_value=["TLSv1.0"]),
        ):
            result = scanner.check_tls("example.com")

        findings = result["findings"]
        self.assertIn("Weak certificate signature algorithm: SHA1", findings)
        self.assertIn("Certificate validity period exceeds 398 days (501 days)", findings)
        self.assertIn("Leaf certificate has BasicConstraints CA=True", findings)
        self.assertIn("Certificate ExtendedKeyUsage does not include serverAuth", findings)
        self.assertIn("Intermediate certificate in chain has expired", findings)
        self.assertIn("Weak signature algorithm in intermediate certificate: SHA1", findings)
        self.assertIn("Weak RSA key in intermediate certificate: 1024 bits", findings)
        self.assertIn("Server only supports deprecated TLS protocols", findings)
        self.assertIn("TLS cipher suite lacks forward secrecy: AES256-GCM-SHA384", findings)
        self.assertEqual(result["crl_urls"], ["http://crl.example.test/ca.crl"])
        self.assertFalse(result["has_sct"])
        self.assertFalse(result["tls13_supported"])

    def test_missing_intermediate_reported_only_when_chain_api_available(self):
        issuer_cert, _ = self._build_cert(common_name="Test CA")
        leaf_cert, _ = self._build_cert(
            common_name="example.com",
            san_dns=["example.com"],
            issuer_name=issuer_cert.subject,
        )
        res_with_api = {"self_signed": False, "findings": []}
        TLSScanner._check_certificate_chain_quality(res_with_api, [leaf_cert], has_chain_api=True)
        self.assertIn("Server did not send intermediate certificate(s)", res_with_api["findings"])

        res_without_api = {"self_signed": False, "findings": []}
        TLSScanner._check_certificate_chain_quality(res_without_api, [leaf_cert], has_chain_api=False)
        self.assertNotIn("Server did not send intermediate certificate(s)", res_without_api["findings"])

    def test_ocsp_cryptographic_and_freshness_validation(self):
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        issuer_cert, _ = self._build_cert(common_name="Test CA", key=ca_key)
        leaf_cert, _ = self._build_cert(
            common_name="example.com",
            issuer_name=issuer_cert.subject,
            aia_ocsp="http://ocsp.example.test/ocsp",
            key=ca_key,
        )
        now = datetime.datetime.now(datetime.timezone.utc)

        valid_ocsp = (
            ocsp.OCSPResponseBuilder()
            .add_response(
                cert=leaf_cert,
                issuer=issuer_cert,
                algorithm=hashes.SHA1(),
                cert_status=ocsp.OCSPCertStatus.GOOD,
                this_update=now - datetime.timedelta(minutes=5),
                next_update=now + datetime.timedelta(hours=12),
                revocation_time=None,
                revocation_reason=None,
            )
            .responder_id(ocsp.OCSPResponderEncoding.HASH, issuer_cert)
            .sign(ca_key, hashes.SHA256())
        )
        scanner = TLSScanner()
        with patch.object(
            scanner,
            "_fetch_public_http_bytes",
            return_value=valid_ocsp.public_bytes(serialization.Encoding.DER),
        ):
            res_good = scanner._check_ocsp(
                leaf_cert,
                [leaf_cert, issuer_cert],
                certificate_trusted=True,
            )
        self.assertEqual(res_good["status"], "GOOD")
        self.assertTrue(res_good["response_validated"])
        self.assertTrue(res_good["signature_valid"])
        self.assertTrue(res_good["fresh"])

        # Expired next_update & wrong signing key
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_cert, _ = self._build_cert(common_name="Rogue Responder", key=other_key)
        stale_bad_sig = (
            ocsp.OCSPResponseBuilder()
            .add_response(
                cert=leaf_cert,
                issuer=issuer_cert,
                algorithm=hashes.SHA1(),
                cert_status=ocsp.OCSPCertStatus.GOOD,
                this_update=now - datetime.timedelta(days=2),
                next_update=now - datetime.timedelta(hours=1),
                revocation_time=None,
                revocation_reason=None,
            )
            .responder_id(ocsp.OCSPResponderEncoding.HASH, other_cert)
            .sign(other_key, hashes.SHA256())
        )
        with patch.object(
            scanner,
            "_fetch_public_http_bytes",
            return_value=stale_bad_sig.public_bytes(serialization.Encoding.DER),
        ):
            res_bad = scanner._check_ocsp(
                leaf_cert,
                [leaf_cert, issuer_cert],
                certificate_trusted=True,
            )
        self.assertEqual(res_bad["status"], "REPORTED_GOOD_UNVALIDATED")
        self.assertFalse(res_bad["response_validated"])
        self.assertFalse(res_bad["signature_valid"])
        self.assertFalse(res_bad["fresh"])

    def test_starttls_validation_and_smtp_negotiation(self):
        scanner = TLSScanner()
        with self.assertRaises(ValueError):
            scanner.check_tls("example.com", 25, starttls="ssh")

        sock = MagicMock()
        sock.recv.side_effect = [bytes([b]) for b in b"220 mail.example.com ESMTP\r\n250-OK\r\n250 STARTTLS\r\n220 Ready\r\n"]
        TLSScanner._negotiate_starttls(sock, "smtp")
        sent = b"".join(call.args[0] for call in sock.sendall.call_args_list)
        self.assertIn(b"EHLO uspector.local\r\n", sent)
        self.assertIn(b"STARTTLS\r\n", sent)

# --- Output ---
if __name__ == "__main__":
    unittest.main()
