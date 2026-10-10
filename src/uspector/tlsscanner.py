# Uspector – Copyright (c) 2026 Menahem Levinski

import hashlib
import ipaddress
import math
import socket
import ssl
import time
import urllib.error
import urllib.request
import warnings

from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

# ====== TLS Scanner ======
class TLSScanner:
    """Inspect TLS configuration and certificate information for a server."""

    def __init__(self, timeout=5.0):
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise TypeError("timeout must be a positive number")

        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a finite positive number")

        self.timeout = float(timeout)

    # ====== Input Validation ======
    @staticmethod
    def _normalize_domain(domain):
        """Validate and normalize a DNS hostname or IP address."""

        if not isinstance(domain, str) or not domain.strip():
            raise ValueError("domain must be a non-empty string")

        domain = domain.strip().rstrip(".")

        if not domain:
            raise ValueError("domain must be a valid hostname")

        if any(char.isspace() for char in domain):
            raise ValueError("domain must not contain whitespace")

        if "://" in domain or "/" in domain or "\\" in domain:
            raise ValueError("provide a hostname or IP address, not a URL")

        # Accept IPv4 and IPv6 literals, including unbracketed IPv6.
        try:
            return ipaddress.ip_address(domain).compressed
        except ValueError:
            pass

        # Validate DNS label structure. Internationalized domain names
        # are normalized to ASCII using Python's built-in IDNA codec.
        try:
            ascii_domain = domain.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("invalid hostname") from exc

        if len(ascii_domain) > 253:
            raise ValueError("hostname is too long")

        labels = ascii_domain.split(".")

        for label in labels:
            if (
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or not all(
                    char.isalnum() or char == "-"
                    for char in label
                )
            ):
                raise ValueError("invalid hostname")

        return ascii_domain

    # ====== Certificate Conversion ======
    @staticmethod
    def _to_x509_certificate(certificate):
        """Convert supported certificate representations to an X.509 object."""

        if isinstance(certificate, x509.Certificate):
            return certificate

        if isinstance(certificate, str):
            certificate = certificate.encode("ascii")

        if isinstance(certificate, bytes):
            try:
                return x509.load_der_x509_certificate(certificate)
            except ValueError:
                return x509.load_pem_x509_certificate(certificate)

        public_bytes = getattr(certificate, "public_bytes", None)

        if callable(public_bytes):
            try:
                encoded = public_bytes()
            except TypeError:
                encoded = public_bytes(serialization.Encoding.DER)

            return TLSScanner._to_x509_certificate(encoded)

        raise TypeError("Unsupported certificate representation")

    # ====== Independent Hostname Validation ======
    @staticmethod
    def _certificate_hostname_matches(certificate, domain):
        """Match certificate SAN against a DNS hostname or IP address."""

        try:
            san = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
        except x509.ExtensionNotFound:
            return False

        try:
            ip = ipaddress.ip_address(domain)
        except ValueError:
            ip = None

        if ip is not None:
            return ip in san.get_values_for_type(x509.IPAddress)

        domain = domain.lower().rstrip(".")
        dns_names = san.get_values_for_type(x509.DNSName)

        for name in dns_names:
            name = name.lower().rstrip(".")

            if name == domain:
                return True

            if name.startswith("*."):
                suffix = name[2:]

                if (
                    domain.endswith("." + suffix)
                    and domain.count(".") == suffix.count(".") + 1
                ):
                    return True

        return False

    # ====== Certificate Chain ======
    def _get_certificate_chain(self, tls_sock, leaf_certificate):
        """Return available parsed certificates, with the leaf first."""

        chain = [leaf_certificate]
        leaf_fingerprint = leaf_certificate.fingerprint(hashes.SHA256())

        get_chain = getattr(tls_sock, "get_unverified_chain", None)

        if not callable(get_chain):
            return chain

        try:
            raw_chain = get_chain()
        except Exception:
            return chain

        for item in raw_chain or []:
            try:
                certificate = self._to_x509_certificate(item)
            except (TypeError, ValueError):
                continue

            fingerprint = certificate.fingerprint(hashes.SHA256())

            if fingerprint == leaf_fingerprint:
                continue

            if not any(
                fingerprint == existing.fingerprint(hashes.SHA256())
                for existing in chain
            ):
                chain.append(certificate)

        return chain

    # ====== OCSP Revocation Check ======
    def _check_ocsp(self, certificate, certificate_chain):
        """
        Query the certificate's OCSP responder.

        OCSP status is reported as unvalidated. This method does not verify
        the response signature, responder authorization, certificate ID,
        or response freshness, so it cannot establish revocation status.
        """

        result = {
            "status": "Unavailable",
            "url": None,
            "response_validated": False,
        }

        if certificate is None:
            result["status"] = "Certificate Unavailable"
            return result

        try:
            aia = certificate.extensions.get_extension_for_class(
                x509.AuthorityInformationAccess
            ).value

            for access in aia:
                if (
                    access.access_method == AuthorityInformationAccessOID.OCSP
                    and isinstance(
                        access.access_location,
                        x509.UniformResourceIdentifier,
                    )
                ):
                    result["url"] = access.access_location.value
                    break

        except x509.ExtensionNotFound:
            result["status"] = "URL Not Available"
            return result

        except Exception:
            return result

        if not result["url"]:
            result["status"] = "URL Not Available"
            return result

        # Find a candidate issuer certificate.
        # Matching names alone do not establish issuer authenticity.
        issuer = None
        certificate_fingerprint = certificate.fingerprint(hashes.SHA256())

        for candidate in certificate_chain or []:
            if candidate.fingerprint(hashes.SHA256()) == certificate_fingerprint:
                continue

            if candidate.subject == certificate.issuer:
                issuer = candidate
                break

        if issuer is None:
            result["status"] = "Issuer Certificate Unavailable"
            return result

        try:
            request = (
                ocsp.OCSPRequestBuilder()
                .add_certificate(certificate, issuer, hashes.SHA1())
                .build()
            )

            request_data = request.public_bytes(serialization.Encoding.DER)

            http_request = urllib.request.Request(
                result["url"],
                data=request_data,
                headers={
                    "Content-Type": "application/ocsp-request",
                    "Accept": "application/ocsp-response",
                },
                method="POST",
            )

            with urllib.request.urlopen(
                http_request,
                timeout=self.timeout,
            ) as response:
                response_data = response.read(1_000_001)

            if len(response_data) > 1_000_000:
                result["status"] = "Response Too Large"
                return result

            ocsp_response = ocsp.load_der_ocsp_response(response_data)

            if (
                ocsp_response.response_status
                != ocsp.OCSPResponseStatus.SUCCESSFUL
            ):
                result["status"] = (
                    "Responder Error: "
                    f"{ocsp_response.response_status.name}"
                )
                return result

            # Parsed status only; response authenticity and freshness
            # have not been validated.
            certificate_status = ocsp_response.certificate_status

            if certificate_status == ocsp.OCSPCertStatus.GOOD:
                result["status"] = "REPORTED_GOOD_UNVALIDATED"

            elif certificate_status == ocsp.OCSPCertStatus.REVOKED:
                result["status"] = "REPORTED_REVOKED_UNVALIDATED"

            else:
                result["status"] = "REPORTED_UNKNOWN_UNVALIDATED"

        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            ValueError,
            ssl.SSLError,
        ):
            result["status"] = "Unavailable"

        except Exception:
            result["status"] = "Unavailable"

        return result

    # ====== TLS Connection Inspection ======
    def _inspect_connection(self, domain, port, context):
        """Open a TLS connection and collect certificate details."""

        raw_sock = socket.create_connection(
            (domain, port),
            timeout=self.timeout,
        )

        try:
            with context.wrap_socket(
                raw_sock,
                server_hostname=domain,
            ) as tls_sock:
                cert_der = tls_sock.getpeercert(binary_form=True)

                if not cert_der:
                    raise ssl.SSLError(
                        "The server did not provide a certificate"
                    )

                certificate = x509.load_der_x509_certificate(cert_der)

                return {
                    "tls_version": tls_sock.version(),
                    "cipher": tls_sock.cipher(),
                    "alpn": tls_sock.selected_alpn_protocol(),
                    "certificate_obj": certificate,
                    "certificate_chain": self._get_certificate_chain(
                        tls_sock,
                        certificate,
                    ),
                    "fingerprint": hashlib.sha256(cert_der).hexdigest().upper(),
                }

        finally:
            try:
                raw_sock.close()
            except OSError:
                pass

    # ====== TLS Protocol Support ======
    def _check_tls_protocol_support(self, domain, port=443):
        """
        Probe TLS 1.0 through TLS 1.3.

        Returned versions are confirmed successful probes only. A failed
        probe does not prove a protocol is disabled.
        """

        supported_versions = []

        versions = [
            ("TLSv1.0", ssl.TLSVersion.TLSv1, "TLSv1"),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1, "TLSv1.1"),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2, "TLSv1.2"),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3, "TLSv1.3"),
        ]

        for version_name, tls_version, expected in versions:
            raw_sock = None

            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    context.minimum_version = tls_version
                    context.maximum_version = tls_version

                if tls_version in (
                    ssl.TLSVersion.TLSv1,
                    ssl.TLSVersion.TLSv1_1,
                ):
                    context.set_ciphers("DEFAULT:@SECLEVEL=0")

                raw_sock = socket.create_connection(
                    (domain, port),
                    timeout=self.timeout,
                )

                with context.wrap_socket(
                    raw_sock,
                    server_hostname=domain,
                ) as tls_sock:
                    if tls_sock.version() == expected:
                        supported_versions.append(version_name)

            except (ssl.SSLError, OSError, ValueError):
                pass

            finally:
                if raw_sock is not None:
                    try:
                        raw_sock.close()
                    except OSError:
                        pass

        return supported_versions

    # ====== TLS Check ======
    def check_tls(self, domain, port=443):
        """Scan a domain and return a structured dictionary of findings."""

        domain = self._normalize_domain(domain)

        if isinstance(port, bool) or not isinstance(port, int):
            raise TypeError("port must be an integer")

        if not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")

        result = {
            "domain": domain,
            "port": port,
            "findings": [],
            "verdict": "INCONCLUSIVE",
            "connection_status": "Failed",
            "diagnostic_handshake": "Not Attempted",
            "certificate_trusted": False,
            "hostname_valid": None,
            "resolved_ips": [],
            "supported_tls_versions": [],
        }

        certificate = None
        certificate_chain = []

        # DNS resolution.
        try:
            addresses = socket.getaddrinfo(
                domain,
                port,
                type=socket.SOCK_STREAM,
            )

            result["resolved_ips"] = list(
                dict.fromkeys(item[4][0] for item in addresses)
            )

        except OSError as exc:
            result["error"] = f"DNS resolution failed: {exc}"
            return result

        if not result["resolved_ips"]:
            result["error"] = "DNS returned no usable addresses"
            return result

        # A DNS failure should not be confused with a certificate problem.
        # The connection attempt itself determines the final connection status.
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.set_alpn_protocols(["h2", "http/1.1"])

        start_time = time.perf_counter()

        try:
            inspected = self._inspect_connection(domain, port, context)

            result.update({
                "connection_status": "Passed",
                "diagnostic_handshake": "Not Needed",
                "certificate_trusted": True,
                "hostname_valid": True,
                "tls_version": inspected["tls_version"],
                "cipher": inspected["cipher"],
                "alpn": inspected["alpn"],
                "fingerprint": inspected["fingerprint"],
            })

            certificate = inspected["certificate_obj"]
            certificate_chain = inspected["certificate_chain"]
      
        except ssl.SSLCertVerificationError as exc:
            result["ssl_error"] = str(exc)
            error_text = str(exc).lower()

            if (
                "hostname mismatch" in error_text
                or "not valid for" in error_text
                or "doesn't match" in error_text
                or "ip address mismatch" in error_text
            ):
                result["hostname_valid"] = False
                result["findings"].append(
                    "Certificate hostname does not match the requested domain"
                )

            elif "expired" in error_text:
                result["findings"].append(
                    "TLS certificate has expired"
                )

            elif "self-signed" in error_text:
                result["findings"].append(
                    "TLS certificate chain contains a self-signed certificate"
                )

            elif (
                "unable to get local issuer" in error_text
                or "unable to verify the first certificate" in error_text
            ):
                result["findings"].append(
                    "TLS certificate chain could not be verified to a trusted issuer"
                )

            else:
                result["findings"].append(
                    f"TLS certificate verification failed: {exc}"
                )

            # Diagnostic-only retry. This never marks the connection trusted.
            diagnostic_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            diagnostic_context.check_hostname = False
            diagnostic_context.verify_mode = ssl.CERT_NONE
            diagnostic_context.set_alpn_protocols(["h2", "http/1.1"])

            try:
                inspected = self._inspect_connection(
                    domain,
                    port,
                    diagnostic_context,
                )

                result.update({
                    "diagnostic_handshake": "Passed",
                    "tls_version": inspected["tls_version"],
                    "cipher": inspected["cipher"],
                    "alpn": inspected["alpn"],
                    "fingerprint": inspected["fingerprint"],
                })

                certificate = inspected["certificate_obj"]
                certificate_chain = inspected["certificate_chain"]

            except (ssl.SSLError, OSError, ValueError) as diagnostic_exc:
                result["diagnostic_handshake"] = "Failed"
                result["diagnostic_error"] = str(diagnostic_exc)

                result["findings"].append(
                    "TLS handshake failed: the server may require an unsupported "
                    "legacy protocol or cipher suite"
                )

        except (ssl.SSLError, OSError, ValueError) as exc:
            result["ssl_error"] = str(exc)

            # Retry with weaker legacy settings for diagnostics only.
            diagnostic_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            diagnostic_context.check_hostname = False
            diagnostic_context.verify_mode = ssl.CERT_NONE
            diagnostic_context.set_alpn_protocols(["h2", "http/1.1"])

            try:
                diagnostic_context.set_ciphers("DEFAULT:@SECLEVEL=0")

                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    diagnostic_context.minimum_version = ssl.TLSVersion.TLSv1

                inspected = self._inspect_connection(
                    domain,
                    port,
                    diagnostic_context,
                )

                result.update({
                    "diagnostic_handshake": "Passed",
                    "tls_version": inspected["tls_version"],
                    "cipher": inspected["cipher"],
                    "alpn": inspected["alpn"],
                    "fingerprint": inspected["fingerprint"],
                })

                certificate = inspected["certificate_obj"]
                certificate_chain = inspected["certificate_chain"]

            except (ssl.SSLError, OSError, ValueError) as diagnostic_exc:
                result["diagnostic_handshake"] = "Failed"
                result["diagnostic_error"] = str(diagnostic_exc)

                result["findings"].append(
                    "TLS handshake failed: the server may require an unsupported "
                    "legacy protocol or cipher suite"
                )

        finally:
            result["latency_ms"] = round(
                (time.perf_counter() - start_time) * 1000,
                1,
            )

        
        # Certificate details.
        if certificate is not None:
            hostname_matches = self._certificate_hostname_matches(
                certificate,
                domain,
            )
            result["hostname_valid"] = hostname_matches

            if not hostname_matches:
                finding = (
                    "Certificate hostname does not match "
                    "the requested domain"
                )

                if finding not in result["findings"]:
                    result["findings"].append(finding)

            result["subject"] = certificate.subject.rfc4514_string()
            result["issuer"] = certificate.issuer.rfc4514_string()

            not_before = certificate.not_valid_before_utc
            not_after = certificate.not_valid_after_utc

            result["not_before"] = not_before.isoformat()
            result["not_after"] = not_after.isoformat()

            # Public-key type and strength.
            public_key = certificate.public_key()

            if isinstance(public_key, rsa.RSAPublicKey):
                result["public_key_type"] = "RSA"
                result["public_key_bits"] = public_key.key_size

                if public_key.key_size < 2048:
                    result["findings"].append(
                        f"Weak RSA key: {public_key.key_size} bits"
                    )

            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                result["public_key_type"] = "EC"
                result["public_key_bits"] = public_key.key_size

                if public_key.key_size < 224:
                    result["findings"].append(
                        f"Weak elliptic-curve key: {public_key.key_size} bits"
                    )

            else:
                result["public_key_type"] = type(public_key).__name__

                key_size = getattr(public_key, "key_size", None)

                if key_size is not None:
                    result["public_key_bits"] = key_size

            # Subject Alternative Names.
            try:
                san_ext = certificate.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                )

                result["san"] = san_ext.value.get_values_for_type(
                    x509.DNSName
                )

                result["san_ip_addresses"] = [
                    str(address)
                    for address in san_ext.value.get_values_for_type(
                        x509.IPAddress
                    )
                ]

            except x509.ExtensionNotFound:
                result["san"] = []
                result["san_ip_addresses"] = []

            # Subject and issuer name equality is only an indication.
            result["self_signed"] = (
                certificate.subject == certificate.issuer
            )

            if result["self_signed"]:
                result["findings"].append(
                    "Certificate subject and issuer are identical"
                )

            self._check_certificate_validity(result, certificate)

            result["ocsp"] = self._check_ocsp(
                certificate,
                certificate_chain,
            )

            if result["ocsp"]["status"] == "REPORTED_REVOKED_UNVALIDATED":
                result["findings"].append(
                    "OCSP responder reported the certificate as revoked; "
                    "the response has not been cryptographically validated"
                )

        # Probe TLS versions. Failed probes are not evidence that versions
        # are disabled; only successful negotiations are reported here.
        result["supported_tls_versions"] = (
            self._check_tls_protocol_support(domain, port)
        )

        supported_versions = result["supported_tls_versions"]

        if "TLSv1.0" in supported_versions:
            result["findings"].append(
                "Server supports deprecated TLSv1.0"
            )

        if "TLSv1.1" in supported_versions:
            result["findings"].append(
                "Server supports deprecated TLSv1.1"
            )

        # Weak cipher suite indicators for the negotiated connection.
        cipher = result.get("cipher")

        if cipher:
            cipher_name = cipher[0].upper()

            if any(
                weak_name in cipher_name
                for weak_name in ("RC4", "3DES", "DES")
            ):
                result["findings"].append(
                    f"Weak TLS cipher suite: {cipher[0]}"
                )

        # Final verdict.
        if result["connection_status"] == "Passed":
            if (
                result["hostname_valid"] is False
                or result["findings"]
            ):
                result["verdict"] = "WARNING"
            else:
                result["verdict"] = "SECURE"

        elif (
            result["diagnostic_handshake"] == "Passed"
            and result["findings"]
        ):
            result["verdict"] = "WARNING"

        else:
            result["verdict"] = "INCONCLUSIVE"

        return result

    # ====== Certificate Validity ======
    @staticmethod
    def _check_certificate_validity(result, certificate):
        """Check certificate validity dates and report days remaining."""

        now = datetime.now(timezone.utc)
        not_before = certificate.not_valid_before_utc
        not_after = certificate.not_valid_after_utc

        if now < not_before:
            result["findings"].append("Certificate is not yet valid")

        seconds_remaining = (not_after - now).total_seconds()
        days_remaining = math.floor(seconds_remaining / 86400)

        result["days_remaining"] = days_remaining

        if seconds_remaining < 0:
            result["findings"].append("Certificate has expired")

        elif days_remaining <= 30:
            result["findings"].append(
                f"Certificate expires in {days_remaining} days"
            )

    # ====== Name To String ======
    @staticmethod
    def _name_to_string(name):
        """Format a cryptography X.509 name."""

        return name.rfc4514_string()
