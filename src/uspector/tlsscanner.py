# Uspector – Copyright (c) 2026 Menahem Levinski

import hashlib
import ipaddress
import math
import socket
import ssl
import time
import warnings

from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin, urlparse

import requests

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa

from ._http import PinnedIPAdapter, validate_public_http_url


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
                    "." in suffix
                    and not suffix.startswith(".")
                    and domain.endswith("." + suffix)
                    and domain.count(".") == suffix.count(".") + 1
                ):
                    return True

        return False

    @staticmethod
    def _is_ip_literal(domain):
        try:
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            return False

    @staticmethod
    def _validate_public_http_url(url, return_all=False):
        return validate_public_http_url(
            url,
            error_prefix="AIA URL",
            resolver=socket.getaddrinfo,
            return_all=return_all,
        )

    def _fetch_public_http_bytes(
        self,
        url,
        method="GET",
        data=None,
        headers=None,
        max_bytes=1_000_000,
    ):
        current_url = url
        pinned_ips = {}

        with requests.Session() as session:
            session.trust_env = False
            adapter = PinnedIPAdapter(pinned_ips)
            session.mount("http://", adapter)
            session.mount("https://", adapter)

            for _ in range(4):
                host, port, dest_ip = self._validate_public_http_url(
                    current_url,
                    return_all=True,
                )
                pinned_ips[(host, port)] = dest_ip

                response = session.request(
                    method=method,
                    url=current_url,
                    data=data if method == "POST" else None,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=False,
                    stream=True,
                    verify=True,
                )

                try:
                    if response.is_redirect or response.is_permanent_redirect:
                        location = response.headers.get("Location")
                        if not location:
                            raise ValueError("Redirect without Location header.")
                        current_url = urljoin(current_url, location)
                        if method == "POST" and response.status_code in (301, 302, 303):
                            method = "GET"
                            data = None
                        continue

                    response.raise_for_status()

                    content = bytearray()
                    for chunk in response.iter_content(chunk_size=8192):
                        if not chunk:
                            continue
                        remaining = (max_bytes + 1) - len(content)
                        if remaining <= 0:
                            break
                        content.extend(chunk[:remaining])
                        if len(content) > max_bytes:
                            break

                    return bytes(content)
                finally:
                    response.close()

        raise ValueError("Too many redirects while querying AIA URL.")

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

    # ====== Signature Verification ======
    @staticmethod
    def _verify_signature(public_key, signature, data, hash_algorithm):
        """Verify an X.509 or OCSP signature against a candidate public key."""
        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                if hash_algorithm is None:
                    return False
                try:
                    public_key.verify(
                        signature,
                        data,
                        padding.PKCS1v15(),
                        hash_algorithm,
                    )
                    return True
                except InvalidSignature:
                    public_key.verify(
                        signature,
                        data,
                        padding.PSS(
                            mgf=padding.MGF1(hash_algorithm),
                            salt_length=padding.PSS.AUTO,
                        ),
                        hash_algorithm,
                    )
                    return True

            if isinstance(public_key, ec.EllipticCurvePublicKey):
                if hash_algorithm is None:
                    return False
                public_key.verify(signature, data, ec.ECDSA(hash_algorithm))
                return True

            if isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                public_key.verify(signature, data)
                return True

        except (InvalidSignature, TypeError, ValueError):
            return False

        return False

    # ====== OCSP Revocation Check ======
    def _validate_ocsp_response(
        self,
        ocsp_response,
        certificate,
        issuer,
        certificate_trusted,
    ):
        """Validate OCSP CertID, freshness, and cryptographic signature."""
        now = datetime.now(timezone.utc)
        serial_matches = ocsp_response.serial_number == certificate.serial_number
        if serial_matches:
            resp_in_hash = getattr(ocsp_response, "issuer_name_hash", None)
            resp_ik_hash = getattr(ocsp_response, "issuer_key_hash", None)
            resp_hash_alg = getattr(ocsp_response, "hash_algorithm", None)
            if (
                isinstance(resp_in_hash, (bytes, bytearray))
                and isinstance(resp_ik_hash, (bytes, bytearray))
                and isinstance(resp_hash_alg, hashes.HashAlgorithm)
            ):
                try:
                    expected_req = (
                        ocsp.OCSPRequestBuilder()
                        .add_certificate(certificate, issuer, resp_hash_alg)
                        .build()
                    )
                    serial_matches = (
                        bytes(resp_in_hash) == expected_req.issuer_name_hash
                        and bytes(resp_ik_hash) == expected_req.issuer_key_hash
                    )
                except Exception:
                    serial_matches = False

        this_update = getattr(ocsp_response, "this_update_utc", None)
        next_update = getattr(ocsp_response, "next_update_utc", None)
        is_fresh = True
        if this_update is not None and this_update > now + timedelta(minutes=5):
            is_fresh = False
        if next_update is not None and next_update < now:
            is_fresh = False

        signer_key = None
        responder_certs = getattr(ocsp_response, "certificates", None) or []
        resp_key_hash = getattr(ocsp_response, "responder_key_hash", None)
        resp_name = getattr(ocsp_response, "responder_name", None)

        if responder_certs:
            for candidate in responder_certs:
                name_match = resp_name is not None and candidate.subject == resp_name
                key_match = False
                if resp_key_hash is not None:
                    try:
                        candidate_ski = x509.SubjectKeyIdentifier.from_public_key(
                            candidate.public_key()
                        ).digest
                        key_match = candidate_ski == resp_key_hash
                    except Exception:
                        key_match = False
                if not (name_match or key_match):
                    continue

                if candidate.issuer != issuer.subject:
                    continue
                if now < candidate.not_valid_before_utc or now > candidate.not_valid_after_utc:
                    continue

                try:
                    eku = candidate.extensions.get_extension_for_class(
                        x509.ExtendedKeyUsage
                    ).value
                    if ExtendedKeyUsageOID.OCSP_SIGNING not in eku:
                        continue
                except x509.ExtensionNotFound:
                    continue

                if self._verify_signature(
                    issuer.public_key(),
                    candidate.signature,
                    candidate.tbs_certificate_bytes,
                    candidate.signature_hash_algorithm,
                ):
                    signer_key = candidate.public_key()
                    break

        if signer_key is None and (
            resp_name is None or resp_name == issuer.subject or not responder_certs
        ):
            signer_key = issuer.public_key()

        sig_valid = False
        if signer_key is not None:
            sig_valid = self._verify_signature(
                signer_key,
                ocsp_response.signature,
                ocsp_response.tbs_response_bytes,
                ocsp_response.signature_hash_algorithm,
            )

        validated = bool(
            serial_matches
            and is_fresh
            and sig_valid
            and certificate_trusted
        )

        return {
            "serial_matches": serial_matches,
            "fresh": is_fresh,
            "signature_valid": sig_valid,
            "validated": validated,
        }

    def _check_ocsp(self, certificate, certificate_chain, certificate_trusted=False):
        """
        Query and validate the certificate's OCSP responder.
        """

        result = {
            "status": "Unavailable",
            "url": None,
            "response_validated": False,
        }

        if certificate is None:
            result["status"] = "Certificate Unavailable"
            return result

        aia = None
        ca_issuers_urls = []

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
                    and not result["url"]
                ):
                    result["url"] = access.access_location.value
                elif (
                    access.access_method == AuthorityInformationAccessOID.CA_ISSUERS
                    and isinstance(
                        access.access_location,
                        x509.UniformResourceIdentifier,
                    )
                ):
                    ca_issuers_urls.append(access.access_location.value)

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

        # Fallback for Python <3.13 (no get_unverified_chain) or incomplete server chains.
        if issuer is None:
            for ca_url in ca_issuers_urls:
                try:
                    issuer_bytes = self._fetch_public_http_bytes(
                        ca_url,
                        method="GET",
                        headers={"Accept": "application/pkix-cert,application/x-x509-ca-cert,*/*"},
                    )
                    if len(issuer_bytes) > 1_000_000:
                        continue
                    candidate = self._to_x509_certificate(issuer_bytes)
                    if (
                        candidate.fingerprint(hashes.SHA256()) != certificate_fingerprint
                        and candidate.subject == certificate.issuer
                    ):
                        issuer = candidate
                        break
                except (
                    requests.RequestException,
                    TimeoutError,
                    OSError,
                    ValueError,
                    TypeError,
                    ssl.SSLError,
                ):
                    continue

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

            response_data = self._fetch_public_http_bytes(
                result["url"],
                method="POST",
                data=request_data,
                headers={
                    "Content-Type": "application/ocsp-request",
                    "Accept": "application/ocsp-response",
                },
            )

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

            validation = self._validate_ocsp_response(
                ocsp_response,
                certificate,
                issuer,
                certificate_trusted,
            )
            result["signature_valid"] = validation["signature_valid"]
            result["fresh"] = validation["fresh"]
            result["response_validated"] = validation["validated"]

            if not validation["serial_matches"]:
                result["status"] = "Serial Mismatch"
                return result

            certificate_status = ocsp_response.certificate_status

            if validation["validated"]:
                if certificate_status == ocsp.OCSPCertStatus.GOOD:
                    result["status"] = "GOOD"
                elif certificate_status == ocsp.OCSPCertStatus.REVOKED:
                    result["status"] = "REVOKED"
                else:
                    result["status"] = "UNKNOWN"
            else:
                if certificate_status == ocsp.OCSPCertStatus.GOOD:
                    result["status"] = "REPORTED_GOOD_UNVALIDATED"
                elif certificate_status == ocsp.OCSPCertStatus.REVOKED:
                    result["status"] = "REPORTED_REVOKED_UNVALIDATED"
                else:
                    result["status"] = "REPORTED_UNKNOWN_UNVALIDATED"

        except ValueError as exc:
            if "private or restricted" in str(exc) or "localhost" in str(exc) or "scheme" in str(exc).lower():
                result["status"] = "Blocked Non-Public URL"
            else:
                result["status"] = "Unavailable"

        except (
            requests.RequestException,
            TimeoutError,
            OSError,
            ssl.SSLError,
        ):
            result["status"] = "Unavailable"

        except Exception:
            result["status"] = "Unavailable"

        return result

    @staticmethod
    def _recv_line(sock):
        buf = bytearray()
        while len(buf) < 4096:
            ch = sock.recv(1)
            if not ch:
                break
            buf.extend(ch)
            if ch == b"\n":
                break
        return buf.decode("ascii", errors="replace")

    MAX_STARTTLS_LINES = 64

    @classmethod
    def _read_smtp_reply(cls, sock):
        lines = []
        for _ in range(cls.MAX_STARTTLS_LINES):
            line = cls._recv_line(sock)
            if not line:
                break
            lines.append(line)
            if len(line) >= 4 and line[3] == " ":
                break
            if len(line) < 4:
                break
        else:
            raise OSError("STARTTLS server sent too many continuation lines")
        return "".join(lines)

    @classmethod
    def _negotiate_starttls(cls, raw_sock, starttls):
        proto = starttls.lower()
        if proto == "smtp":
            banner = cls._read_smtp_reply(raw_sock)
            if not banner.startswith("220"):
                raise OSError("Unexpected SMTP banner before STARTTLS")
            raw_sock.sendall(b"EHLO uspector.local\r\n")
            ehlo = cls._read_smtp_reply(raw_sock)
            if "250" not in ehlo:
                raise OSError("SMTP EHLO rejected before STARTTLS")
            raw_sock.sendall(b"STARTTLS\r\n")
            reply = cls._read_smtp_reply(raw_sock)
            if not reply.startswith("220"):
                raise OSError("SMTP server rejected STARTTLS")
        elif proto == "imap":
            banner = cls._recv_line(raw_sock)
            if "OK" not in banner.upper():
                raise OSError("Unexpected IMAP banner before STARTTLS")
            raw_sock.sendall(b"a001 STARTTLS\r\n")
            tagged_ok = False
            for _ in range(cls.MAX_STARTTLS_LINES):
                reply = cls._recv_line(raw_sock)
                if not reply:
                    break
                upper_reply = reply.lstrip().upper()
                if upper_reply.startswith("A001 "):
                    tagged_ok = upper_reply.startswith("A001 OK")
                    break
            if not tagged_ok:
                raise OSError("IMAP server rejected STARTTLS")
        elif proto == "ftp":
            banner = cls._read_smtp_reply(raw_sock)
            if not banner.startswith("220"):
                raise OSError("Unexpected FTP banner before AUTH TLS")
            raw_sock.sendall(b"AUTH TLS\r\n")
            reply = cls._read_smtp_reply(raw_sock)
            if not reply.startswith("234"):
                raise OSError("FTP server rejected AUTH TLS")

    # ====== TLS Connection Inspection ======
    def _inspect_connection(
        self,
        domain,
        port,
        context,
        connect_host=None,
        starttls=None,
    ):
        """Open a TLS connection and collect certificate details."""

        target_host = connect_host or domain
        is_ip = self._is_ip_literal(domain)
        server_hostname = None if is_ip else domain

        raw_sock = socket.create_connection(
            (target_host, port),
            timeout=self.timeout,
        )

        try:
            if starttls:
                self._negotiate_starttls(raw_sock, starttls)

            has_chain_api = callable(
                getattr(ssl.SSLSocket, "get_unverified_chain", None)
            )
            with context.wrap_socket(
                raw_sock,
                server_hostname=server_hostname,
            ) as tls_sock:
                cert_der = tls_sock.getpeercert(binary_form=True)

                if not cert_der:
                    raise ssl.SSLError(
                        "The server did not provide a certificate"
                    )

                certificate = x509.load_der_x509_certificate(cert_der)

                try:
                    peer_ip = tls_sock.getpeername()[0]
                except OSError:
                    peer_ip = target_host

                return {
                    "tls_version": tls_sock.version(),
                    "cipher": tls_sock.cipher(),
                    "alpn": tls_sock.selected_alpn_protocol(),
                    "certificate_obj": certificate,
                    "certificate_chain": self._get_certificate_chain(
                        tls_sock,
                        certificate,
                    ),
                    "has_chain_api": has_chain_api,
                    "fingerprint": hashlib.sha256(cert_der).hexdigest().upper(),
                    "peer_ip": peer_ip,
                }

        finally:
            try:
                raw_sock.close()
            except OSError:
                pass

    # ====== TLS Protocol Support ======
    def _check_tls_protocol_support(
        self,
        domain,
        port=443,
        connect_host=None,
        connect_hosts=None,
        starttls=None,
    ):
        """
        Probe TLS 1.0 through TLS 1.3.

        Returned versions are confirmed successful probes only. A failed
        probe does not prove a protocol is disabled.
        """

        supported_versions = []
        hosts = (
            list(connect_hosts)
            if connect_hosts
            else [connect_host or domain]
        )
        server_hostname = None if self._is_ip_literal(domain) else domain

        versions = [
            ("TLSv1.0", ssl.TLSVersion.TLSv1, "TLSv1"),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1, "TLSv1.1"),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2, "TLSv1.2"),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3, "TLSv1.3"),
        ]

        for version_name, tls_version, expected in versions:
            for target_host in hosts:
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
                        (target_host, port),
                        timeout=self.timeout,
                    )

                    if starttls:
                        self._negotiate_starttls(raw_sock, starttls)

                    with context.wrap_socket(
                        raw_sock,
                        server_hostname=server_hostname,
                    ) as tls_sock:
                        negotiated = tls_sock.version()

                        if negotiated == expected:
                            supported_versions.append(version_name)
                    break

                except ssl.SSLError:
                    break
                except (OSError, ValueError):
                    continue

                finally:
                    if raw_sock is not None:
                        try:
                            raw_sock.close()
                        except OSError:
                            pass

        return supported_versions

    def _probe_weak_ciphers(self, domain, port, hosts, starttls=None):
        """Optionally probe whether the server accepts weak TLS 1.2 cipher classes."""
        probes = [
            ("RC4", "RC4:@SECLEVEL=0"),
            ("3DES", "3DES:@SECLEVEL=0"),
            ("NULL", "eNULL:@SECLEVEL=0"),
            ("EXPORT", "EXP:@SECLEVEL=0"),
            ("Static-RSA", "kRSA:!ECDHE:!DHE:@SECLEVEL=0"),
        ]
        accepted = []
        server_hostname = None if self._is_ip_literal(domain) else domain

        for label, cipher_spec in probes:
            for target_host in hosts:
                raw_sock = None
                try:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", DeprecationWarning)
                        context.maximum_version = ssl.TLSVersion.TLSv1_2
                    context.set_ciphers(cipher_spec)

                    raw_sock = socket.create_connection(
                        (target_host, port),
                        timeout=self.timeout,
                    )
                    if starttls:
                        self._negotiate_starttls(raw_sock, starttls)

                    with context.wrap_socket(
                        raw_sock,
                        server_hostname=server_hostname,
                    ) as tls_sock:
                        cipher = tls_sock.cipher()
                        if cipher:
                            accepted.append(f"{label} ({cipher[0]})")
                    break
                except ssl.SSLError:
                    break
                except (OSError, ValueError):
                    continue
                finally:
                    if raw_sock is not None:
                        try:
                            raw_sock.close()
                        except OSError:
                            pass

        return accepted

    @staticmethod
    def _check_certificate_hygiene(result, certificate):
        """Inspect signature algorithm, constraints, EKU, SCT, and CRL fields."""
        sig_hash = certificate.signature_hash_algorithm
        if isinstance(sig_hash, (hashes.MD5, hashes.SHA1)):
            result["findings"].append(
                f"Weak certificate signature algorithm: {sig_hash.name.upper()}"
            )

        if result.get("certificate_trusted"):
            validity_days = (
                certificate.not_valid_after_utc - certificate.not_valid_before_utc
            ).days
            if validity_days > 398:
                result["findings"].append(
                    f"Certificate validity period exceeds 398 days ({validity_days} days)"
                )

        try:
            bc = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
            if bc.ca:
                result["findings"].append(
                    "Leaf certificate has BasicConstraints CA=True"
                )
        except x509.ExtensionNotFound:
            pass

        try:
            eku = certificate.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            ).value
            if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
                result["findings"].append(
                    "Certificate ExtendedKeyUsage does not include serverAuth"
                )
        except x509.ExtensionNotFound:
            pass

        try:
            sct_ext = certificate.extensions.get_extension_for_class(
                x509.PrecertificateSignedCertificateTimestamps
            ).value
            result["has_sct"] = bool(len(sct_ext))
        except x509.ExtensionNotFound:
            result["has_sct"] = False

        crl_urls = []
        try:
            cdp = certificate.extensions.get_extension_for_class(
                x509.CRLDistributionPoints
            ).value
            for point in cdp:
                for name in point.full_name or []:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        crl_urls.append(name.value)
        except x509.ExtensionNotFound:
            pass
        result["crl_urls"] = crl_urls

    @staticmethod
    def _check_certificate_chain_quality(result, certificate_chain, has_chain_api):
        """Inspect presented intermediate certificates for completeness and hygiene."""
        result["chain_length"] = len(certificate_chain)
        result["chain_contains_root"] = any(
            cert.subject == cert.issuer for cert in certificate_chain[1:]
        )

        if (
            has_chain_api
            and not result.get("self_signed")
            and len(certificate_chain) < 2
        ):
            result["findings"].append(
                "Server did not send intermediate certificate(s)"
            )

        now = datetime.now(timezone.utc)
        for intermediate in certificate_chain[1:]:
            if intermediate.subject == intermediate.issuer:
                continue

            if intermediate.not_valid_after_utc < now:
                result["findings"].append(
                    "Intermediate certificate in chain has expired"
                )

            sig_hash = intermediate.signature_hash_algorithm
            if isinstance(sig_hash, (hashes.MD5, hashes.SHA1)):
                result["findings"].append(
                    f"Weak signature algorithm in intermediate certificate: {sig_hash.name.upper()}"
                )

            pub_key = intermediate.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey) and pub_key.key_size < 2048:
                result["findings"].append(
                    f"Weak RSA key in intermediate certificate: {pub_key.key_size} bits"
                )

    # ====== TLS Check ======
    def check_tls(
        self,
        domain,
        port=443,
        probe_weak_ciphers=False,
        starttls=None,
    ):
        """Scan a domain and return a structured dictionary of findings."""

        domain = self._normalize_domain(domain)

        if isinstance(port, bool) or not isinstance(port, int):
            raise TypeError("port must be an integer")

        if not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")

        if starttls is not None:
            if not isinstance(starttls, str) or starttls.lower() not in (
                "smtp",
                "imap",
                "ftp",
            ):
                raise ValueError("starttls must be one of: smtp, imap, ftp")
            starttls = starttls.lower()

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
        has_chain_api = False

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

        is_ip = self._is_ip_literal(domain)

        # Standard TLS connection with certificate verification.
        context = ssl.create_default_context()
        context.check_hostname = not is_ip
        context.verify_mode = ssl.CERT_REQUIRED
        context.set_alpn_protocols(["h2", "http/1.1"])

        start_time = time.perf_counter()
        connected_ip = None

        def _connect_with_resolved_ips(tls_context, preferred_ip=None):
            candidates = (
                [preferred_ip]
                if preferred_ip
                else result["resolved_ips"]
            )
            last_os_error = None
            for ip_addr in candidates:
                try:
                    return self._inspect_connection(
                        domain,
                        port,
                        tls_context,
                        connect_host=ip_addr,
                        starttls=starttls,
                    )
                except ssl.SSLError:
                    raise
                except OSError as os_exc:
                    last_os_error = os_exc
                    continue
            if last_os_error is not None:
                raise last_os_error
            raise OSError("No resolved IP addresses available")

        try:
            inspected = _connect_with_resolved_ips(context)
            connected_ip = inspected.get("peer_ip", connected_ip)
            result["connected_ip"] = connected_ip

            if is_ip and not self._certificate_hostname_matches(
                inspected["certificate_obj"],
                domain,
            ):
                raise ssl.SSLCertVerificationError(
                    "IP address mismatch: certificate is not valid for this IP"
                )

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
            has_chain_api = inspected.get("has_chain_api", False)

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

            elif "self-signed certificate" in error_text:
                result["findings"].append(
                    "TLS certificate is self-signed and not trusted"
                )

            elif "certificate has expired" in error_text:
                # Expiration is reported once by _check_certificate_validity().
                pass

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
                inspected = _connect_with_resolved_ips(
                    diagnostic_context,
                    preferred_ip=connected_ip,
                )
                connected_ip = inspected.get("peer_ip", connected_ip)
                result["connected_ip"] = connected_ip

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

                inspected = _connect_with_resolved_ips(
                    diagnostic_context,
                    preferred_ip=connected_ip,
                )
                connected_ip = inspected.get("peer_ip", connected_ip)
                result["connected_ip"] = connected_ip

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

            if (
                result["self_signed"]
                and "TLS certificate is self-signed and not trusted"
                not in result["findings"]
            ):
                result["findings"].append(
                    "Certificate subject and issuer are identical"
                )

            self._check_certificate_validity(result, certificate)
            self._check_certificate_hygiene(result, certificate)
            self._check_certificate_chain_quality(
                result,
                certificate_chain,
                has_chain_api,
            )

            result["ocsp"] = self._check_ocsp(
                certificate,
                certificate_chain,
                certificate_trusted=result["certificate_trusted"],
            )

            ocsp_info = result["ocsp"]
            ocsp_status = ocsp_info.get("status")
            if ocsp_status == "REVOKED":
                result["findings"].append(
                    "OCSP responder reported the certificate as revoked"
                )
            elif ocsp_status == "REPORTED_REVOKED_UNVALIDATED":
                result["findings"].append(
                    "OCSP responder reported the certificate as revoked; "
                    "the response has not been cryptographically validated"
                )
            elif ocsp_status == "Serial Mismatch":
                result["findings"].append(
                    "OCSP response serial number does not match certificate"
                )

            if ocsp_info.get("signature_valid") is False:
                result["findings"].append(
                    "OCSP response signature verification failed"
                )
            if ocsp_info.get("fresh") is False:
                result["findings"].append("OCSP response has expired")

        # Probe TLS versions. Failed probes do not prove versions are disabled.
        probe_hosts = [connected_ip] if connected_ip else result["resolved_ips"]
        result["supported_tls_versions"] = (
            self._check_tls_protocol_support(
                domain,
                port,
                connect_hosts=probe_hosts,
                starttls=starttls,
            )
        )

        supported_versions = result["supported_tls_versions"]
        result["tls13_supported"] = "TLSv1.3" in supported_versions

        if "TLSv1.0" in supported_versions:
            result["findings"].append(
                "Server supports deprecated TLSv1.0"
            )

        if "TLSv1.1" in supported_versions:
            result["findings"].append(
                "Server supports deprecated TLSv1.1"
            )

        if supported_versions and all(
            ver in ("TLSv1.0", "TLSv1.1") for ver in supported_versions
        ):
            result["findings"].append(
                "Server only supports deprecated TLS protocols"
            )

        # Weak cipher suite indicators for the negotiated connection.
        cipher = result.get("cipher")

        if cipher:
            cipher_name = cipher[0].upper()
            cipher_bits = cipher[2] if len(cipher) > 2 else None
            negotiated_version = result.get("tls_version")

            if any(
                weak_name in cipher_name
                for weak_name in (
                    "RC4",
                    "3DES",
                    "DES",
                    "NULL",
                    "EXPORT",
                    "ANON",
                    "ADH",
                    "AECDH",
                    "MD5",
                    "RC2",
                )
            ) or (isinstance(cipher_bits, int) and cipher_bits < 128):
                result["findings"].append(
                    f"Weak TLS cipher suite: {cipher[0]}"
                )
            elif (
                negotiated_version != "TLSv1.3"
                and "ECDHE" not in cipher_name
                and "DHE" not in cipher_name
            ):
                result["findings"].append(
                    f"TLS cipher suite lacks forward secrecy: {cipher[0]}"
                )

        if probe_weak_ciphers:
            weak_supported = self._probe_weak_ciphers(
                domain,
                port,
                probe_hosts,
                starttls=starttls,
            )
            result["weak_ciphers_supported"] = weak_supported
            if weak_supported:
                result["findings"].append(
                    "Server accepts weak TLS 1.2 cipher suite(s): "
                    + ", ".join(weak_supported)
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

        elif result["diagnostic_handshake"] == "Passed":
            if (
                not result["certificate_trusted"]
                or result["hostname_valid"] is False
                or result["findings"]
            ):
                result["verdict"] = "WARNING"
            else:
                result["verdict"] = "INCONCLUSIVE"

        else:
            result["verdict"] = "INCONCLUSIVE"

        return result

    # ====== Format Output ======
    @staticmethod
    def format_scan(result: dict) -> str:
        """Format TLS scan results for readable CLI output."""
        domain = result.get("domain", "Unknown")
        port = result.get("port", 443)

        lines = [
            f"Uspector TLS Scan: {domain}:{port}",
            "=" * 50,
            "",
            "TLS Overview:",
            f"  Verdict: {result.get('verdict', 'INCONCLUSIVE')}",
            f"  Connection Status: {result.get('connection_status', 'Unknown')}",
            f"  Certificate Trusted: "
            f"{'Yes' if result.get('certificate_trusted') else 'No'}",
        ]

        hostname_valid = result.get("hostname_valid")
        if hostname_valid is not None:
            lines.append(
                "  Hostname Valid: "
                + ("Yes" if hostname_valid else "No")
            )
        else:
            lines.append("  Hostname Valid: Unknown")

        # Connection details
        lines.extend(["", "Connection:"])

        if result.get("tls_version"):
            lines.append(f"  Negotiated TLS Version: {result['tls_version']}")

        cipher = result.get("cipher")
        if cipher:
            lines.append(f"  Cipher Suite: {cipher[0]}")
            if len(cipher) > 1 and cipher[1]:
                lines.append(f"  Cipher Protocol: {cipher[1]}")
            if len(cipher) > 2 and cipher[2] is not None:
                lines.append(f"  Cipher Bits: {cipher[2]}")

        if result.get("alpn"):
            lines.append(f"  ALPN: {result['alpn']}")

        if result.get("latency_ms") is not None:
            lines.append(f"  Latency: {result['latency_ms']} ms")

        ips = result.get("resolved_ips") or []
        lines.append("  Resolved IPs:")
        if ips:
            lines.extend(f"    - {ip}" for ip in ips)
        else:
            lines.append("    None found")

        # Protocol support
        lines.extend(["", "Supported TLS Versions:"])
        versions = result.get("supported_tls_versions") or []
        if versions:
            lines.extend(f"  - {version}" for version in versions)
        else:
            lines.append("  No successful protocol probes")

        # Certificate details
        lines.extend(["", "Certificate:"])

        certificate_fields = [
            ("Subject", "subject"),
            ("Issuer", "issuer"),
            ("Fingerprint (SHA-256)", "fingerprint"),
            ("Valid From", "not_before"),
            ("Valid Until", "not_after"),
            ("Days Remaining", "days_remaining"),
            ("Public Key Type", "public_key_type"),
            ("Public Key Bits", "public_key_bits"),
        ]

        for label, key in certificate_fields:
            value = result.get(key)
            if value is not None and value != "":
                lines.append(f"  {label}: {value}")

        if "self_signed" in result:
            lines.append(
                "  Subject Matches Issuer: "
                + ("Yes" if result["self_signed"] else "No")
            )

        san = result.get("san") or []
        if san:
            lines.append("  Subject Alternative Names:")
            lines.extend(f"    - {name}" for name in san)

        san_ips = result.get("san_ip_addresses") or []
        if san_ips:
            lines.append("  SAN IP Addresses:")
            lines.extend(f"    - {ip}" for ip in san_ips)

        # Diagnostic handshake
        diagnostic = result.get("diagnostic_handshake")
        if diagnostic and diagnostic != "Not Attempted":
            lines.extend([
                "",
                "Diagnostic Handshake:",
                f"  Status: {diagnostic}",
            ])

        # OCSP
        ocsp_result = result.get("ocsp")
        if isinstance(ocsp_result, dict):
            lines.extend(["", "OCSP:"])
            lines.append(
                f"  Status: {ocsp_result.get('status', 'Unknown')}"
            )

            if ocsp_result.get("url"):
                lines.append(f"  Responder URL: {ocsp_result['url']}")

            lines.append(
                "  Response Validated: "
                + (
                    "Yes"
                    if ocsp_result.get("response_validated")
                    else "No"
                )
            )

        # Errors
        for label, key in (
            ("Error", "error"),
            ("TLS Error", "ssl_error"),
            ("Diagnostic Error", "diagnostic_error"),
        ):
            if result.get(key):
                lines.extend(["", f"{label}: {result[key]}"])

        # Findings
        lines.extend(["", "Findings:"])
        findings = result.get("findings") or []

        if findings:
            lines.extend(f"  - {finding}" for finding in findings)
        else:
            lines.append("  None")

        return "\n".join(lines)

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
