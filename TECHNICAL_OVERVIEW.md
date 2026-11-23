# Uspector Technical Overview

This document describes the architecture, module structure, execution flows, security controls, and output contracts of **Uspector** (`1.1.2`).

---

## 1. Repository & Package Layout

```text
uspector-net/
├── .github/workflows/
│   └── linux-release.yml     # Runs unit tests and builds standalone Linux binary (PyInstaller)
├── img/
│   └── uspector-main-logo-prod.png
├── src/uspector/
│   ├── __init__.py           # Public exports & __version__ ("1.1.2")
│   ├── _http.py              # Shared timeout, SSRF/DNS-pinning, and cookie-parsing helpers
│   ├── cli.py                # argparse CLI entrypoint (uspector) and exit-code mapping
│   ├── dnsscanner.py         # Standard-library DNS wire client and DNS/email/DNSSEC checks
│   ├── tlsscanner.py         # TLS handshake, X.509 hygiene, chain, and OCSP validator
│   ├── webscanner.py         # HTTP header, cookie, client-side HTML, and SEO scanner
│   └── phpscanner.py         # Passive remote PHP disclosure and configuration scanner
├── tests/
│   ├── test_cli.py
│   ├── test_dnsscanner.py
│   ├── test_phpscanner.py
│   ├── test_tlsscanner.py
│   └── test_webscanner.py
├── CONTRIBUTING.md
├── LICENSE
├── README.md
├── SECURITY.md
└── pyproject.toml
```

### Runtime Dependencies
Defined in `pyproject.toml` (`requires-python = ">=3.10"`, build backend `hatchling`):
- `cryptography>=44.0.0` (X.509 parsing/validation and OCSP requests/responses in `tlsscanner.py`)
- `requests>=2.32.0` (HTTP transport in `_http.py`, `tlsscanner.py`, `webscanner.py`, `phpscanner.py`)
- `DNSScanner` uses only the Python standard library.

---

## 2. High-Level Architecture

```text
                ┌───────────────────────────┐
                │   CLI (uspector.cli:main) │
                │  dns | tls | web | php    │
                └─────────────┬─────────────┘
                              │ dispatches & formats (--json / format_scan)
         ┌──────────────┬─────┴───────┬───────────────┐
         ▼              ▼             ▼               ▼
  ┌─────────────┐ ┌───────────┐ ┌───────────┐ ┌────────────┐
  │ DNSScanner  │ │TLSScanner │ │WebScanner │ │ PHPScanner │
  │ (stdlib UDP │ │(ssl/x509  │ │(HTTP/HTML │ │(HTTP/PHP   │
  │  /TCP DNS)  │ │ + OCSP)   │ │  + SEO)   │ │  exposure) │
  └─────────────┘ └─────┬─────┘ └─────┬─────┘ └──────┬─────┘
                        │             │              │
                        └─────────────┼──────────────┘
                                      ▼
                        ┌──────────────────────────┐
                        │   Shared Layer (_http.py) │
                        │ - validate_timeout()     │
                        │ - validate_public_http_url│
                        │ - PinnedIPAdapter        │
                        │ - Set-Cookie parsers     │
                        └──────────────────────────┘
```

Each scanner exposes:
1. A programmatic scan method (`scan(...)` or `check_tls(...)`) returning a structured `dict` suitable for Python callers and `--json` serialization.
2. A `@staticmethod format_scan(result: dict) -> str` renderer producing human-readable CLI output.

---

## 3. Shared HTTP & Security Primitives (`src/uspector/_http.py`)

- **`validate_timeout(timeout)`**: Rejects `bool`, non-numeric types (`TypeError`), and non-finite or `<= 0` numbers (`ValueError`).
- **`validate_public_http_url(url, error_prefix="Target", resolver=None, return_all=False)`**:
  - Enforces `http` / `https` schemes, non-empty hostnames, absence of URL credentials, valid port bounds (`1..65535`), and non-`localhost` hostnames.
  - Resolves via `socket.getaddrinfo(..., type=socket.SOCK_STREAM)` and requires every returned IP address to satisfy `ipaddress.ip_address(...).is_global`.
  - Returns `(hostname.lower(), port, validated_ip)` by default, or `(hostname.lower(), port, tuple(validated_ips))` when `return_all=True`.
- **`PinnedIPAdapter(HTTPAdapter)`**:
  - Prevents DNS-rebinding TOCTOU between validation and connection by pinning `(host, effective_port)` to a validated IP or tuple of validated IPs.
  - `send()` preserves the original `Host` header (`parsed.netloc`) when connecting to a pinned IP and fails over across candidate validated IPs on `requests.exceptions.ConnectionError`.
  - `get_connection_with_tls_context()` rewrites `host_params["host"]` to the pinned IP while setting `pool_kwargs["server_hostname"]` and `pool_kwargs["assert_hostname"]` to the original hostname for HTTPS SNI and certificate verification (skipping SNI override when `host` is an IP literal).
- **`extract_set_cookie_headers(response)` & `parse_cookie_attributes(cookie_header)`**:
  - Prefers `response.raw.headers.getlist("Set-Cookie")` and falls back to a cookie-token-aware regex split on comma-joined `Set-Cookie` headers so `Expires=` dates containing commas are not split.
  - Parses `Secure`, `HttpOnly`, and validates `SameSite` (`lax`, `strict`, or `none` paired with `secure`).

---

## 4. Scanner Subsystems

### 4.1 `DNSScanner` (`src/uspector/dnsscanner.py`)
- **Resolver Discovery (`_discover_nameservers`)**:
  - On Windows (`winreg`), inspects `Tcpip\Parameters\Interfaces` (`NameServer`, `DhcpNameServer`), preferring interfaces with active `IPAddress` / `DhcpIPAddress` values and falling back to all discovered resolvers.
  - On POSIX, parses `/etc/resolv.conf`.
  - Preserves IPv6 link-local zone IDs (`%zone`) and falls back to `["1.1.1.1"]` only when `nameservers=None` and discovery yields nothing (explicit `nameservers=[]` is preserved).
- **Wire Codec & Transport**:
  - `_encode_name()` / `_decode_name()` support IDNA encoding, label/wire length checks (`1..63` bytes per label, `<= 255` wire bytes), and compression pointer loop/bounds validation (`max_wire_end` prevents RDATA overruns).
  - `_exchange()` sends EDNS(0) UDP queries (`1232`-byte payload, DO bit set when `dnssec=True`), verifies both source IP and port plus TXID and QR flag while ignoring stray packets until deadline, and falls back to length-prefixed TCP (`_exchange_tcp`) when `TC=1`.
  - `_parse_rr()` parses `A`, `AAAA`, `NS`, `CNAME`, `PTR`, `MX`, `SOA`, `TXT`, `CAA`, `DS`, `DNSKEY`, `RRSIG`, `SRV`, `TLSA` (52), `SVCB` (64), and `HTTPS` (65), preserving root `"."` targets.
- **Evaluations in `scan(target, dkim_selector=None, include_dnssec=True, check_extended=False)`**:
  - Queries `A`, `AAAA`, `CNAME`, `MX`, `NS`, `SOA`, `TXT`, `CAA` (plus `DS`, `DNSKEY`, `RRSIG` when `include_dnssec=True`) and deduplicates `CNAME` fallbacks from `A`/`AAAA` responses.
  - Evaluates SPF (`+all`/`?all`, deprecated `ptr`, missing terminator, 10-DNS-lookup budget), DMARC (`p=none`, `sp=none`, `pct < 100`, missing `rua`/`ruf`), DKIM (revoked `p=`, `t=y`, stdlib ASN.1 DER RSA bit-length via `_rsa_bits_from_spki`), CAA (`issue`/`issuewild`/`iodef`), NS redundancy, MX IP-literal targets, Null MX (`0 .`), SOA timers, deprecated `DNSKEY` algorithms, and `RRSIG` expiration.
  - When `check_extended=True`, `_run_extended_checks()` additionally queries `_mta-sts`, `_smtp._tls`, `default._bimi`, `_443._tcp` (`TLSA`), `HTTPS`, `SVCB`, `NSEC`/`NSEC3`, dangling `CNAME`s (`NXDOMAIN`), and `FCrDNS` via `reverse_lookup()`.

### 4.2 `TLSScanner` (`src/uspector/tlsscanner.py`)
- **Input & Connection Flow (`check_tls(domain, port=443, probe_weak_ciphers=False, starttls=None)`)**:
  - Validates `timeout`, `port`, optional `starttls` (`"smtp"`, `"imap"`, `"ftp"`), and normalizes hostnames (IDNA) or IPv4/IPv6 literals.
  - Resolves target IPs once into `resolved_ips`, connects through `_inspect_connection` across candidates (tracking `connected_ip`), and omits SNI (`server_hostname=None`) when the target is an IP literal while enforcing SAN IP matching via `_certificate_hostname_matches()`.
  - Falls back to unverified diagnostic handshakes (`SSLCertVerificationError` retry, then `@SECLEVEL=0` / `TLSv1` retry) to collect certificate details when strict verification fails.
- **Certificate, Chain & OCSP Checks**:
  - `_check_certificate_validity()`: checks `not_valid_before_utc`, `not_valid_after_utc`, and `<= 30` days remaining.
  - `_check_certificate_hygiene()`: flags `MD5`/`SHA1` signatures, `> 398`-day leaf validity on trusted certs, `BasicConstraints(ca=True)` on leaf certs, missing `serverAuth` EKU, and extracts `has_sct` and `crl_urls`.
  - `_check_certificate_chain_quality()`: checks missing intermediates when `SSLSocket.get_unverified_chain` is present (Python 3.13+) and audits intermediate expiry, weak signatures, and `< 2048`-bit RSA keys.
  - `_check_ocsp()`: checks AIA `OCSP` and `CA_ISSUERS` URLs via `_fetch_public_http_bytes()` (enforcing `validate_public_http_url` + `PinnedIPAdapter` SSRF guards and max 1 MB reads), then `_validate_ocsp_response()` verifies `CertID` (`serial_number`, `issuer_name_hash`, and `issuer_key_hash`), `this_update`/`next_update` freshness, and cryptographic signature (direct issuer or delegated `OCSP_SIGNING` responder matched by subject or `SubjectKeyIdentifier` key hash). Sets `response_validated=True` only when all checks and `certificate_trusted` pass.
- **Protocol & Cipher Probing**:
  - `_check_tls_protocol_support()` probes `TLSv1.0`–`TLSv1.3` across resolved IPs, flags deprecated protocols, weak negotiated ciphers (`RC4`, `3DES`, `DES`, `NULL`, `EXPORT`, `ANON`, `ADH`, `AECDH`, `MD5`, `RC2`, `< 128` bits), and TLS `<= 1.2` suites lacking forward secrecy (`ECDHE`/`DHE`).
  - When `probe_weak_ciphers=True`, `_probe_weak_ciphers()` probes TLS 1.2 acceptance of weak cipher classes.
- **Verdict Model**: `"VALID"`, `"WARNING"`, or `"INCONCLUSIVE"`.

### 4.3 `WebScanner` (`src/uspector/webscanner.py`)
- **Transport & SSRF Control (`WebScanner(timeout=15.0, allow_private=True, check_metadata=False)`)**:
  - `_normalize_url()` enforces string input, `http`/`https`, hostname, no credentials, and valid port (`1..65535`).
  - `_open_response()`: when `allow_private=True`, uses `requests.get(..., allow_redirects=True, stream=True)`; when `allow_private=False`, enforces `validate_public_http_url` + `PinnedIPAdapter` across up to `MAX_REDIRECTS` (`5`) manual redirect hops.
- **Response Processing (`scan`)**:
  - Bounds body reads incrementally to `MAX_RESPONSE_SIZE` (`1 MiB`), detects charset (`Content-Type` header -> HTML `<meta charset>` -> non-`ISO-8859-1` encoding -> `utf-8`), and decodes once.
  - `_audit_security_headers()` checks `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy` (plus directives and `Report-Only`), `Referrer-Policy`, `Permissions-Policy`, `Strict-Transport-Security` (`max-age >= 31536000`, `includeSubDomains`, or unencrypted HTTP warning), cross-origin isolation headers (`COOP`, `COEP`, `CORP`, `X-Permitted-Cross-Domain-Policies`), passive CORS (`*` + credentials), `Cache-Control` on cookie-setting responses, and version banners.
  - Collects cookies across redirect history and final response using `_http.py` helpers.
  - Single-pass `SEOHTMLParser` extracts SEO signals (ignoring `<svg><title>`, keeping first metadata/canonical tags, distinguishing missing `alt` from decorative `alt=""`) while collecting passive HTML security signals for `_audit_html_security()` (mixed content, missing SRI, unsafe `target="_blank"`, insecure password forms, and private-IP comments).
  - When `check_metadata=True`, `_check_metadata_endpoints()` inspects `/.well-known/security.txt`, `/robots.txt`, and HTTP-to-HTTPS redirect enforcement through `_open_response`.

### 4.4 `PHPScanner` (`src/uspector/phpscanner.py`)
- **Mandatory SSRF Guard**: `_normalize_url()` and `_validate_destination()` (backed by `validate_public_http_url` + `PinnedIPAdapter`) always block `localhost` and non-global IPs across initial requests and up to `MAX_REDIRECTS` (`5`) redirects, reading at most `MAX_RESPONSE_SIZE` (`1 MiB`) within a `requests.Session()` context manager and preserving `CaseInsensitiveDict` headers.
- **Detection & Exposure Analysis (`scan`)**:
  - Detects PHP version (`X-Powered-By` or `phpinfo()`/error response bodies only, avoiding prose false positives), flags EOL branches (`< MIN_SUPPORTED_PHP_BRANCH`, `(8, 2)`), detects PHP/framework session cookies and meta signatures (`_detect_framework`), and checks PHP session cookie security flags (`PHPSESSID`, `laravel_session`, `CAKEPHP`, `SYMFONY`).
  - Inspects response bodies for `PHP_ERROR_PATTERNS`, directory listings, and main-page `phpinfo()`.
  - Probes `EXPOSED_FILES` (`.env*`, `config.php.*`, `index.php.*`, `composer.json`/`lock`, `php.ini`, `.user.ini`, `phpinfo.php`, `info.php`, `test.php`) relative to the post-redirect base path, applying content/Content-Type validation (`_matches_exposed_file`), INI directive audits (`_inspect_ini_findings`), and `composer.json` `require-dev` checks (`_inspect_composer_findings`).
- **Verdict Model**: `"HIGH RISK"`, `"WARNING"`, `"LOW RISK"`, `"INFORMATIONAL"`, `"NO ISSUES DETECTED"`, or `"SCAN FAILED"`.

---

## 5. CLI & Exit-Code Contract (`src/uspector/cli.py`)

`main()` exposes four subcommands (`dns`, `tls`, `web`, `php`) plus `--version`:
- Subcommand options:
  - `dns`: `--dkim-selector`, `--no-dnssec`, `--no-extended`, `-t/--timeout`, `--json`
  - `tls`: `-p/--port`, `-t/--timeout`, `--starttls {smtp,imap,ftp}`, `--probe-weak-ciphers`, `--json`
  - `web`: `-t/--timeout`, `--no-private`, `--check-metadata`, `--json`
  - `php`: `-t/--timeout`, `--json`
- Output is either `json.dumps(result, indent=2, default=str)` (`--json`) or `scanner.format_scan(result)`.
- Exit codes:
  - `0`: Scan succeeded (findings may still be present in the report).
  - `1`: `result["error"]` is set, `tls` failed both primary and diagnostic handshakes, all `dns` record queries returned failed statuses, or an unexpected exception occurred.
  - `2`: `ValueError` / `TypeError` (invalid CLI arguments) or `argparse` parse failure.
  - `130`: `KeyboardInterrupt`.

---

## 6. Testing & Release CI

- **Tests (`tests/`)**: All 74 tests use `unittest` and `unittest.mock` so the suite runs completely offline (`PYTHONPATH=src python -B -m unittest discover -s tests -v`).
- **CI (`.github/workflows/linux-release.yml`)**: Triggered on `workflow_dispatch` and `v*` tags; installs the package, runs `unittest`, builds a one-file Linux binary with PyInstaller (`dist/linux/uspector`), and runs `--version` / `--help` smoke checks across all four subcommands.
