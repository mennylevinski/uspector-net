 <a name="top"></a>

<div align="center">

  <a href="https://github.com/mennylevinski/uspector-net">
    <img src="img/uspector-main-logo-prod.png" alt="Uspector Security Diagnostics logo" width="200" height="200">
  </a>

</div>

# Uspector – DNS, SSL, Web & PHP Security Diagnostics

Uspector is a Python library and command-line tool for DNS diagnostics, SSL/TLS inspection, certificate validation, passive web security diagnostics, and remote PHP security checks.

It helps developers and security professionals inspect TLS configurations, review certificate details, analyze important DNS records, and identify common web security, PHP information disclosure, and SEO configuration issues.

Check out our official website: [uspector.net](https://uspector.net/)

## Installation

Install from PyPI:

```bash
pip install uspector
```

Upgrade to the latest version:

```bash
pip install --upgrade uspector
```

Requirements: Python 3.10 or later.

## Command-Line Interface

Uspector provides separate commands for DNS diagnostics, TLS inspection, web diagnostics, and remote PHP security checks.

### DNS diagnostics

Scan a domain:

```bash
uspector dns example.com
```

Check a DKIM selector, set a custom query timeout, or skip DNSSEC / extended record lookups:

```bash
uspector dns example.com --dkim-selector default --no-dnssec
uspector dns example.com -t 4 --no-extended
```

The DNS scanner inspects common DNS records (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `CAA`, and `SOA`), evaluates SPF/DMARC/DKIM/CAA/NS/SOA hygiene, detects Null MX (`0 .`), and inspects DNSSEC-related records (`DS`, `DNSKEY`, `RRSIG`).

DNSSEC inspection checks record presence, deprecated `DNSKEY` algorithms, and `RRSIG` expiration; it does not perform cryptographic DNSSEC chain validation.

### TLS and certificate inspection

Scan a hostname:

```bash
uspector tls example.com
```

Specify a custom port, connection timeout, `STARTTLS` protocol (`smtp`, `imap`, `ftp`), or weak-cipher probing:

```bash
uspector tls example.com -p 8443 -t 10
uspector tls example.com -p 587 --starttls smtp --probe-weak-ciphers
```

Use this to inspect TLS connectivity, certificate properties, hostname/SAN validation, certificate expiration and hygiene, intermediate chain quality, OCSP status/validation, supported TLS versions (`TLSv1.0`–`TLSv1.3`), cipher suites, and connection diagnostics.

### Web security and SEO diagnostics

Scan a website:

```bash
uspector web example.com
```

Specify a complete URL, custom timeout, private-IP blocking (`--no-private`), or metadata checks (`--check-metadata`):

```bash
uspector web https://example.com -t 10
uspector web https://example.com --no-private --check-metadata
```

The web scanner follows HTTP redirects and reports the final URL, HTTP status, resolved IP addresses, security headers and directive quality, cookie attributes across redirects, passive client-side/HTML/body security indicators, and on-page SEO diagnostics.

### Remote PHP security diagnostics

Scan a website for PHP-related security indicators and information disclosure:

```bash
uspector php example.com
```

Specify a complete URL and custom timeout:

```bash
uspector php https://example.com -t 15
```

The PHP scanner performs passive, remote HTTP-based checks for PHP technology and framework detection, version and EOL lifecycle disclosure, PHP session cookie attributes, exposed `phpinfo()` pages, PHP error messages, publicly accessible configuration and backup files, and directory listing indicators.

The scanner does not execute PHP code or directly inspect the server's PHP configuration. Detection depends on information exposed through HTTP responses, and non-global/localhost targets are blocked.

### JSON output & exit codes

All scanners support structured JSON output:

```bash
uspector dns example.com --json
uspector tls example.com --json
uspector web example.com --json
uspector php example.com --json
```

CLI exit codes:

- `0`: Scan completed successfully
- `1`: Scan error, complete TLS handshake failure, or all DNS record queries failed
- `2`: Invalid CLI input or argument type

## Python API

Uspector exposes `DNSScanner`, `TLSScanner`, `WebScanner`, and `PHPScanner` for use in Python applications.

### DNS scanning

```python
from uspector import DNSScanner

scanner = DNSScanner()
result = scanner.scan("example.com", dkim_selector="default", check_extended=True)

print(result)
```

`check_extended=True` enables optional lookups for `MTA-STS`, `TLS-RPT`, `BIMI`, `TLSA` (`DANE`), `HTTPS`, `SVCB`, `NSEC`/`NSEC3`, dangling `CNAME` targets, and `FCrDNS`.

### TLS scanning

```python
from uspector import TLSScanner

scanner = TLSScanner(timeout=5.0)
result = scanner.check_tls(
    "example.com",
    443,
    probe_weak_ciphers=False,
    starttls=None,  # Optional: "smtp", "imap", or "ftp"
)

print(result)
```

### Web scanning

```python
from uspector import WebScanner

# Set allow_private=False to block localhost/private-IP targets and redirects.
# Set check_metadata=True to also inspect security.txt, robots.txt, and HTTPS redirects.
scanner = WebScanner(timeout=15.0, allow_private=True, check_metadata=False)
result = scanner.scan("https://example.com")

print(result)
```

### PHP scanning

```python
from uspector import PHPScanner

scanner = PHPScanner(timeout=10.0)
result = scanner.scan("https://example.com")

print(result)
```

All scanners return structured results that can be processed by other Python code, incorporated into diagnostic workflows, or serialized for reporting.

## Features

### DNS diagnostics

- IPv4 (`A`) and IPv6 (`AAAA`) record lookups
- `CNAME` record inspection (with `A`/`AAAA` fallback deduplication and optional dangling `NXDOMAIN` check)
- Mail server (`MX`) and name server (`NS`) discovery, redundancy checks, IP-literal detection, and Null MX (`0 .`) awareness
- `TXT` record inspection, including verification, `SPF`, `DMARC`, and `DKIM` records
- `SPF` policy checks (`+all`/`?all`, deprecated `ptr`, missing terminator, and 10-DNS-lookup limit)
- `DMARC` policy and tag checks (`p`, `sp`, `pct`, `rua`/`ruf`)
- Optional `DKIM` selector checks (presence, revoked `p=`, test mode `t=y`, and RSA key bit-length)
- `CAA` record and tag inspection (`issue`, `issuewild`, `iodef`)
- `SOA` record details and timer sanity checks
- `DNSSEC`-related inspection (`DS`, `DNSKEY` deprecated algorithms, `RRSIG` expiration)
- Optional extended checks (`MTA-STS`, `TLS-RPT`, `BIMI`, `TLSA`, `HTTPS`, `SVCB`, `NSEC`/`NSEC3`, and `FCrDNS`)

DNSSEC records are inspected for presence, algorithm hygiene, and signature expiration; full cryptographic chain validation is not performed.

### SSL/TLS inspection

- TLS connection testing and fallback diagnostic handshakes (plus optional `STARTTLS` for `smtp`, `imap`, `ftp`)
- Certificate trust, SAN hostname/IP validation, and single-label wildcard rejection
- Certificate expiration, validity span (`> 398` days), signature hash (`MD5`/`SHA1`), `BasicConstraints`, `ExtendedKeyUsage`, embedded SCT presence, and CRL distribution points
- Intermediate certificate chain completeness (Python 3.13+) and intermediate key/expiry/signature hygiene
- OCSP revocation queries with CertID, freshness, and cryptographic signature validation (with SSRF-guarded AIA `caIssuers` fallback)
- Supported TLS version probing (`TLSv1.0`–`TLSv1.3`), weak/non-PFS cipher suite detection, and optional weak-cipher probing (`probe_weak_ciphers=True`)
- DNS resolution, connected peer IP, ALPN, and structured findings/verdict

### Web security diagnostics

- HTTP response status, redirect chain cookies, and final destination (with optional `allow_private=False` SSRF protection)
- Security-header presence and directive auditing (`Content-Security-Policy` & `Report-Only`, `Strict-Transport-Security` `max-age`/`includeSubDomains`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`)
- Cross-origin isolation header observation (`COOP`, `COEP`, `CORP`, `X-Permitted-Cross-Domain-Policies`), passive CORS (`*` + credentials), `Cache-Control` on cookie-setting responses, and server version banner checks
- Cookie security-attribute checks across redirects (`Secure`, `HttpOnly`, and valid `SameSite` values)
- Passive HTML and body security checks: mixed content, missing Subresource Integrity (`SRI`), `target="_blank"` without `noopener`/`noreferrer`, insecure password forms, source map references, internal IP leaks in URLs/comments, and framework error/stack-trace indicators
- Optional metadata checks (`check_metadata=True`): `/.well-known/security.txt`, `/robots.txt` sensitive `Disallow:` entries, and HTTP-to-HTTPS redirect enforcement

### PHP security diagnostics

- Remote PHP technology and passive framework detection (`Laravel`, `CakePHP`, `Symfony`, `WordPress`, `Drupal`, `Joomla`, `Magento`, `TYPO3`)
- PHP version disclosure and end-of-life (EOL) branch detection
- PHP and framework session cookie attribute checks (`PHPSESSID`, `laravel_session`, `CAKEPHP`, `SYMFONY`)
- Detection of publicly accessible `phpinfo()` pages (main page and common filenames)
- Expanded PHP warning, notice, fatal/deprecated error, `PDOException`/`SQLSTATE`, and Ignition/Whoops stack-trace indicators
- Content-verified checks for publicly accessible backup, `.env`, `php.ini`, `.user.ini`, and `composer.json`/`composer.lock` files (including risky `php.ini`/`.user.ini` directives and exposed `require-dev` metadata)
- PHP-related directory listing detection
- Security findings with severity levels, remediation recommendations, and overall risk verdict

PHP checks are performed remotely through HTTP responses against publicly routable hosts. The scanner cannot determine the actual PHP version or configuration when this information is not publicly disclosed. File exposure indicators should be interpreted in context and do not automatically indicate a vulnerability.

### SEO diagnostics

- HTML title presence and length checks (ignoring inline SVG `<title>` elements)
- Meta description presence and length checks
- Canonical URL detection
- Meta robots and `X-Robots-Tag` inspection
- H1 heading count
- HTML language attribute detection
- Image alternative-text checks (distinguishing missing `alt` attributes from decorative `alt=""`)
- Open Graph title and description presence
- Detection of `noindex` directives

SEO checks are basic diagnostics, not a complete SEO audit. Findings such as title length or missing image alternative text should be interpreted in context.

## Understanding the Results

Uspector returns structured diagnostic information rather than a simple pass/fail result.

Depending on the scanner, results can include:

| Result | Description |
|---|---|
| DNS records | Observed DNS records (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `CAA`, `SOA`, etc.) |
| Email security | `SPF`, `DMARC`, `DKIM`, Null MX, and optional `MTA-STS`/`TLS-RPT`/`BIMI` checks |
| DNSSEC records | Presence, algorithm hygiene, and `RRSIG` expiry inspection; not full validation |
| Target | Hostname or URL being scanned |
| Status code | HTTP response status (top-level for web scans; per-file inside `exposed_files` for PHP scans) |
| Final URL | Destination after redirects (web scans) |
| Resolved IPs | IP addresses resolved during scanning (TLS and web scans) |
| Certificate details | Trust, hostname validity, expiration, signature/chain hygiene, and SAN properties |
| OCSP | Responder URL, unvalidated or cryptographically validated revocation status |
| Security headers | Observed HTTP security-header values (web scans) |
| PHP detection | PHP technology, framework, version disclosure, and EOL indicators |
| Exposed files | Potentially accessible configuration, backup, and diagnostic files (PHP scans) |
| Findings | Detected configuration concerns or indicators |
| Verdict | Overall scan summary (`TLSScanner` and `PHPScanner`) |
| SEO | HTML and indexing-related diagnostics (web scans) |
| Error | Error information when a scan cannot complete |

A reported missing DNS record, security header, or PHP indicator is an observation, not necessarily proof that a system is vulnerable. Findings should be assessed according to the domain's configuration, the site's architecture, intended behavior, and security requirements.

## Requirements

- Python 3.10 or later
- Internet connectivity to the target host
- Dependencies installed automatically by pip

## Responsible Use

Uspector is intended for legitimate diagnostic, educational, troubleshooting, and defensive security purposes.

DNS, TLS, web, and PHP diagnostic results are informational and should be validated before making security decisions.

The remote PHP scanner performs HTTP-based inspection only. It does not execute PHP code, modify remote files, or attempt to exploit vulnerabilities.

## Project Structure

```text
uspector-net/
├── img/                  # Logo and media assets
├── src/
│   └── uspector/
│       ├── _http.py      # Shared HTTP/cookie/SSRF helpers
│       ├── dnsscanner.py # DNS diagnostics
│       ├── tlsscanner.py # TLS inspection
│       ├── webscanner.py # Web security and SEO diagnostics
│       ├── phpscanner.py # Remote PHP security diagnostics
│       └── cli.py        # Command-line interface
├── tests/                # Automated tests
├── LICENSE               # MIT License
├── README.md             # Project documentation
├── SECURITY.md           # Security policy
└── pyproject.toml        # Package configuration and dependencies
```

## License

Uspector is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

<p align="center">
© 2026 Menahem Levinski
<br>
<a href="#top">🔝 Back to top</a>
</p>
