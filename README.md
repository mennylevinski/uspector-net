 <a name="top"></a>

<div align="center">

  <a href="https://github.com/mennylevinski/uspector-net">
    <img src="img/uspector-main-logo-prod.png" alt="Uspector Security Diagnostics logo" width="200" height="200">
  </a>

</div>

# Uspector – DNS, SSL/TLS, Web & PHP Security Diagnostics

Uspector is a Python library and command-line tool for DNS diagnostics, SSL/TLS inspection, certificate validation, passive web security diagnostics, and remote PHP security checks.

It helps developers and security professionals inspect TLS configurations, review certificate details, analyze important DNS records, and identify common web security, PHP information disclosure, and SEO configuration issues.

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

The DNS scanner inspects common DNS records, including IPv4 and IPv6 addresses, CNAME, MX, NS, TXT, CAA, and SOA records. It also checks email security configuration, including SPF and DMARC, and inspects DNSSEC-related records.

DNSSEC inspection reports the presence of relevant records; it does not perform cryptographic DNSSEC validation.

### TLS and certificate inspection

Scan a hostname:

```bash
uspector tls example.com
```

Specify a custom port:

```bash
uspector tls example.com -p 8443
```

Use this to inspect TLS connectivity, certificate properties, hostname validation, certificate expiration, supported TLS versions, cipher suites, and other available connection diagnostics.

### Web security and SEO diagnostics

Scan a website:

```bash
uspector web example.com
```

Specify a complete URL when needed:

```bash
uspector web https://example.com
```

The web scanner follows HTTP redirects and reports information about the final URL, HTTP status, resolved IP addresses, security headers, cookies, and selected response-body indicators.

It also performs basic HTML-based SEO checks when the response contains supported HTML content.

### Remote PHP security diagnostics

Scan a website for PHP-related security indicators and information disclosure:

```bash
uspector php example.com
```

Specify a complete URL:

```bash
uspector php https://example.com
```

The PHP scanner performs remote HTTP-based checks for PHP technology detection, version disclosure, exposed PHP information pages, PHP error messages, publicly accessible configuration and backup files, and directory listing indicators.

The scanner does not execute PHP code or directly inspect the server's PHP configuration. Detection depends on information exposed through HTTP responses.

### JSON output

All scanners support structured JSON output:

```bash
uspector dns example.com --json
uspector tls example.com --json
uspector web example.com --json
uspector php example.com --json
```

## Python API

Uspector exposes `DNSScanner`, `TLSScanner`, `WebScanner`, and `PHPScanner` for use in Python applications.

### DNS scanning

```python
from uspector import DNSScanner

scanner = DNSScanner()
result = scanner.scan("example.com")

print(result)
```

### TLS scanning

```python
from uspector import TLSScanner

scanner = TLSScanner()
result = scanner.check_tls("example.com", 443)

print(result)
```

### Web scanning

```python
from uspector import WebScanner

scanner = WebScanner()
result = scanner.scan("https://example.com")

print(result)
```

### PHP scanning

```python
from uspector import PHPScanner

scanner = PHPScanner()
result = scanner.scan("https://example.com")

print(result)
```

All scanners return structured results that can be processed by other Python code, incorporated into diagnostic workflows, or serialized for reporting.

## Features

### DNS diagnostics

- IPv4 (A) and IPv6 (AAAA) record lookups
- CNAME record inspection
- Mail server (MX) and name server (NS) discovery
- TXT record inspection, including important verification and SPF records
- CAA record inspection
- SOA record details, including primary nameserver, responsible party, and serial number
- SPF and DMARC configuration checks
- Optional DKIM record checks using a specified selector
- DNSSEC-related record inspection, including DS, DNSKEY, and RRSIG
- DNS findings and structured scan results

DNSSEC records are inspected for presence; their cryptographic validity is not verified.

### SSL/TLS inspection

- TLS connection testing and diagnostics
- Certificate trust and hostname validation
- Certificate expiration checks
- TLS version and cipher suite reporting
- DNS resolution and IP address reporting
- Certificate details, including subject, issuer, SAN, and fingerprint
- Structured scan results and security findings

### Web security diagnostics

- HTTP response status and redirect destination
- HTTP security-header inspection
- Cookie security-attribute checks, including `Secure`, `HttpOnly`, and `SameSite`
- DNS resolution and resolved IP reporting
- Detection of selected suspicious or error-related response-body indicators

### PHP security diagnostics

- Remote PHP technology detection
- PHP version disclosure detection
- Detection of publicly accessible `phpinfo()` pages
- PHP warning, notice, fatal error, and stack trace indicators
- Checks for publicly accessible PHP configuration and backup files
- Checks for potentially exposed `.env` files
- Composer manifest and lock-file exposure checks
- PHP-related directory listing detection
- Security findings with severity levels and remediation recommendations

PHP checks are performed remotely through HTTP responses. The scanner cannot determine the actual PHP version or configuration when this information is not publicly disclosed. File exposure indicators should be interpreted in context and do not automatically indicate a vulnerability.

### SEO diagnostics

- HTML title presence and length checks
- Meta description presence and length checks
- Canonical URL detection
- Meta robots and `X-Robots-Tag` inspection
- H1 heading count
- HTML language attribute detection
- Image alternative-text checks
- Open Graph title and description presence
- Detection of `noindex` directives

SEO checks are basic diagnostics, not a complete SEO audit. Findings such as title length or missing image alternative text should be interpreted in context.

## Understanding the Results

Uspector returns structured diagnostic information rather than a simple pass/fail result.

Depending on the scanner, results can include:

| Result | Description |
|---|---|
| DNS records | Observed DNS records, including addresses, mail servers, and nameservers |
| SPF / DMARC | Email security configuration checks |
| DNSSEC records | Presence of DNSSEC-related records; not cryptographic validation |
| Target | Hostname or URL being scanned |
| Status code | HTTP response status, for web and PHP scans |
| Final URL | Destination after redirects |
| Resolved IPs | IP addresses resolved during scanning |
| Certificate details | Certificate trust, hostname validity, expiration, and related properties |
| Security headers | Observed HTTP security-header values |
| PHP detection | PHP technology and version disclosure indicators |
| Exposed files | Potentially accessible configuration, backup, and diagnostic files |
| Findings | Detected configuration concerns or indicators |
| SEO | HTML and indexing-related diagnostics |
| Error | Error information when a scan cannot complete |

A reported missing DNS record, security header, or PHP indicator is an observation, not necessarily proof that a system is vulnerable. Findings should be assessed according to the domain's configuration, the site's architecture, intended behavior, and security requirements.

## Requirements

- Python 3.10 or later
- Internet connectivity to the target host
- Dependencies installed automatically by pip

## Responsible Use

Only scan systems and websites you own or are authorized to assess.

DNS, TLS, web, and PHP diagnostic results are informational and should be validated before making security decisions.

The remote PHP scanner performs HTTP-based inspection only. It does not execute PHP code, modify remote files, or attempt to exploit vulnerabilities.

## Project Structure

```text
uspector-net/
├── img/                  # Logo and media assets
├── src/
│   └── uspector/
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
