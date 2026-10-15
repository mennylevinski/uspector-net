# Uspector — SSL/TLS Security, DNS & Web Diagnostics

Uspector is a Python library and command-line tool for SSL/TLS inspection, DNS diagnostics, certificate validation, and passive web security diagnostics.

It helps developers and security professionals inspect TLS configurations, review certificate details, analyze important DNS records, and identify common web security and SEO configuration issues.

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

Uspector provides separate commands for DNS diagnostics, TLS inspection, and web diagnostics.

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

## Python API

Uspector exposes `DNSScanner`, `TLSScanner`, and `WebScanner` for use in Python applications.

### DNS scanning

```python
from uspector import DNSScanner

scanner = DNSScanner()
result = scanner.scan("example.com")

print(result)
```

The DNS scanner returns structured information about DNS records, email security configuration, DNSSEC record presence, and detected findings.

### TLS scanning

```python
from uspector import TLSScanner

scanner = TLSScanner()
result = scanner.scan("example.com")

print(result)
```

### Web scanning

```python
from uspector import WebScanner

scanner = WebScanner()
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
| Status code | HTTP response status, for web scans |
| Final URL | Destination after redirects |
| Resolved IPs | IP addresses resolved during scanning |
| Certificate details | Certificate trust, hostname validity, expiration, and related properties |
| Security headers | Observed HTTP security-header values |
| Findings | Detected configuration concerns or indicators |
| SEO | HTML and indexing-related diagnostics |
| Error | Error information when a scan cannot complete |

A reported missing DNS record or security header is an observation, not necessarily proof that a system is vulnerable. Findings should be assessed according to the domain's configuration, the site's architecture, intended behavior, and security requirements.

## Requirements

- Python 3.10 or later
- Internet connectivity to the target host
- Dependencies installed automatically by pip

## Responsible Use

Only scan systems and websites you own or are authorized to assess. DNS, TLS, and web diagnostic results are informational and should be validated before making security decisions.

## Project Structure

```text
uspector-net/
├── img/                  # Logo and media assets
├── src/
│   └── uspector/         # Python package source code
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