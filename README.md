 <a name="top"></a>

<div align="center">

  <a href="https://github.com/mennylevinski/uspector-net">
    <img src="img/uspector-main-logo2.png" alt="Uspector TLS and Web Security Scanner logo" width="200" height="200">
  </a>

</div>

# Uspector — SSL/TLS Security & Web Diagnostics

Uspector is a Python library and command-line tool for SSL/TLS inspection, certificate validation, and passive web security diagnostics.

It helps developers and security professionals inspect TLS configurations, review certificate details, and identify common web security and SEO configuration issues.

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

Uspector provides separate commands for TLS inspection and web diagnostics.

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

Uspector exposes `TLSScanner` and `WebScanner` for use in Python applications.

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

Both scanners return structured results that can be processed by other Python code, incorporated into diagnostic workflows, or serialized for reporting.

## Features

### SSL/TLS inspection

- TLS connection testing and diagnostics
- Certificate trust and hostname validation
- Certificate expiration checks
- TLS version and cipher suite reporting
- DNS resolution and IP address reporting
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
| Target | Hostname or URL being scanned |
| Status code | HTTP response status, for web scans |
| Final URL | Destination after redirects |
| Resolved IPs | IP addresses resolved during scanning |
| Security headers | Observed HTTP security-header values |
| Findings | Detected configuration concerns or indicators |
| SEO | HTML and indexing-related diagnostics |
| Error | Error information when a scan cannot complete |

A reported missing security header is an observation, not proof that a website is vulnerable. Findings should be assessed according to the site's architecture, intended behavior, and security requirements.

## Requirements

- Python 3.10 or later
- Internet connectivity to the target host
- Dependencies installed automatically by pip

## Responsible Use

Only scan systems and websites you own or are authorized to assess. TLS and web diagnostic results are informational and should be validated before making security decisions.

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
