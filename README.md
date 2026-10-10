
<div align="center" style="line-height: 0;">
  <a href="https://github.com/mennylevinski/uspector-net">
    <img src="img/uspector-main-logo2.png" alt="Uspector TLS and Certificate Scanner logo" width="200" height="200">
  </a>
</div>

# Uspector – SSL/TLS Security

A Python library for SSL/TLS security testing, certificate validation, and web diagnostics.

## Installation

Install from PyPI:

    pip install uspector

Upgrade to the latest version:

    pip install --upgrade uspector

## Usage

### Command-Line Interface (CLI)

Scan a hostname:

    uspector example.com

### Python Library

    from uspector import Uspector

    scanner = Uspector()
    result = scanner.scan("example.com")

    print(result)

Replace `example.com` with the hostname you want to test.

## Features

- SSL/TLS connection testing and diagnostics
- Certificate trust, hostname validation, and expiration checks
- TLS version and cipher suite reporting
- DNS resolution and IP address reporting
- Security findings and scan verdicts
- Command-line interface and Python API

## Requirements

- Python 3.10 or later
- Internet connectivity to the target host

Dependencies are installed automatically with the package.

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.

## 📁 Project Structure

```bash
uspector-net/                    # Main project folder
│
├── img/                          # Logo and media assets
│
├── uspector/                     # Python package source code
│
├── LICENSE                       # License file
├── README.md                     # Project overview and usage
└── pyproject.toml                # Package configuration and dependencies
```
---

<br>
<p align="center">
© 2026 Menahem Levinski. All rights reserved.
<a href="#top">🔝</a>
</p>