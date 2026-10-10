# Uspector

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