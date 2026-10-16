# Uspector – Copyright (c) 2026 Menahem Levinski

import argparse
import json
import sys

from importlib.metadata import version, PackageNotFoundError

from .dnsscanner import DNSScanner
from .tlsscanner import TLSScanner
from .webscanner import WebScanner


def main():
    parser = argparse.ArgumentParser(
        prog="uspector",
        description="DNS, TLS, and passive web security diagnostics.",
    )

    try:
        package_version = version("uspector")
    except PackageNotFoundError:
        package_version = "unknown"

    parser.add_argument(
        "--version",
        action="version",
        version=f"Uspector {package_version}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # DNS scanner
    dns_parser = subparsers.add_parser(
        "dns",
        help="Inspect DNS records, email security, and DNSSEC.",
        description="Perform DNS security diagnostics.",
    )
    dns_parser.add_argument(
        "hostname",
        help="Hostname or domain to scan.",
    )
    dns_parser.add_argument(
        "--dkim-selector",
        help="DKIM selector to check (optional).",
    )
    dns_parser.add_argument(
        "--no-dnssec",
        action="store_true",
        help="Skip DNSSEC inspection.",
    )
    dns_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the complete result as JSON.",
    )

    # TLS scanner
    tls_parser = subparsers.add_parser(
        "tls",
        help="Inspect TLS configuration and certificates.",
        description="Inspect TLS configuration and certificates.",
    )
    tls_parser.add_argument(
        "hostname",
        help="Hostname or IP address to scan.",
    )
    tls_parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=443,
        help="Target port (default: 443).",
    )
    tls_parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=5.0,
        help="Connection timeout in seconds (default: 5).",
    )
    tls_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the complete result as JSON.",
    )

    # Web scanner
    web_parser = subparsers.add_parser(
        "web",
        help="Inspect HTTP security headers, cookies, and response content.",
        description="Perform passive HTTP security diagnostics.",
    )
    web_parser.add_argument(
        "target",
        help="Target URL or hostname.",
    )
    web_parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=15.0,
        help="HTTP timeout in seconds (default: 15).",
    )
    web_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the complete result as JSON.",
    )

    args = parser.parse_args()

    try:
        if args.command == "dns":
            scanner = DNSScanner()
            result = scanner.scan(
                args.hostname,
                dkim_selector=args.dkim_selector,
                include_dnssec=not args.no_dnssec,
            )
            title = f"Uspector DNS Scan: {args.hostname}"

        elif args.command == "tls":
            scanner = TLSScanner(timeout=args.timeout)
            result = scanner.check_tls(args.hostname, args.port)
            title = f"Uspector TLS Scan: {args.hostname}:{args.port}"

        else:
            scanner = WebScanner(timeout=args.timeout)
            result = scanner.scan(args.target)
            title = f"Uspector Web Scan: {args.target}"

        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            print(scanner.format_scan(result))

        if isinstance(result, dict) and result.get("error"):
            return 1

        return 0

    except KeyboardInterrupt:
        print("\nScan interrupted.", file=sys.stderr)
        return 130
    except (ValueError, TypeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Scan failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
