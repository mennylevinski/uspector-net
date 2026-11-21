# Uspector – Copyright (c) 2026 Menahem Levinski

import argparse
import json
import sys

from importlib.metadata import version, PackageNotFoundError

from .dnsscanner import DNSScanner
from .tlsscanner import TLSScanner
from .webscanner import WebScanner
from .phpscanner import PHPScanner


def main():
    parser = argparse.ArgumentParser(
        prog="uspector",
        description="DNS, TLS, web, and remote PHP security diagnostics.",
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
        "--no-extended",
        action="store_true",
        help="Skip extended DNS checks (MTA-STS, TLS-RPT, BIMI, dangling CNAME).",
    )
    dns_parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=None,
        help="DNS query timeout in seconds (default: 2).",
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
        "--starttls",
        choices=("smtp", "imap", "ftp"),
        default=None,
        help="Negotiate STARTTLS before TLS handshake (smtp, imap, ftp).",
    )
    tls_parser.add_argument(
        "--probe-weak-ciphers",
        action="store_true",
        help="Opt-in active probing for legacy/weak cipher suites.",
    )
    tls_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the complete result as JSON.",
    )

        # PHP scanner
    php_parser = subparsers.add_parser(
        "php",
        help="Inspect remote PHP security and information disclosure.",
        description="Perform remote PHP security diagnostics.",
    )
    php_parser.add_argument(
        "target",
        help="Target URL or hostname.",
    )
    php_parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout in seconds (default: 10).",
    )
    php_parser.add_argument(
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
        "--no-private",
        action="store_true",
        help="Block private, loopback, and non-global destination IPs.",
    )
    web_parser.add_argument(
        "--check-metadata",
        action="store_true",
        help="Inspect security.txt, robots.txt, and HTTP-to-HTTPS redirect.",
    )
    web_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the complete result as JSON.",
    )

    args = parser.parse_args()

    try:
        if args.command == "dns":
            dns_init_kwargs = {}
            if args.timeout is not None:
                dns_init_kwargs["timeout"] = args.timeout
            scanner = DNSScanner(**dns_init_kwargs)
            dns_scan_kwargs = {
                "dkim_selector": args.dkim_selector,
                "include_dnssec": not args.no_dnssec,
            }
            if args.no_extended:
                dns_scan_kwargs["check_extended"] = False
            result = scanner.scan(
                args.hostname,
                **dns_scan_kwargs,
            )

        elif args.command == "tls":
            scanner = TLSScanner(timeout=args.timeout)
            tls_kwargs = {}
            if args.starttls is not None:
                tls_kwargs["starttls"] = args.starttls
            if args.probe_weak_ciphers:
                tls_kwargs["probe_weak_ciphers"] = True
            result = scanner.check_tls(args.hostname, args.port, **tls_kwargs)

        elif args.command == "web":
            web_init_kwargs = {"timeout": args.timeout}
            if args.no_private:
                web_init_kwargs["allow_private"] = False
            if args.check_metadata:
                web_init_kwargs["check_metadata"] = True
            scanner = WebScanner(**web_init_kwargs)
            result = scanner.scan(args.target)

        elif args.command == "php":
            scanner = PHPScanner(timeout=args.timeout)
            result = scanner.scan(args.target)

        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            print(scanner.format_scan(result))

        if isinstance(result, dict):
            if result.get("error"):
                return 1

            if (
                args.command == "tls"
                and result.get("connection_status") == "Failed"
                and result.get("diagnostic_handshake") == "Failed"
            ):
                return 1

            if args.command == "dns":
                records = result.get("records")
                failed_statuses = {
                    "DNS_ERROR",
                    "INVALID_QUERY",
                    "SERVFAIL",
                    "REFUSED",
                    "FORMERR",
                    "NOTIMP",
                    "NOTAUTH",
                    "NOTZONE",
                }
                if (
                    isinstance(records, dict)
                    and records
                    and all(
                        isinstance(entry, dict)
                        and entry.get("status") in failed_statuses
                        for entry in records.values()
                    )
                ):
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
