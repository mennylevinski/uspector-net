# Uspector – Copyright (c) 2026 Menahem Levinski

import argparse
import json
import sys

from .tlsscanner import TLSScanner

def main():
    parser = argparse.ArgumentParser(
        prog="uspector",
        description="Inspect TLS configuration and certificates of a remote host.",
    )

    parser.add_argument(
        "hostname",
        help="Hostname or IP address to scan.",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=443,
        help="Target port (default: 443).",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=5.0,
        help="Connection timeout in seconds (default: 5).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the complete result as JSON.",
    )

    args = parser.parse_args()

    try:
        scanner = TLSScanner(timeout=args.timeout)
        result = scanner.check_tls(args.hostname, args.port)

        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            print(f"Uspector TLS Scan: {args.hostname}:{args.port}")
            print("=" * 50)

            if isinstance(result, dict):
                for key, value in result.items():
                    print(f"{key.replace('_', ' ').title()}: {value}")
            else:
                print(result)

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
