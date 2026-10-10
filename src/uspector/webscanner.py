
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Uspector Passive Web Scanner
Author: Menny Levinski

HTTP security diagnostics.
TLS certificate and protocol checks are handled by tlsscanner.py.
"""

import socket
from urllib.parse import urlparse

import requests


class WebScanner:
    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout

    def scan(self, target: str) -> dict:
        """Scan an HTTP(S) endpoint and return structured results."""
        result = {
            "target": target,
            "final_url": None,
            "status_code": None,
            "findings": [],
            "security_headers": {},
            "cookies": [],
            "body_indicators": [],
            "resolved_ips": [],
            "error": None,
        }

        try:
            target = self._normalize_url(target)
            result["target"] = target

            parsed = urlparse(target)
            hostname = parsed.hostname

            if hostname:
                try:
                    addresses = socket.getaddrinfo(
                        hostname,
                        parsed.port or (443 if parsed.scheme == "https" else 80),
                        type=socket.SOCK_STREAM,
                    )
                    result["resolved_ips"] = list(
                        dict.fromkeys(item[4][0] for item in addresses)
                    )
                except socket.gaierror:
                    result["findings"].append(
                        "DNS resolution failed"
                    )

            # Ordinary GET request only; no attack payloads.
            with requests.get(
                target,
                timeout=self.timeout,
                allow_redirects=True,
                headers={"User-Agent": "Uspector-WebScanner/1.0"},
                stream=True,
            ) as response:
                result["final_url"] = response.url
                result["status_code"] = response.status_code

                headers = response.headers

                # HTTP security headers only. TLS checks remain in tlsscanner.
                header_names = (
                    "X-Content-Type-Options",
                    "X-Frame-Options",
                    "Content-Security-Policy",
                    "Referrer-Policy",
                    "Permissions-Policy",
                )

                for name in header_names:
                    value = headers.get(name)
                    result["security_headers"][name] = value

                    if value is None:
                        result["findings"].append(
                            f"Missing security header: {name}"
                        )

                # HSTS is an HTTP policy header, but only meaningful on HTTPS.
                if urlparse(response.url).scheme == "https":
                    value = headers.get("Strict-Transport-Security")
                    result["security_headers"][
                        "Strict-Transport-Security"
                    ] = value

                    if value is None:
                        result["findings"].append(
                            "Missing security header: "
                            "Strict-Transport-Security"
                        )

                # Cookie attributes.
                raw_headers = getattr(
                    getattr(response, "raw", None),
                    "headers",
                    None,
                )

                cookie_headers = (
                    raw_headers.getlist("Set-Cookie")
                    if raw_headers is not None
                    and hasattr(raw_headers, "getlist")
                    else []
                )

                if not cookie_headers:
                    cookie = headers.get("Set-Cookie")
                    if cookie:
                        cookie_headers = [cookie]

                for cookie_header in cookie_headers:
                    parts = [
                        part.strip()
                        for part in cookie_header.split(";")
                    ]
                    if not parts or "=" not in parts[0]:
                        continue

                    name = parts[0].split("=", 1)[0]
                    attributes = {
                        part.split("=", 1)[0].strip().lower()
                        for part in parts[1:]
                    }

                    cookie_result = {
                        "name": name,
                        "secure": "secure" in attributes,
                        "httponly": "httponly" in attributes,
                        "samesite": "samesite" in attributes,
                    }
                    result["cookies"].append(cookie_result)

                    missing = [
                        flag
                        for flag, present in (
                            ("Secure", cookie_result["secure"]),
                            ("HttpOnly", cookie_result["httponly"]),
                            ("SameSite", cookie_result["samesite"]),
                        )
                        if not present
                    ]

                    if missing:
                        result["findings"].append(
                            f"Cookie {name!r} missing attributes: "
                            + ", ".join(missing)
                        )

                # Read a bounded amount of response content.
                content_type = headers.get("Content-Type", "").lower()

                if "text/html" in content_type or "text/plain" in content_type:
                    body = bytearray()

                    for chunk in response.iter_content(16384):
                        body.extend(chunk)
                        if len(body) >= 1024 * 1024:
                            break

                    text = bytes(body[:1024 * 1024]).decode(
                        response.encoding or "utf-8",
                        errors="replace",
                    ).lower()

                    # Passive indicators only; these do not confirm vulnerabilities.
                    indicators = (
                        "<script>alert(1)</script>",
                        "sql syntax",
                        "mysql_fetch",
                        "sqlite error",
                        "postgresql error",
                        "odbc sql",
                    )

                    for indicator in indicators:
                        if indicator in text:
                            result["body_indicators"].append(indicator)

                    if result["body_indicators"]:
                        result["findings"].append(
                            "Informational response-body indicators detected"
                        )

        except (ValueError, requests.RequestException) as exc:
            result["error"] = str(exc)

        return result

    @staticmethod
    def _normalize_url(target: str) -> str:
        target = target.strip()

        if "://" not in target:
            target = "https://" + target

        parsed = urlparse(target)

        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError(
                "Target must be a valid HTTP or HTTPS URL"
            )

        return target
