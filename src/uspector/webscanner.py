# Uspector – Copyright (c) 2026 Menahem Levinski

"""
HTTP security diagnostics.
"""

import socket
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser

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
            "seo": None,
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

                    
                    if "text/html" in content_type:
                        seo_parser = SEOHTMLParser()
                        seo_parser.feed(
                            bytes(body[:1024 * 1024]).decode(
                                response.encoding or "utf-8",
                                errors="replace",
                            )
                        )

                        title = " ".join(
                            "".join(seo_parser.title).split()
                        )
                        description = seo_parser.meta_description
                        final_url = result["final_url"] or target

                        seo = {
                            "title": title or None,
                            "title_length": len(title),
                            "meta_description": description or None,
                            "meta_description_length": len(description or ""),
                            "canonical_url": (
                                urljoin(final_url, seo_parser.canonical_url)
                                if seo_parser.canonical_url
                                else None
                            ),
                            "meta_robots": seo_parser.meta_robots,
                            "x_robots_tag": headers.get("X-Robots-Tag"),
                            "h1_count": len(seo_parser.h1_headings),
                            "h1_headings": seo_parser.h1_headings,
                            "html_language": seo_parser.html_lang,
                            "image_count": seo_parser.image_count,
                            "images_missing_alt": seo_parser.images_missing_alt,
                            "og_title": seo_parser.og_title,
                            "og_description": seo_parser.og_description,
                            "findings": [],
                        }

                        if not title:
                            seo["findings"].append("Missing page title")
                        elif len(title) > 60:
                            seo["findings"].append(
                                "Page title exceeds 60 characters"
                            )

                        if not description:
                            seo["findings"].append(
                                "Missing meta description"
                            )
                        elif len(description) > 160:
                            seo["findings"].append(
                                "Meta description exceeds 160 characters"
                            )

                        if not seo["canonical_url"]:
                            seo["findings"].append("Missing canonical URL")

                        if seo["h1_count"] == 0:
                            seo["findings"].append("Missing H1 heading")
                        elif seo["h1_count"] > 1:
                            seo["findings"].append("Multiple H1 headings")

                        if not seo["html_language"]:
                            seo["findings"].append(
                                "Missing HTML language declaration"
                            )

                        if seo["images_missing_alt"]:
                            seo["findings"].append(
                                f"{seo['images_missing_alt']} image(s) "
                                "missing alt text"
                            )

                        if not seo["og_title"]:
                            seo["findings"].append(
                                "Missing Open Graph title"
                            )

                        if not seo["og_description"]:
                            seo["findings"].append(
                                "Missing Open Graph description"
                            )

                        # Check whether search engines are instructed
                        # not to index this page.
                        robots_directives = " ".join(
                            value for value in (
                                seo["meta_robots"],
                                seo["x_robots_tag"],
                            )
                            if value
                        ).lower()

                        if "noindex" in robots_directives:
                            seo["findings"].append(
                                "Noindex directive detected; search engines "
                                "may exclude this page"
                            )

                        result["seo"] = seo

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


class SEOHTMLParser(HTMLParser):
    """Extract basic on-page SEO signals from HTML."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = []
        self.h1_headings = []
        self.meta_description = None
        self.meta_robots = None
        self.canonical_url = None
        self.og_title = None
        self.og_description = None
        self.html_lang = None
        self.image_count = 0
        self.images_missing_alt = 0
        self._in_title = False
        self._in_h1 = False
        self._current_h1 = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        tag = tag.lower()

        if tag == "html":
            self.html_lang = attrs.get("lang")

        elif tag == "title":
            self._in_title = True

        elif tag == "h1":
            self._in_h1 = True
            self._current_h1 = []

        elif tag == "img":
            self.image_count += 1
            if not attrs.get("alt", "").strip():
                self.images_missing_alt += 1

        elif tag == "meta":
            name = (attrs.get("name") or "").strip().lower()
            prop = (attrs.get("property") or "").strip().lower()
            content = (attrs.get("content") or "").strip()

            if name == "description":
                self.meta_description = content
            elif name == "robots":
                self.meta_robots = content
            elif prop == "og:title":
                self.og_title = content
            elif prop == "og:description":
                self.og_description = content

        elif tag == "link":
            rel = (attrs.get("rel") or "").lower().split()
            href = attrs.get("href")
            if "canonical" in rel and href:
                self.canonical_url = href.strip()

    def handle_data(self, data):
        if self._in_title:
            self.title.append(data)
        if self._in_h1:
            self._current_h1.append(data)

    def handle_endtag(self, tag):
        tag = tag.lower()

        if tag == "title":
            self._in_title = False

        elif tag == "h1" and self._in_h1:
            heading = " ".join("".join(self._current_h1).split())
            self.h1_headings.append(heading)
            self._current_h1 = []
            self._in_h1 = False
