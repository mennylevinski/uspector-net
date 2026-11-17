# Uspector – Copyright (c) 2026 Menahem Levinski

"""
HTTP security diagnostics.
"""

import codecs
import contextlib
import re
import socket
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser

import requests

from ._http import (
    PinnedIPAdapter,
    extract_set_cookie_headers,
    parse_cookie_attributes,
    validate_public_http_url,
    validate_timeout,
)


class WebScanner:
    MAX_REDIRECTS = 5
    MAX_RESPONSE_SIZE = 1024 * 1024

    def __init__(
        self,
        timeout: float = 15.0,
        allow_private: bool = True,
        check_metadata: bool = False,
    ):
        self.timeout = validate_timeout(timeout)
        self.allow_private = bool(allow_private)
        self.check_metadata = bool(check_metadata)

    @staticmethod
    def format_scan(result: dict) -> str:
        """Format web scan results for readable CLI output."""
        lines = [
            f"Uspector Web Scan: {result.get('target') or 'Unknown'}",
            "=" * 50,
            "",
            "HTTP Overview:",
        ]

        if result.get("final_url"):
            lines.append(f"  Final URL: {result['final_url']}")

        status = result.get("status_code")
        lines.append(
            f"  Status Code: {status if status is not None else 'Unavailable'}"
        )

        ips = result.get("resolved_ips") or []
        lines.append("  Resolved IPs:")
        if ips:
            lines.extend(f"    - {ip}" for ip in ips)
        else:
            lines.append("    None found")

        if result.get("error"):
            lines.append(f"  Error: {result['error']}")

        # Security headers
        lines.extend(["", "Security Headers:"])
        headers = result.get("security_headers") or {}

        if headers:
            for name, value in headers.items():
                lines.append(f"  {name}: {value if value else 'Not present'}")
        else:
            lines.append("  No header information available")

        # Cookies
        lines.extend(["", "Cookies:"])
        cookies = result.get("cookies") or []

        if cookies:
            for cookie in cookies:
                lines.append(f"  - {cookie.get('name', 'Unknown')}")
                lines.append(
                    f"      Secure: {'Yes' if cookie.get('secure') else 'No'}"
                )
                lines.append(
                    f"      HttpOnly: {'Yes' if cookie.get('httponly') else 'No'}"
                )
                lines.append(
                    f"      SameSite: {'Yes' if cookie.get('samesite') else 'No'}"
                )
        else:
            lines.append("  None found")

        # Response-body indicators
        lines.extend(["", "Response Indicators:"])
        indicators = result.get("body_indicators") or []

        if indicators:
            lines.extend(f"  - {item}" for item in indicators)
        else:
            lines.append("  None detected")

        # SEO diagnostics
        lines.extend(["", "SEO Diagnostics:"])
        seo = result.get("seo")

        if isinstance(seo, dict):
            seo_fields = [
                ("Title Length", "title_length"),
                ("Meta Description", "has_meta_description"),
                ("Meta Description Length", "meta_description_length"),
                ("Canonical URL", "canonical_url"),
                ("Meta Robots", "meta_robots"),
                ("X-Robots-Tag", "x_robots_tag"),
                ("H1 Count", "h1_count"),
                ("HTML Language", "html_language"),
                ("Image Count", "image_count"),
                ("Images Missing Alt", "images_missing_alt"),
                ("Open Graph Title", "has_og_title"),
                ("Open Graph Description", "has_og_description"),
            ]

            for label, key in seo_fields:
                value = seo.get(key)
                if isinstance(value, bool):
                    value = "Yes" if value else "No"
                elif value is None or value == "":
                    value = "Not found"
                lines.append(f"  {label}: {value}")

            seo_findings = seo.get("findings") or []
            lines.append("  SEO Findings:")
            if seo_findings:
                lines.extend(f"    - {item}" for item in seo_findings)
            else:
                lines.append("    None")
        else:
            lines.append("  No HTML SEO data available")

        # General findings
        lines.extend(["", "Findings:"])
        findings = result.get("findings") or []

        if findings:
            lines.extend(f"  - {item}" for item in findings)
        else:
            lines.append("  None")

        return "\n".join(lines)

    @contextlib.contextmanager
    def _open_response(self, target: str):
        headers = {"User-Agent": "Uspector-WebScanner/1.0"}

        if self.allow_private:
            with requests.get(
                target,
                timeout=self.timeout,
                allow_redirects=True,
                headers=headers,
                stream=True,
            ) as response:
                history = getattr(response, "history", None)
                hist_list = (
                    list(history)
                    if isinstance(history, (list, tuple))
                    else []
                )
                yield response, hist_list
            return

        current_url = target
        pinned_ips = {}
        history = []

        with requests.Session() as session:
            session.trust_env = False
            adapter = PinnedIPAdapter(pinned_ips)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            session.headers.update(headers)

            for _ in range(self.MAX_REDIRECTS + 1):
                host, port, dest_ip = validate_public_http_url(
                    current_url,
                    error_prefix="Target",
                    resolver=socket.getaddrinfo,
                )
                pinned_ips[(host, port)] = dest_ip

                response = session.get(
                    current_url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    stream=True,
                )

                if response.is_redirect or response.is_permanent_redirect:
                    location = response.headers.get("Location")
                    cookie_headers = extract_set_cookie_headers(response)
                    response.close()

                    if not location:
                        raise ValueError("Redirect without a Location header.")

                    history.append(cookie_headers)
                    current_url = urljoin(current_url, location)
                    continue

                try:
                    yield response, history
                finally:
                    response.close()
                return

        raise ValueError("Maximum redirect limit exceeded.")

    @staticmethod
    def _detect_charset(
        raw_bytes: bytes,
        content_type: str,
        response_encoding: str | None,
    ) -> str:
        def _valid_codec(name: str | None) -> str | None:
            if not name:
                return None
            try:
                codecs.lookup(name)
                return name
            except LookupError:
                return None

        ct_match = re.search(
            r'charset\s*=\s*["\']?([A-Za-z0-9._-]+)',
            content_type,
            re.IGNORECASE,
        )
        if ct_match:
            codec = _valid_codec(ct_match.group(1))
            if codec:
                return codec

        if "text/html" in content_type:
            head = raw_bytes[:4096].decode("ascii", errors="ignore")
            meta_match = re.search(
                r'<meta\b[^>]*\bcharset\s*=\s*["\']?\s*([A-Za-z0-9._-]+)',
                head,
                re.IGNORECASE,
            )
            if meta_match:
                codec = _valid_codec(meta_match.group(1))
                if codec:
                    return codec

        if response_encoding and response_encoding.lower() not in (
            "iso-8859-1",
            "latin-1",
            "latin1",
        ):
            codec = _valid_codec(response_encoding)
            if codec:
                return codec

        return "utf-8"

    @staticmethod
    def _audit_csp(csp_value: str, findings: list[str]) -> None:
        directives: dict[str, list[str]] = {}
        for part in csp_value.split(";"):
            tokens = part.strip().split()
            if tokens:
                directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]

        script_sources = directives.get("script-src", directives.get("default-src", []))
        if "'unsafe-inline'" in script_sources:
            findings.append("CSP allows 'unsafe-inline' scripts")
        if "'unsafe-eval'" in script_sources:
            findings.append("CSP allows 'unsafe-eval' scripts")
        if "*" in script_sources:
            findings.append("CSP allows wildcard '*' script source")
        if "frame-ancestors" not in directives:
            findings.append("CSP missing 'frame-ancestors' directive")
        if "object-src" not in directives:
            findings.append("CSP missing 'object-src' directive")

    @classmethod
    def _audit_security_headers(
        cls,
        headers,
        final_url: str,
        has_cookies: bool,
        result: dict,
    ) -> None:
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

            if value is None or not str(value).strip():
                result["findings"].append(f"Missing security header: {name}")

        xcto = headers.get("X-Content-Type-Options")
        if xcto and str(xcto).strip().lower() != "nosniff":
            result["findings"].append(
                "Invalid X-Content-Type-Options header (expected 'nosniff')"
            )

        xfo = headers.get("X-Frame-Options")
        if xfo and str(xfo).strip().upper() not in ("DENY", "SAMEORIGIN"):
            result["findings"].append(
                "Weak or non-standard X-Frame-Options header"
            )

        csp = headers.get("Content-Security-Policy")
        if csp and str(csp).strip():
            cls._audit_csp(str(csp), result["findings"])
        elif headers.get("Content-Security-Policy-Report-Only"):
            result["findings"].append(
                "Content-Security-Policy is in report-only mode (not enforced)"
            )

        ref_policy = headers.get("Referrer-Policy")
        if ref_policy and str(ref_policy).strip():
            policies = [p.strip().lower() for p in str(ref_policy).split(",")]
            if any(p in ("unsafe-url", "no-referrer-when-downgrade") for p in policies):
                result["findings"].append(
                    "Weak Referrer-Policy value configured"
                )

        # HSTS is an HTTP policy header, only meaningful on HTTPS.
        final_scheme = urlparse(final_url).scheme.lower()
        if final_scheme == "https":
            value = headers.get("Strict-Transport-Security")
            result["security_headers"]["Strict-Transport-Security"] = value

            if value is None or not str(value).strip():
                result["findings"].append(
                    "Missing security header: Strict-Transport-Security"
                )
            else:
                max_age_match = re.search(
                    r"(?:^|;)\s*max-age\s*=\s*(\d+)",
                    str(value),
                    re.IGNORECASE,
                )
                if not max_age_match or int(max_age_match.group(1)) <= 0:
                    result["findings"].append(
                        "Insecure Strict-Transport-Security header: "
                        "max-age is missing or zero"
                    )
                else:
                    if int(max_age_match.group(1)) < 31536000:
                        result["findings"].append(
                            "HSTS max-age is below recommended 1 year (31536000 seconds)"
                        )
                    if "includesubdomains" not in str(value).lower():
                        result["findings"].append(
                            "HSTS header missing includeSubDomains directive"
                        )
        elif final_scheme == "http":
            result["findings"].append(
                "Target served over unencrypted HTTP (HSTS requires HTTPS)"
            )

        # Optional cross-origin isolation headers (record when present).
        for iso_name in (
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Embedder-Policy",
            "Cross-Origin-Resource-Policy",
            "X-Permitted-Cross-Domain-Policies",
        ):
            iso_val = headers.get(iso_name)
            if iso_val is not None:
                result["security_headers"][iso_name] = iso_val
                if (
                    iso_name == "X-Permitted-Cross-Domain-Policies"
                    and str(iso_val).strip().lower() == "all"
                ):
                    result["findings"].append(
                        "Permissive X-Permitted-Cross-Domain-Policies: all"
                    )

        # Passive CORS & cache checks.
        acao = (headers.get("Access-Control-Allow-Origin") or "").strip()
        acac = (headers.get("Access-Control-Allow-Credentials") or "").strip().lower()
        if acao == "*" and acac == "true":
            result["findings"].append(
                "Insecure CORS configuration: wildcard origin with credentials"
            )

        if has_cookies:
            cache_ctrl = (headers.get("Cache-Control") or "").lower()
            if "no-store" not in cache_ctrl and "private" not in cache_ctrl:
                result["findings"].append(
                    "Response sets cookies without Cache-Control: no-store or private"
                )

        # Server / technology version banner disclosure.
        for banner_hdr in (
            "Server",
            "X-Powered-By",
            "X-AspNet-Version",
            "X-AspNetMvc-Version",
        ):
            banner_val = headers.get(banner_hdr)
            if banner_val and re.search(r"[/ ]\d+(?:\.\d+)+", str(banner_val)):
                result["findings"].append(
                    f"Server technology version disclosed in {banner_hdr} header"
                )

    @staticmethod
    def _audit_html_security(
        seo_parser: "SEOHTMLParser",
        final_url: str,
        result: dict,
    ) -> None:
        parsed_final = urlparse(final_url)
        final_scheme = parsed_final.scheme.lower()
        final_netloc = parsed_final.netloc.lower()

        if final_scheme == "https":
            if seo_parser.mixed_active_urls:
                result["findings"].append(
                    f"Mixed active/form content over HTTP detected ({len(seo_parser.mixed_active_urls)})"
                )
            if seo_parser.mixed_passive_urls:
                result["findings"].append(
                    f"Mixed passive content (HTTP images) detected ({len(seo_parser.mixed_passive_urls)})"
                )

        missing_sri = 0
        for res_url, has_integrity in seo_parser.external_sri_resources:
            parsed_res = urlparse(urljoin(final_url, res_url))
            if (
                parsed_res.scheme.lower() in ("http", "https")
                and parsed_res.netloc
                and parsed_res.netloc.lower() != final_netloc
                and not has_integrity
            ):
                missing_sri += 1
        if missing_sri:
            result["findings"].append(
                f"{missing_sri} external script/stylesheet(s) missing Subresource Integrity (SRI)"
            )

        if seo_parser.unsafe_blank_links:
            result["findings"].append(
                f"{seo_parser.unsafe_blank_links} link(s) with target='_blank' missing rel='noopener'/'noreferrer'"
            )

        if seo_parser.has_password_input and (
            final_scheme == "http" or seo_parser.insecure_password_form
        ):
            result["findings"].append(
                "Password input served or submitted over unencrypted HTTP"
            )

    def _check_metadata_endpoints(
        self,
        original_target: str,
        final_url: str,
        result: dict,
    ) -> None:
        parsed_final = urlparse(final_url)
        origin = f"{parsed_final.scheme}://{parsed_final.netloc}"

        metadata: dict = {}

        # 1. /.well-known/security.txt
        try:
            with self._open_response(f"{origin}/.well-known/security.txt") as (sec_resp, _):
                if sec_resp.status_code == 200:
                    sec_body = b"".join(sec_resp.iter_content(8192))[:65536].decode(
                        "utf-8", errors="replace"
                    )
                    has_contact = bool(re.search(r"(?im)^Contact:", sec_body))
                    exp_match = re.search(r"(?im)^Expires:\s*(.+)$", sec_body)
                    metadata["security_txt"] = {
                        "present": has_contact,
                        "expires": exp_match.group(1).strip() if exp_match else None,
                    }
        except (ValueError, requests.RequestException, OSError):
            pass

        # 2. /robots.txt passive sensitive-disallow inspection
        try:
            with self._open_response(f"{origin}/robots.txt") as (rob_resp, _):
                if rob_resp.status_code == 200:
                    rob_body = b"".join(rob_resp.iter_content(8192))[:65536].decode(
                        "utf-8", errors="replace"
                    )
                    disallows = re.findall(
                        r"(?im)^Disallow:\s*(\S+)",
                        rob_body,
                    )
                    sensitive = [
                        p for p in disallows
                        if any(
                            kw in p.lower()
                            for kw in ("admin", "backup", ".env", "phpinfo", "config")
                        )
                    ]
                    metadata["robots_txt"] = {
                        "present": True,
                        "sensitive_disallows": sensitive,
                    }
                    if sensitive:
                        result["findings"].append(
                            "robots.txt references potentially sensitive disallowed paths"
                        )
        except (ValueError, requests.RequestException, OSError):
            pass

        # 3. HTTP -> HTTPS redirect enforcement check
        parsed_orig = urlparse(original_target)
        if parsed_orig.scheme.lower() == "http" or parsed_final.scheme.lower() == "https":
            http_url = f"http://{parsed_final.netloc}/"
            try:
                with self._open_response(http_url) as (http_resp, _):
                    if urlparse(http_resp.url or http_url).scheme.lower() != "https":
                        result["findings"].append(
                            "HTTP endpoint does not redirect to HTTPS"
                        )
                        metadata["https_redirect"] = False
                    else:
                        metadata["https_redirect"] = True
            except (ValueError, requests.RequestException, OSError):
                pass

        if metadata:
            result["metadata"] = metadata

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
            with self._open_response(target) as (response, history):
                final_url = response.url or target
                result["final_url"] = final_url
                result["status_code"] = response.status_code

                headers = response.headers

                # Cookie attributes across redirect history and final response.
                cookie_headers: list[str] = []
                for item in history:
                    if isinstance(item, list):
                        cookie_headers.extend(item)
                    else:
                        cookie_headers.extend(extract_set_cookie_headers(item))
                cookie_headers.extend(extract_set_cookie_headers(response))

                cookies_by_name: dict[str, dict] = {}
                for cookie_header in cookie_headers:
                    cookie_result = parse_cookie_attributes(cookie_header)
                    if cookie_result:
                        cookies_by_name[cookie_result["name"]] = cookie_result

                self._audit_security_headers(
                    headers,
                    final_url,
                    bool(cookies_by_name),
                    result,
                )

                for cookie_result in cookies_by_name.values():
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
                            f"Cookie {cookie_result['name']!r} missing attributes: "
                            + ", ".join(missing)
                        )

                # Read a bounded amount of response content.
                content_type = headers.get("Content-Type", "").lower()

                if "text/html" in content_type or "text/plain" in content_type:
                    body = bytearray()

                    for chunk in response.iter_content(16384):
                        if not chunk:
                            continue
                        remaining = self.MAX_RESPONSE_SIZE - len(body)
                        if remaining <= 0:
                            break
                        body.extend(chunk[:remaining])
                        if len(body) >= self.MAX_RESPONSE_SIZE:
                            break

                    raw_bytes = bytes(body)
                    charset = self._detect_charset(
                        raw_bytes,
                        content_type,
                        getattr(response, "encoding", None),
                    )
                    decoded_text = raw_bytes.decode(charset, errors="replace")
                    lower_text = decoded_text.lower()

                    # Passive indicators only; these do not confirm vulnerabilities.
                    indicators = (
                        "<script>alert(1)</script>",
                        "sql syntax",
                        "mysql_fetch",
                        "sqlite error",
                        "postgresql error",
                        "odbc sql",
                        "traceback (most recent call last):",
                        "django.core.exceptions",
                        "werkzeug.debug",
                        "server error in '/' application",
                        "whitelabel error page",
                        "sourcemappingurl=",
                    )

                    for indicator in indicators:
                        if indicator in lower_text:
                            result["body_indicators"].append(indicator)

                    private_ip_url_re = re.compile(
                        r"https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
                        r"192\.168\.\d{1,3}\.\d{1,3}|"
                        r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
                        re.IGNORECASE,
                    )
                    if private_ip_url_re.search(decoded_text):
                        result["body_indicators"].append("internal-ip-url")

                    if result["body_indicators"]:
                        result["findings"].append(
                            "Informational response-body indicators detected"
                        )

                    if "text/html" in content_type:
                        seo_parser = SEOHTMLParser()
                        seo_parser.feed(decoded_text)

                        if any(
                            private_ip_url_re.search(c)
                            or re.search(
                                r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
                                r"192\.168\.\d{1,3}\.\d{1,3}|"
                                r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
                                c,
                            )
                            for c in seo_parser.comments
                        ):
                            if "internal-ip-comment" not in result["body_indicators"]:
                                result["body_indicators"].append("internal-ip-comment")
                            if (
                                "Informational response-body indicators detected"
                                not in result["findings"]
                            ):
                                result["findings"].append(
                                    "Informational response-body indicators detected"
                                )

                        self._audit_html_security(seo_parser, final_url, result)

                        title = " ".join(
                            "".join(seo_parser.title).split()
                        )
                        description = seo_parser.meta_description
                        final_url = result["final_url"] or target

                        seo = {
                            "title_length": len(title),
                            "has_meta_description": bool(description),
                            "meta_description_length": len(description or ""),
                            "canonical_url": (
                                urljoin(final_url, seo_parser.canonical_url)
                                if seo_parser.canonical_url
                                else None
                            ),
                            "meta_robots": seo_parser.meta_robots,
                            "x_robots_tag": headers.get("X-Robots-Tag"),
                            "h1_count": len(seo_parser.h1_headings),
                            "html_language": seo_parser.html_lang,
                            "image_count": seo_parser.image_count,
                            "images_missing_alt": seo_parser.images_missing_alt,
                            "has_og_title": bool(seo_parser.og_title),
                            "has_og_description": bool(seo_parser.og_description),
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

                        if not seo["has_og_title"]:
                            seo["findings"].append(
                                "Missing Open Graph title"
                            )

                        if not seo["has_og_description"]:
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

                if self.check_metadata:
                    self._check_metadata_endpoints(
                        target,
                        final_url,
                        result,
                    )

        except (TypeError, ValueError, requests.RequestException, OSError) as exc:
            result["error"] = str(exc)

        return result

    @staticmethod
    def _normalize_url(target: str) -> str:
        if not isinstance(target, str):
            raise TypeError("Target must be a string")

        target = target.strip()

        if "://" not in target:
            target = "https://" + target

        parsed = urlparse(target)

        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or (parsed.port is not None and not (1 <= parsed.port <= 65535))
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
        self._has_title = False
        self._svg_depth = 0
        self._in_h1 = False
        self._current_h1 = []
        self.mixed_active_urls = []
        self.mixed_passive_urls = []
        self.external_sri_resources = []
        self.unsafe_blank_links = 0
        self.has_password_input = False
        self.insecure_password_form = False
        self._current_form_insecure = False
        self.comments = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        tag = tag.lower()

        if tag == "svg":
            self._svg_depth += 1

        elif tag == "html" and self.html_lang is None:
            self.html_lang = attrs.get("lang")

        elif tag == "title":
            if self._svg_depth == 0 and not self._has_title:
                self._in_title = True

        elif tag == "h1":
            self._in_h1 = True
            self._current_h1 = []

        elif tag == "img":
            self.image_count += 1
            if "alt" not in attrs:
                self.images_missing_alt += 1
            src = (attrs.get("src") or "").strip()
            if src.lower().startswith("http://"):
                self.mixed_passive_urls.append(src)

        elif tag == "script":
            src = (attrs.get("src") or "").strip()
            if src:
                if src.lower().startswith("http://"):
                    self.mixed_active_urls.append(src)
                self.external_sri_resources.append((src, "integrity" in attrs))

        elif tag == "iframe":
            src = (attrs.get("src") or "").strip()
            if src.lower().startswith("http://"):
                self.mixed_active_urls.append(src)

        elif tag == "a":
            target_attr = (attrs.get("target") or "").strip().lower()
            if target_attr == "_blank":
                rel_tokens = set((attrs.get("rel") or "").lower().split())
                if "noopener" not in rel_tokens and "noreferrer" not in rel_tokens:
                    self.unsafe_blank_links += 1

        elif tag == "form":
            action = (attrs.get("action") or "").strip()
            self._current_form_insecure = action.lower().startswith("http://")
            if self._current_form_insecure:
                self.mixed_active_urls.append(action)

        elif tag == "input":
            if (attrs.get("type") or "").strip().lower() == "password":
                self.has_password_input = True
                if self._current_form_insecure:
                    self.insecure_password_form = True

        elif tag == "meta":
            name = (attrs.get("name") or "").strip().lower()
            prop = (attrs.get("property") or "").strip().lower()
            content = (attrs.get("content") or "").strip()

            if name == "description" and self.meta_description is None:
                self.meta_description = content
            elif name == "robots" and self.meta_robots is None:
                self.meta_robots = content
            elif prop == "og:title" and self.og_title is None:
                self.og_title = content
            elif prop == "og:description" and self.og_description is None:
                self.og_description = content

        elif tag == "link":
            rel = (attrs.get("rel") or "").lower().split()
            href = (attrs.get("href") or "").strip()
            if "canonical" in rel and href and self.canonical_url is None:
                self.canonical_url = href
            if "stylesheet" in rel and href:
                if href.lower().startswith("http://"):
                    self.mixed_active_urls.append(href)
                self.external_sri_resources.append((href, "integrity" in attrs))

    def handle_comment(self, data):
        if data:
            self.comments.append(data)

    def handle_data(self, data):
        if self._in_title:
            self.title.append(data)
        if self._in_h1:
            self._current_h1.append(data)

    def handle_endtag(self, tag):
        tag = tag.lower()

        if tag == "svg" and self._svg_depth > 0:
            self._svg_depth -= 1

        elif tag == "form":
            self._current_form_insecure = False

        elif tag == "title" and self._in_title:
            self._in_title = False
            self._has_title = True

        elif tag == "h1" and self._in_h1:
            heading = " ".join("".join(self._current_h1).split())
            self.h1_headings.append(heading)
            self._current_h1 = []
            self._in_h1 = False
