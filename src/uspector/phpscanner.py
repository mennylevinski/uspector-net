
# Uspector - Copyright (c) 2026 Menahem Levinski

import json
import re
import socket
from urllib.parse import urljoin, urlparse, urlunparse

import requests
from requests.structures import CaseInsensitiveDict

from ._http import (
    PinnedIPAdapter,
    extract_set_cookie_headers,
    parse_cookie_attributes,
    validate_public_http_url,
    validate_timeout,
)


class PHPScanner:

    USER_AGENT = "Uspector/1.0 PHP Security Scanner"

    TIMEOUT = 10
    MAX_RESPONSE_SIZE = 1024 * 1024
    MAX_REDIRECTS = 5

    PHP_ERROR_PATTERNS = [
        r"Fatal error:",
        r"Parse error:",
        r"Catchable fatal error:",
        r"Warning:\s+.*\bin\s+.*\bon line\b",
        r"Notice:\s+.*\bin\s+.*\bon line\b",
        r"Deprecated:\s+.*\bin\s+.*\bon line\b",
        r"Strict Standards:\s+.*\bin\s+.*\bon line\b",
        r"Uncaught\s+\w+(?:Error|Exception)",
        r"\bPDOException\b",
        r"\bSQLSTATE\[[0-9A-Z]+\]",
        r"\bmysqli_sql_exception\b",
        r"open_basedir restriction in effect",
        r"Call to undefined function",
        r"Whoops! There was an error",
        r"Symfony\\Component\\ErrorHandler",
        r"Stack trace:",
    ]

    # Minimum supported PHP branch as of 2026-11 (8.1 security support ended Dec 2025).
    MIN_SUPPORTED_PHP_BRANCH = (8, 2)

    PHP_SESSION_COOKIES = (
        "phpsessid",
        "laravel_session",
        "cakephp",
        "symfony",
    )

    PHPINFO_PATTERNS = [
        r"<title>phpinfo\(\)</title>",
        r"<h1 class=\"p\">PHP Version",
        r"PHP License",
        r"Configuration File \(php\.ini\) Path",
    ]

    EXPOSED_FILES = {
        ".env": "HIGH",
        ".env.backup": "HIGH",
        ".env.bak": "HIGH",
        "config.php.bak": "HIGH",
        "config.php~": "HIGH",
        "config.php.old": "HIGH",
        "index.php.bak": "MEDIUM",
        "index.php~": "MEDIUM",
        "composer.json": "LOW",
        "composer.lock": "LOW",
        "php.ini": "MEDIUM",
        ".user.ini": "MEDIUM",
        "phpinfo.php": "HIGH",
        "info.php": "HIGH",
        "test.php": "MEDIUM",
    }

    def __init__(self, timeout=10):
        self.timeout = validate_timeout(timeout)

    # --------------------------------------------------
    # Target validation
    # --------------------------------------------------

    @staticmethod
    def _normalize_url(target):

        if not isinstance(target, str):
            raise ValueError("Target must be a non-empty string.")

        target = target.strip()

        if not target:
            raise ValueError("Target cannot be empty.")

        if "://" not in target:
            target = "https://" + target

        parsed = urlparse(target)

        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError("Only HTTP and HTTPS targets are supported.")

        if not parsed.hostname:
            raise ValueError("Invalid target hostname.")

        if parsed.username or parsed.password:
            raise ValueError("URLs containing credentials are not supported.")

        if parsed.port is not None and not (1 <= parsed.port <= 65535):
            raise ValueError("Invalid target port.")

        if parsed.hostname.lower() == "localhost":
            raise ValueError("Localhost targets are not allowed.")

        return urlunparse((
            parsed.scheme.lower(),
            parsed.netloc,
            parsed.path or "/",
            "",
            parsed.query,
            "",
        ))

    @staticmethod
    def _validate_destination(url, return_all=False):
        return validate_public_http_url(
            url,
            error_prefix="Target",
            resolver=socket.getaddrinfo,
            return_all=return_all,
        )

    # --------------------------------------------------
    # HTTP request handling
    # --------------------------------------------------

    def _request(self, session, url, pinned_ips=None):

        current_url = url

        for _ in range(self.MAX_REDIRECTS + 1):

            try:
                validated = self._validate_destination(
                    current_url,
                    return_all=True,
                )
            except TypeError:
                validated = self._validate_destination(current_url)
            if (
                pinned_ips is not None
                and isinstance(validated, tuple)
                and len(validated) == 3
            ):
                dest_host, dest_port, dest_ip = validated
                pinned_ips[(dest_host, dest_port)] = dest_ip

            response = session.get(
                current_url,
                timeout=self.timeout,
                allow_redirects=False,
                stream=True,
                verify=True,
            )

            if response.is_redirect or response.is_permanent_redirect:

                location = response.headers.get("Location")
                response.close()

                if not location:
                    raise ValueError("Redirect without a Location header.")

                current_url = urljoin(current_url, location)
                continue

            content = bytearray()

            try:
                for chunk in response.iter_content(chunk_size=8192):

                    if not chunk:
                        continue

                    remaining = self.MAX_RESPONSE_SIZE - len(content)

                    if remaining <= 0:
                        break

                    content.extend(chunk[:remaining])

                    if len(content) >= self.MAX_RESPONSE_SIZE:
                        break

                content_type = response.headers.get("Content-Type", "")
                encoding = response.encoding
                if (
                    not encoding
                    or (
                        isinstance(encoding, str)
                        and encoding.lower() in ("iso-8859-1", "latin-1", "latin1")
                        and "charset=" not in content_type.lower()
                    )
                ):
                    encoding = "utf-8"

                body = content.decode(
                    encoding,
                    errors="replace",
                )

                return {
                    "url": current_url,
                    "status_code": response.status_code,
                    "headers": CaseInsensitiveDict(response.headers),
                    "set_cookie_headers": extract_set_cookie_headers(response),
                    "body": body,
                    "content_type": content_type,
                }

            finally:
                response.close()

        raise ValueError("Maximum redirect limit exceeded.")

    # --------------------------------------------------
    # Detection helpers
    # --------------------------------------------------

    @staticmethod
    def _detect_php_version(headers, body):

        powered_by = headers.get("X-Powered-By", "")

        match = re.search(
            r"PHP/([0-9]+(?:\.[0-9]+){1,3})",
            powered_by,
            re.IGNORECASE,
        )

        if match:
            return match.group(1), "X-Powered-By"

        if (
            PHPScanner._is_phpinfo(body)
            or PHPScanner._is_php_error(body)
            or re.search(r'<h1[^>]*class=["\']p["\'][^>]*>\s*PHP Version\s+[0-9]', body, re.IGNORECASE)
        ):
            match = re.search(
                r"PHP Version ([0-9]+(?:\.[0-9]+){1,3})",
                body,
                re.IGNORECASE,
            )

            if match:
                return match.group(1), "Response Body"

        return None, None

    @staticmethod
    def _contains_pattern(body, patterns):

        for pattern in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                return True

        return False

    @staticmethod
    def _is_phpinfo(body):

        return PHPScanner._contains_pattern(
            body,
            PHPScanner.PHPINFO_PATTERNS,
        )

    @staticmethod
    def _is_php_error(body):

        return PHPScanner._contains_pattern(
            body,
            PHPScanner.PHP_ERROR_PATTERNS,
        )

    @staticmethod
    def _is_directory_listing(body):

        patterns = [
            r"<title>Index of /",
            r"<h1>Index of /",
            r"Directory listing for /",
        ]

        return PHPScanner._contains_pattern(body, patterns)

    @staticmethod
    def _is_html_or_asset_response(content_type, body):
        media_type = content_type.split(";", 1)[0].strip().lower()
        if media_type in (
            "text/html",
            "application/xhtml+xml",
            "text/css",
            "application/javascript",
            "text/javascript",
        ):
            return True

        stripped = body.lstrip()[:64].lower()
        return stripped.startswith(("<!doctype html", "<html"))

    @classmethod
    def _matches_exposed_file(cls, filename, response_body, content_type):
        if filename in ("phpinfo.php", "info.php"):
            return cls._is_phpinfo(response_body)

        if filename == "test.php":
            if cls._is_phpinfo(response_body) or cls._is_php_error(response_body):
                return True
            if cls._is_html_or_asset_response(content_type, response_body):
                return False
            return "<?php" in response_body or bool(
                re.search(
                    r"\b(?:phpinfo|var_dump|print_r|xdebug|display_errors)\b",
                    response_body,
                    re.IGNORECASE,
                )
            )

        if cls._is_html_or_asset_response(content_type, response_body):
            return False

        if filename.startswith(".env"):
            return bool(re.search(r"(?m)^\s*[A-Z_][A-Z0-9_]*\s*=", response_body))

        if filename == "composer.json":
            try:
                data = json.loads(response_body)
            except (ValueError, TypeError):
                return False
            return isinstance(data, dict) and any(
                key in data
                for key in ("name", "require", "require-dev", "autoload", "scripts")
            )

        if filename == "composer.lock":
            try:
                data = json.loads(response_body)
            except (ValueError, TypeError):
                return False
            return isinstance(data, dict) and "packages" in data

        if filename.endswith((".bak", ".old", "~")):
            return "<?php" in response_body or bool(
                re.search(
                    r"(?m)^\s*\$?\w*(?:DB_PASSWORD|DB_USERNAME|db_pass|password)\s*[=:]",
                    response_body,
                    re.IGNORECASE,
                )
            )

        if filename in ("php.ini", ".user.ini"):
            return bool(
                re.search(
                    r"(?m)^\s*(?:display_errors|expose_php|memory_limit|"
                    r"allow_url_include|open_basedir|auto_prepend_file|"
                    r"session\.cookie_httponly)\s*=",
                    response_body,
                    re.IGNORECASE,
                )
            )

        return True

    @classmethod
    def _is_eol_php_version(cls, version_str):
        try:
            parts = [int(p) for p in version_str.split(".")[:2]]
            if len(parts) < 2:
                return False
            return tuple(parts) < cls.MIN_SUPPORTED_PHP_BRANCH
        except (ValueError, AttributeError):
            return False

    @staticmethod
    def _detect_framework(headers, body, cookie_names):
        lowered_cookies = {name.lower() for name in cookie_names}
        if "laravel_session" in lowered_cookies:
            return "Laravel"
        if "cakephp" in lowered_cookies:
            return "CakePHP"
        if "symfony" in lowered_cookies:
            return "Symfony"
        if any(name.startswith("wordpress_logged_in_") for name in lowered_cookies):
            return "WordPress"

        if headers.get("X-Drupal-Cache") or headers.get("X-Drupal-Dynamic-Cache"):
            return "Drupal"
        if "wordpress" in (headers.get("X-Redirect-By") or "").lower():
            return "WordPress"

        gen_match = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            body[:8192],
            re.IGNORECASE,
        )
        if gen_match:
            gen_val = gen_match.group(1)
            for fw in ("WordPress", "Drupal", "Joomla", "Magento", "TYPO3"):
                if fw.lower() in gen_val.lower():
                    return fw

        return None

    @staticmethod
    def _inspect_ini_findings(filename, response_body, findings):
        directives = {}
        for line in response_body.splitlines():
            stripped = line.split(";", 1)[0].strip()
            if "=" not in stripped:
                continue
            k, v = stripped.split("=", 1)
            directives[k.strip().lower()] = v.strip().strip("\"'").lower()

        if directives.get("allow_url_include") in ("1", "on", "true", "yes"):
            PHPScanner._add_finding(
                findings,
                "HIGH",
                f"Dangerous PHP Setting in {filename}: allow_url_include",
                f"{filename} enables allow_url_include, increasing remote file inclusion risk.",
                "Set allow_url_include = Off and restrict public access to INI files.",
            )

        if directives.get("display_errors") in ("1", "on", "true", "yes"):
            PHPScanner._add_finding(
                findings,
                "MEDIUM",
                f"Verbose Errors Enabled in {filename}: display_errors",
                f"{filename} configures display_errors = On.",
                "Set display_errors = Off in production and log errors server-side.",
            )

        if directives.get("session.cookie_httponly") in ("0", "off", "false", "no"):
            PHPScanner._add_finding(
                findings,
                "MEDIUM",
                f"Insecure Session Setting in {filename}: session.cookie_httponly",
                f"{filename} disables HttpOnly on PHP session cookies.",
                "Enable session.cookie_httponly = 1.",
            )

    @staticmethod
    def _inspect_composer_findings(response_body, findings):
        try:
            data = json.loads(response_body)
        except (ValueError, TypeError):
            return

        if not isinstance(data, dict):
            return

        require_dev = data.get("require-dev")
        if isinstance(require_dev, dict) and require_dev:
            PHPScanner._add_finding(
                findings,
                "LOW",
                "Composer Development Dependencies Exposed",
                f"composer.json lists {len(require_dev)} require-dev package(s).",
                "Block public access to composer.json and avoid deploying dev metadata.",
            )

    # --------------------------------------------------
    # Findings
    # --------------------------------------------------

    @staticmethod
    def _add_finding(findings, severity, title, description, recommendation):

        findings.append({
            "severity": severity,
            "title": title,
            "description": description,
            "recommendation": recommendation,
        })

    # --------------------------------------------------
    # Main scan
    # --------------------------------------------------

    def scan(self, target):

        result = {
            "target": target,
            "php_detected": False,
            "php_version": None,
            "detection_method": None,
            "framework": None,
            "server_software": None,
            "version_disclosure": False,
            "phpinfo_exposure": False,
            "php_error_disclosure": False,
            "directory_listing": False,
            "exposed_files": [],
            "findings": [],
            "verdict": "INCONCLUSIVE",
        }

        try:

            base_url = self._normalize_url(target)
            pinned_ips = {}

            with requests.Session() as session:
                session.trust_env = False
                adapter = PinnedIPAdapter(pinned_ips)
                session.mount("http://", adapter)
                session.mount("https://", adapter)
                session.headers.update({
                    "User-Agent": self.USER_AGENT,
                    "Accept": "text/html,application/json,*/*",
                })

                # Main page
                main_response = self._request(session, base_url, pinned_ips)

                headers = main_response["headers"]
                body = main_response["body"]
                set_cookie_headers = main_response.get("set_cookie_headers") or []

                parsed_cookies = []
                for cookie_hdr in set_cookie_headers:
                    parsed_cookie = parse_cookie_attributes(cookie_hdr)
                    if parsed_cookie:
                        parsed_cookies.append(parsed_cookie)
                cookie_names = [c["name"] for c in parsed_cookies]

                powered_by = headers.get("X-Powered-By", "")
                server = headers.get("Server", "")

                result["server_software"] = server or None
                framework = self._detect_framework(headers, body, cookie_names)
                if framework:
                    result["framework"] = framework

                php_version, version_method = self._detect_php_version(
                    headers,
                    body,
                )

                if php_version:
                    result["php_detected"] = True
                    result["php_version"] = php_version
                    result["detection_method"] = version_method
                    result["version_disclosure"] = True

                elif "php" in powered_by.lower():
                    result["php_detected"] = True
                    result["detection_method"] = "X-Powered-By"

                elif any(
                    name.lower() in self.PHP_SESSION_COOKIES
                    for name in cookie_names
                ) or "PHPSESSID" in headers.get("Set-Cookie", ""):
                    result["php_detected"] = True
                    result["detection_method"] = (
                        "PHP Session Cookie"
                        if any(n.lower() == "phpsessid" for n in cookie_names)
                        or "PHPSESSID" in headers.get("Set-Cookie", "")
                        else "PHP Framework Session Cookie"
                    )
                elif framework:
                    result["php_detected"] = True
                    result["detection_method"] = f"Framework Signature ({framework})"

                if result["version_disclosure"]:
                    self._add_finding(
                        result["findings"],
                        "LOW",
                        "PHP Version Disclosure",
                        f"The server disclosed PHP version {php_version}.",
                        "Remove PHP version information from HTTP response headers.",
                    )
                    if self._is_eol_php_version(php_version):
                        self._add_finding(
                            result["findings"],
                            "MEDIUM",
                            f"End-of-Life PHP Version: {php_version}",
                            f"PHP {php_version} belongs to an end-of-life branch without security updates.",
                            "Upgrade to an actively supported PHP release branch.",
                        )

                for cookie in parsed_cookies:
                    if cookie["name"].lower() in self.PHP_SESSION_COOKIES:
                        missing_flags = [
                            flag
                            for flag, ok in (
                                ("Secure", cookie["secure"]),
                                ("HttpOnly", cookie["httponly"]),
                                ("SameSite", cookie["samesite"]),
                            )
                            if not ok
                        ]
                        if missing_flags:
                            self._add_finding(
                                result["findings"],
                                "MEDIUM",
                                f"Insecure PHP Session Cookie: {cookie['name']}",
                                (
                                    f"Session cookie {cookie['name']!r} is missing "
                                    f"recommended attributes: {', '.join(missing_flags)}."
                                ),
                                "Set Secure, HttpOnly, and SameSite attributes on PHP session cookies.",
                            )

                main_phpinfo = self._is_phpinfo(body)
                if main_phpinfo:
                    result["php_detected"] = True
                    result["phpinfo_exposure"] = True
                    if not result["detection_method"]:
                        result["detection_method"] = "phpinfo()"
                    self._add_finding(
                        result["findings"],
                        "HIGH",
                        "PHP Information Exposure",
                        "A publicly accessible phpinfo() page was detected.",
                        "Remove the exposed page or restrict access to authorized administrators.",
                    )

                # Error disclosure
                if self._is_php_error(body):
                    result["php_error_disclosure"] = True
                    if not result["php_detected"]:
                        result["php_detected"] = True
                        result["detection_method"] = "PHP Error Message"

                    self._add_finding(
                        result["findings"],
                        "MEDIUM",
                        "PHP Error Disclosure",
                        "The response appears to contain PHP error information.",
                        "Disable public error display and configure server-side error logging.",
                    )

                # Directory listing
                if self._is_directory_listing(body):
                    result["directory_listing"] = True

                    self._add_finding(
                        result["findings"],
                        "MEDIUM",
                        "Directory Listing Enabled",
                        "The server appears to expose a directory index.",
                        "Disable directory listing in the web server configuration.",
                    )

                # PHP-related exposure checks against the final post-redirect location
                final_parsed = urlparse(main_response.get("url") or base_url)
                base_path = final_parsed.path or "/"
                if not base_path.endswith("/"):
                    base_path = base_path.rsplit("/", 1)[0] + "/"
                probe_base = f"{final_parsed.scheme}://{final_parsed.netloc}{base_path}"

                for filename, severity in self.EXPOSED_FILES.items():

                    probe_url = urljoin(probe_base, filename)

                    try:
                        response = self._request(session, probe_url, pinned_ips)

                        if response["status_code"] != 200:
                            continue

                        response_body = response["body"]
                        content_type = response["content_type"].lower()

                        if not response_body.strip():
                            continue

                        if not self._matches_exposed_file(
                            filename,
                            response_body,
                            content_type,
                        ):
                            continue

                        if filename in ("phpinfo.php", "info.php"):
                            result["phpinfo_exposure"] = True
                            result["php_detected"] = True
                            if not result["detection_method"]:
                                result["detection_method"] = f"Exposed {filename}"

                            probe_version, probe_method = self._detect_php_version(
                                response["headers"],
                                response_body,
                            )
                            if probe_version and not result["php_version"]:
                                result["php_version"] = probe_version
                                result["detection_method"] = probe_method
                                result["version_disclosure"] = True
                                self._add_finding(
                                    result["findings"],
                                    "LOW",
                                    "PHP Version Disclosure",
                                    f"The server disclosed PHP version {probe_version}.",
                                    "Remove PHP version information from HTTP response headers.",
                                )
                                if self._is_eol_php_version(probe_version):
                                    self._add_finding(
                                        result["findings"],
                                        "MEDIUM",
                                        f"End-of-Life PHP Version: {probe_version}",
                                        f"PHP {probe_version} belongs to an end-of-life branch without security updates.",
                                        "Upgrade to an actively supported PHP release branch.",
                                    )

                        result["exposed_files"].append({
                            "file": filename,
                            "status_code": response["status_code"],
                            "severity": severity,
                        })

                        self._add_finding(
                            result["findings"],
                            severity,
                            f"Exposed File: {filename}",
                            f"The file {filename} appears to be publicly accessible.",
                            "Restrict access to sensitive files and remove unnecessary public backups.",
                        )

                        if filename in ("php.ini", ".user.ini"):
                            self._inspect_ini_findings(
                                filename,
                                response_body,
                                result["findings"],
                            )
                        elif filename == "composer.json":
                            self._inspect_composer_findings(
                                response_body,
                                result["findings"],
                            )

                    except (requests.RequestException, ValueError):
                        continue

            # Verdict
            severities = {
                finding["severity"]
                for finding in result["findings"]
            }

            if "HIGH" in severities:
                result["verdict"] = "HIGH RISK"

            elif "MEDIUM" in severities:
                result["verdict"] = "WARNING"

            elif "LOW" in severities:
                result["verdict"] = "LOW RISK"

            elif result["php_detected"]:
                result["verdict"] = "INFORMATIONAL"

            else:
                result["verdict"] = "NO ISSUES DETECTED"

        except (requests.RequestException, ValueError, OSError) as exc:

            result["error"] = str(exc)
            result["verdict"] = "SCAN FAILED"

        except Exception as exc:

            result["error"] = f"Unexpected scan error: {exc}"
            result["verdict"] = "SCAN FAILED"

        return result

    # --------------------------------------------------
    # Formatted output
    # --------------------------------------------------

    @staticmethod
    def format_scan(result):

        lines = []

        target = result.get("target", "Unknown")

        lines.append(f"Uspector PHP Security Scan: {target}")
        lines.append("=" * 50)

        lines.append("")
        lines.append("PHP Detection")

        lines.append(
            f"  PHP Detected: "
            f"{'Yes' if result.get('php_detected') else 'Not Confirmed'}"
        )

        lines.append(
            f"  PHP Version: {result.get('php_version') or 'Not Disclosed'}"
        )

        lines.append(
            f"  Detection Method: "
            f"{result.get('detection_method') or 'Not Detected'}"
        )

        lines.append(
            f"  Server Software: "
            f"{result.get('server_software') or 'Not Disclosed'}"
        )

        lines.append("")
        lines.append("Information Disclosure")

        lines.append(
            f"  PHP Version Disclosure: "
            f"{'Detected' if result.get('version_disclosure') else 'Not Detected'}"
        )

        lines.append(
            f"  PHP Error Disclosure: "
            f"{'Detected' if result.get('php_error_disclosure') else 'Not Detected'}"
        )

        lines.append(
            f"  phpinfo Exposure: "
            f"{'Detected' if result.get('phpinfo_exposure') else 'Not Detected'}"
        )

        lines.append("")
        lines.append("Exposed Files")

        exposed = result.get("exposed_files", [])

        if exposed:
            for item in exposed:
                lines.append(
                    f"  [{item['severity']}] {item['file']} "
                    f"(HTTP {item['status_code']})"
                )
        else:
            lines.append("  No exposed files detected.")

        lines.append("")
        lines.append("Directory Exposure")

        lines.append(
            f"  Directory Listing: "
            f"{'Detected' if result.get('directory_listing') else 'Not Detected'}"
        )

        lines.append("")
        lines.append("Findings")

        findings = result.get("findings", [])

        if findings:
            for finding in findings:
                lines.append(
                    f"  [{finding['severity']}] {finding['title']}"
                )
                lines.append(
                    f"      {finding['description']}"
                )
                lines.append(
                    f"      Recommendation: {finding['recommendation']}"
                )
        else:
            lines.append("  No findings reported.")

        if result.get("error"):
            lines.append("")
            lines.append(f"Error: {result['error']}")

        lines.append("")
        lines.append(f"Verdict: {result.get('verdict', 'UNKNOWN')}")

        return "\n".join(lines)
