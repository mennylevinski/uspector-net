
# Uspector - Copyright (c) 2026 Menahem Levinski

import ipaddress
import re
import socket
from urllib.parse import urljoin, urlparse, urlunparse

import requests


class PHPScanner:

    USER_AGENT = "Uspector/1.0 PHP Security Scanner"

    TIMEOUT = 10
    MAX_RESPONSE_SIZE = 1024 * 1024
    MAX_REDIRECTS = 5

    PHP_ERROR_PATTERNS = [
        r"Fatal error:",
        r"Parse error:",
        r"Warning:\s+.*\bin\s+.*\bon line\b",
        r"Notice:\s+.*\bin\s+.*\bon line\b",
        r"Uncaught\s+\w+(?:Error|Exception)",
        r"Stack trace:",
    ]

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
        "phpinfo.php": "HIGH",
        "info.php": "HIGH",
        "test.php": "MEDIUM",
    }

    def __init__(self, timeout=10):
        self.timeout = timeout

    # --------------------------------------------------
    # Target validation
    # --------------------------------------------------

    @staticmethod
    def _normalize_url(target):

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

        if parsed.port and not (1 <= parsed.port <= 65535):
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
    def _validate_destination(url):

        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            raise ValueError("Invalid redirect destination.")

        if parsed.scheme not in ("http", "https"):
            raise ValueError("Unsupported redirect protocol.")

        if parsed.username or parsed.password:
            raise ValueError("Redirect credentials are not allowed.")

        try:
            addresses = socket.getaddrinfo(
                hostname,
                parsed.port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror:
            raise ValueError("Unable to resolve target hostname.")

        if not addresses:
            raise ValueError("Target hostname did not resolve.")

        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])

            if not ip.is_global:
                raise ValueError(
                    "Target resolves to a private or restricted IP address."
                )

    # --------------------------------------------------
    # HTTP request handling
    # --------------------------------------------------

    def _request(self, session, url):

        current_url = url

        for _ in range(self.MAX_REDIRECTS + 1):

            self._validate_destination(current_url)

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

                body = content.decode(
                    response.encoding or "utf-8",
                    errors="replace",
                )

                return {
                    "url": current_url,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": body,
                    "content_type": response.headers.get(
                        "Content-Type", ""
                    ),
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

            session = requests.Session()
            session.trust_env = False
            session.headers.update({
                "User-Agent": self.USER_AGENT,
                "Accept": "text/html,application/json,*/*",
            })

            # Main page
            main_response = self._request(session, base_url)

            headers = main_response["headers"]
            body = main_response["body"]

            powered_by = headers.get("X-Powered-By", "")
            server = headers.get("Server", "")

            result["server_software"] = server or None

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

            elif "PHPSESSID" in headers.get("Set-Cookie", ""):
                result["php_detected"] = True
                result["detection_method"] = "PHP Session Cookie"

            if result["version_disclosure"]:

                self._add_finding(
                    result["findings"],
                    "LOW",
                    "PHP Version Disclosure",
                    f"The server disclosed PHP version {php_version}.",
                    "Remove PHP version information from HTTP response headers.",
                )

            # Error disclosure
            if self._is_php_error(body):

                result["php_error_disclosure"] = True

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

            # PHP-related exposure checks
            parsed = urlparse(base_url)
            origin = f"{parsed.scheme}://{parsed.netloc}/"

            for filename, severity in self.EXPOSED_FILES.items():

                probe_url = urljoin(origin, filename)

                try:
                    response = self._request(session, probe_url)

                    if response["status_code"] != 200:
                        continue

                    response_body = response["body"]
                    content_type = response["content_type"].lower()

                    if not response_body.strip():
                        continue

                    if filename in ("phpinfo.php", "info.php"):
                        if not self._is_phpinfo(response_body):
                            continue

                        result["phpinfo_exposure"] = True

                    elif filename.startswith(".env"):
                        # Avoid reporting a generic HTML fallback as an exposed file.
                        if not re.search(
                            r"(?m)^\s*[A-Z_][A-Z0-9_]*\s*=",
                            response_body,
                        ):
                            continue

                    elif filename == "composer.json":
                        if not re.search(
                            r'"(?:name|require|autoload|scripts)"\s*:',
                            response_body,
                        ):
                            continue

                    elif filename == "composer.lock":
                        if '"packages"' not in response_body:
                            continue

                    elif filename.endswith((".bak", ".old", "~")):
                        # Require recognizable PHP source/configuration content.
                        if "<?php" not in response_body and not re.search(
                            r"(?:DB_PASSWORD|DB_USERNAME|database|password)\s*=",
                            response_body,
                            re.IGNORECASE,
                        ):
                            continue

                    elif filename == "php.ini":
                        if not re.search(
                            r"(?m)^\s*(?:display_errors|expose_php|memory_limit)\s*=",
                            response_body,
                        ):
                            continue

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

                except (requests.RequestException, ValueError):
                    continue

            if result["phpinfo_exposure"]:

                self._add_finding(
                    result["findings"],
                    "HIGH",
                    "PHP Information Exposure",
                    "A publicly accessible phpinfo() page was detected.",
                    "Remove the exposed page or restrict access to authorized administrators.",
                )

            session.close()

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
