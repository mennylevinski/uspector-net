# Uspector – Copyright (c) 2026 Menahem Levinski

import socket
import unittest
from unittest.mock import MagicMock, patch

import requests

from uspector import PHPScanner
from uspector._http import PinnedIPAdapter


class TestPHPScanner(unittest.TestCase):

    def test_timeout_validation(self):
        self.assertEqual(PHPScanner().timeout, 10.0)
        self.assertEqual(PHPScanner(timeout=5).timeout, 5.0)
        for bad in (0, -1, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                PHPScanner(timeout=bad)
        for bad_type in ("invalid", True, None):
            with self.assertRaises(TypeError):
                PHPScanner(timeout=bad_type)

    def test_normalize_url_validation(self):
        self.assertEqual(
            PHPScanner._normalize_url("example.com"),
            "https://example.com/",
        )
        for bad in ("", "ftp://example.com", "https://user:pass@example.com", "http://localhost", "http://example.com:0"):
            with self.assertRaises(ValueError):
                PHPScanner._normalize_url(bad)

    def test_validate_destination_blocks_private_ip_and_returns_pinned_ip(self):
        with patch(
            "uspector.phpscanner.socket.getaddrinfo",
            return_value=[(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 443))],
        ):
            with self.assertRaises(ValueError):
                PHPScanner._validate_destination("https://example.com/")

        with patch(
            "uspector.phpscanner.socket.getaddrinfo",
            return_value=[(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))],
        ):
            host, port, ip = PHPScanner._validate_destination("https://example.com/")
            self.assertEqual((host, port, ip), ("example.com", 443, "93.184.216.34"))

    @staticmethod
    def _mock_http_response(status_code=404, headers=None, body=b"", url="https://www.example.com/app/"):
        resp = MagicMock()
        resp.status_code = status_code
        resp.is_redirect = False
        resp.is_permanent_redirect = False
        resp.headers = headers or {}
        resp.encoding = "utf-8"
        resp.iter_content.return_value = [body] if body else []
        resp.url = url
        return resp

    def test_case_insensitive_headers_prose_ignored_and_test_php_filtered(self):
        scanner = PHPScanner()
        main_body = b"<html><body><p>Our guide covers PHP Version 8.2 features.</p></body></html>"
        soft_404 = b"<html><head><title>Not Found</title></head><body>Page missing</body></html>"

        session = MagicMock()
        session.__enter__.return_value = session
        session.__exit__.return_value = False

        def fake_get(url, **kwargs):
            if url == "https://example.com/":
                return self._mock_http_response(
                    status_code=200,
                    headers={
                        "x-powered-by": "PHP/8.3.1",
                        "server": "nginx",
                        "Content-Type": "text/html",
                    },
                    body=main_body,
                )
            if url.endswith("/test.php"):
                return self._mock_http_response(
                    status_code=200,
                    headers={"Content-Type": "text/html"},
                    body=soft_404,
                )
            return self._mock_http_response(status_code=404)

        session.get.side_effect = fake_get

        with (
            patch("uspector.phpscanner.requests.Session", return_value=session),
            patch(
                "uspector.phpscanner.socket.getaddrinfo",
                return_value=[(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))],
            ),
        ):
            result = scanner.scan("https://example.com/")

        self.assertTrue(result["php_detected"])
        self.assertEqual(result["php_version"], "8.3.1")
        self.assertEqual(result["detection_method"], "X-Powered-By")
        self.assertEqual(result["server_software"], "nginx")
        self.assertEqual(result["exposed_files"], [])
        self.assertEqual(result["verdict"], "LOW RISK")

    def test_prose_php_version_alone_not_reported(self):
        scanner = PHPScanner()
        session = MagicMock()
        session.__enter__.return_value = session
        session.__exit__.return_value = False
        session.get.side_effect = [
            self._mock_http_response(
                status_code=200,
                headers={"Content-Type": "text/html"},
                body=b"<html><body>Requires PHP Version 8.2 or newer.</body></html>",
            ),
            *[self._mock_http_response(status_code=404) for _ in scanner.EXPOSED_FILES],
        ]

        with (
            patch("uspector.phpscanner.requests.Session", return_value=session),
            patch(
                "uspector.phpscanner.socket.getaddrinfo",
                return_value=[(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))],
            ),
        ):
            result = scanner.scan("https://example.com/")

        self.assertFalse(result["php_detected"])
        self.assertIsNone(result["php_version"])
        self.assertEqual(result["verdict"], "NO ISSUES DETECTED")

    def test_phpinfo_probe_updates_version_without_duplicate_high_finding_and_follows_redirect_base(self):
        scanner = PHPScanner()
        session = MagicMock()
        session.__enter__.return_value = session
        session.__exit__.return_value = False

        redirect_resp = MagicMock()
        redirect_resp.status_code = 301
        redirect_resp.is_redirect = True
        redirect_resp.is_permanent_redirect = True
        redirect_resp.headers = {"Location": "https://www.example.com/sub/"}

        phpinfo_html = (
            b"<title>phpinfo()</title><h1 class=\"p\">PHP Version 8.2.15</h1>"
        )

        probed_urls = []

        def fake_get(url, **kwargs):
            probed_urls.append(url)
            if url == "https://example.com/":
                return redirect_resp
            if url == "https://www.example.com/sub/":
                return self._mock_http_response(
                    status_code=200,
                    headers={"Content-Type": "text/html"},
                    body=b"<html><body>Hello</body></html>",
                )
            if url == "https://www.example.com/sub/phpinfo.php":
                return self._mock_http_response(
                    status_code=200,
                    headers={"Content-Type": "text/html"},
                    body=phpinfo_html,
                )
            return self._mock_http_response(status_code=404)

        session.get.side_effect = fake_get

        with (
            patch("uspector.phpscanner.requests.Session", return_value=session),
            patch(
                "uspector.phpscanner.socket.getaddrinfo",
                return_value=[(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))],
            ),
        ):
            result = scanner.scan("https://example.com/")

        self.assertTrue(result["phpinfo_exposure"])
        self.assertTrue(result["php_detected"])
        self.assertEqual(result["php_version"], "8.2.15")
        self.assertIn("https://www.example.com/sub/.env", probed_urls)
        high_findings = [f for f in result["findings"] if f["severity"] == "HIGH"]
        self.assertEqual(len(high_findings), 1)
        self.assertEqual(high_findings[0]["title"], "Exposed File: phpinfo.php")

    def test_session_closed_when_main_request_fails(self):
        scanner = PHPScanner()
        session = MagicMock()
        session.__enter__.return_value = session
        session.__exit__.return_value = False
        session.get.side_effect = OSError("Network down")

        with (
            patch("uspector.phpscanner.requests.Session", return_value=session),
            patch(
                "uspector.phpscanner.socket.getaddrinfo",
                return_value=[(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))],
            ),
        ):
            result = scanner.scan("https://example.com/")

        self.assertEqual(result["verdict"], "SCAN FAILED")
        session.__exit__.assert_called_once()

    def test_pinned_ip_adapter_pins_host_and_preserves_tls_sni_and_host_header(self):
        pinned_ips = {("example.com", 443): "93.184.216.34"}
        adapter = PinnedIPAdapter(pinned_ips)
        prepared = requests.Request("GET", "https://example.com/path").prepare()

        adapter.poolmanager = MagicMock()
        adapter.get_connection_with_tls_context(prepared, verify=True)

        adapter.poolmanager.connection_from_host.assert_called_once()
        call_kwargs = adapter.poolmanager.connection_from_host.call_args.kwargs
        self.assertEqual(call_kwargs["host"], "93.184.216.34")
        self.assertIsNone(call_kwargs["port"])
        self.assertEqual(call_kwargs["pool_kwargs"]["server_hostname"], "example.com")
        self.assertEqual(call_kwargs["pool_kwargs"]["assert_hostname"], "example.com")

        with patch.object(requests.adapters.HTTPAdapter, "send", return_value=MagicMock()) as mock_send:
            adapter.send(prepared)
            sent_request = mock_send.call_args.args[0]
            self.assertEqual(sent_request.headers["Host"], "example.com")

    def test_eol_php_session_cookie_framework_errors_ini_and_composer_checks(self):
        scanner = PHPScanner()
        session = MagicMock()
        session.__enter__.return_value = session
        session.__exit__.return_value = False

        main_resp = self._mock_http_response(
            status_code=200,
            headers={
                "X-Powered-By": "PHP/7.4.33",
                "Content-Type": "text/html",
                "Set-Cookie": "laravel_session=xyz; Path=/",
            },
            body=b"<html><body>SQLSTATE[42000]: Syntax error in PDOException</body></html>",
        )
        main_resp.raw.headers.getlist.return_value = ["laravel_session=xyz; Path=/"]

        user_ini_resp = self._mock_http_response(
            status_code=200,
            headers={"Content-Type": "text/plain"},
            body=b"allow_url_include = On\ndisplay_errors = On\n",
        )
        composer_resp = self._mock_http_response(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=b'{"name": "app/site", "require": {"php": "^7.4"}, "require-dev": {"phpunit/phpunit": "^9.0"}}',
        )

        def fake_get(url, **kwargs):
            if url == "https://example.com/":
                return main_resp
            if url.endswith("/.user.ini"):
                return user_ini_resp
            if url.endswith("/composer.json"):
                return composer_resp
            return self._mock_http_response(status_code=404)

        session.get.side_effect = fake_get

        with (
            patch("uspector.phpscanner.requests.Session", return_value=session),
            patch(
                "uspector.phpscanner.socket.getaddrinfo",
                return_value=[(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))],
            ),
        ):
            result = scanner.scan("https://example.com/")

        titles = [f["title"] for f in result["findings"]]
        self.assertEqual(result["framework"], "Laravel")
        self.assertTrue(result["php_error_disclosure"])
        self.assertIn("End-of-Life PHP Version: 7.4.33", titles)
        self.assertIn("Insecure PHP Session Cookie: laravel_session", titles)
        self.assertIn("Dangerous PHP Setting in .user.ini: allow_url_include", titles)
        self.assertIn("Verbose Errors Enabled in .user.ini: display_errors", titles)
        self.assertIn("Composer Development Dependencies Exposed", titles)
        self.assertEqual(result["verdict"], "HIGH RISK")


if __name__ == "__main__":
    unittest.main()
