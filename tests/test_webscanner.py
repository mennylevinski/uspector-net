# Uspector – Copyright (c) 2026 Menahem Levinski

import socket
import unittest
from unittest.mock import MagicMock, patch

from uspector import WebScanner


class TestWebScanner(unittest.TestCase):

    def test_default_timeout(self):
        scanner = WebScanner()
        self.assertEqual(scanner.timeout, 15.0)

    def test_custom_timeout(self):
        scanner = WebScanner(timeout=10.0)
        self.assertEqual(scanner.timeout, 10.0)

    def test_rejects_zero_timeout(self):
        with self.assertRaises(ValueError):
            WebScanner(timeout=0)

    def test_rejects_negative_timeout(self):
        with self.assertRaises(ValueError):
            WebScanner(timeout=-1)

    def test_rejects_invalid_timeout(self):
        with self.assertRaises((TypeError, ValueError)):
            WebScanner(timeout="invalid")

    @staticmethod
    def _mock_response(url="https://example.com/", status_code=200, headers=None, body=b""):
        response = MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        response.url = url
        response.status_code = status_code
        response.headers = headers or {"Content-Type": "text/html; charset=utf-8"}
        response.encoding = "utf-8"
        response.raw.headers.getlist.return_value = []
        response.iter_content.return_value = [body] if body else []
        return response

    @patch("uspector.webscanner.requests.get")
    def test_successful_scan_returns_dictionary(self, mock_get):
        mock_get.return_value = self._mock_response(
            headers={
                "Content-Type": "text/html; charset=utf-8",
                "Strict-Transport-Security": "max-age=31536000",
                "X-Content-Type-Options": "nosniff",
            },
            body=b"<html><title>Example</title><body>Hello</body></html>",
        )

        scanner = WebScanner()
        result = scanner.scan("https://example.com")

        self.assertIsInstance(result, dict)
        self.assertIn("target", result)
        self.assertIn("findings", result)
        self.assertIn("error", result)
        self.assertIsNone(result["error"])
        self.assertEqual(result["target"], "https://example.com")

    @patch("uspector.webscanner.requests.get")
    def test_http_failure_is_reported(self, mock_get):
        mock_get.side_effect = OSError("Simulated connection failure")

        scanner = WebScanner()
        result = scanner.scan("https://example.com")

        self.assertIsInstance(result, dict)
        self.assertTrue(
            result.get("error") or result.get("findings") is not None,
            f"Unexpected result: {result}",
        )

    @patch("uspector.webscanner.requests.get")
    def test_request_uses_configured_timeout(self, mock_get):
        mock_get.return_value = self._mock_response(
            headers={"Content-Type": "text/html"},
            body=b"<html></html>",
        )

        scanner = WebScanner(timeout=7.0)
        scanner.scan("https://example.com")

        mock_get.assert_called_once()
        self.assertEqual(
            mock_get.call_args.kwargs.get("timeout"),
            7.0,
        )

    def test_rejects_port_zero_and_non_string_target(self):
        scanner = WebScanner()
        res_port0 = scanner.scan("http://example.com:0")
        self.assertTrue(res_port0.get("error"))

        res_none = scanner.scan(None)
        self.assertTrue(res_none.get("error"))

    @patch("uspector.webscanner.requests.get")
    def test_utf8_decoding_and_seo_parser_fixes(self, mock_get):
        html = (
            "<html><head>"
            "<meta charset='utf-8'>"
            "<title>Café Title</title>"
            "<meta name='description' content='First description'>"
            "<meta name='description' content='Duplicate description'>"
            "<link rel='canonical' href='https://example.com/first'>"
            "<link rel='canonical' href='https://example.com/second'>"
            "</head><body>"
            "<svg><title>Icon Title</title></svg>"
            "<img src='a.png' alt=''>"
            "<img src='b.png'>"
            "</body></html>"
        ).encode("utf-8")

        resp = self._mock_response(
            headers={"Content-Type": "text/html"},
            body=html,
        )
        # Simulate requests defaulting text/html without charset header to ISO-8859-1.
        resp.encoding = "ISO-8859-1"
        mock_get.return_value = resp

        result = WebScanner().scan("https://example.com")
        seo = result["seo"]
        self.assertEqual(seo["title_length"], len("Café Title"))
        self.assertEqual(seo["meta_description_length"], len("First description"))
        self.assertEqual(seo["canonical_url"], "https://example.com/first")
        self.assertEqual(seo["image_count"], 2)
        self.assertEqual(seo["images_missing_alt"], 1)

    @patch("uspector.webscanner.requests.get")
    def test_cookies_across_history_samesite_and_security_header_edge_cases(self, mock_get):
        redirect_resp = MagicMock()
        redirect_resp.raw.headers.getlist.return_value = [
            "redir=1; HttpOnly; SameSite=None"
        ]

        final_resp = self._mock_response(
            url="https://example.com/",
            headers={
                "Content-Type": "text/html",
                "Strict-Transport-Security": "max-age=0",
                "X-Content-Type-Options": "   ",
            },
            body=b"<html></html>",
        )
        final_resp.history = [redirect_resp]
        final_resp.raw.headers.getlist.return_value = [
            "sess=abc; Secure; HttpOnly; SameSite=None",
            "bad=xyz; SameSite=Bogus",
        ]
        mock_get.return_value = final_resp

        result = WebScanner().scan("https://example.com")
        cookies = {c["name"]: c for c in result["cookies"]}
        self.assertFalse(cookies["redir"]["samesite"])
        self.assertTrue(cookies["sess"]["samesite"])
        self.assertFalse(cookies["bad"]["samesite"])
        self.assertIn("Missing security header: X-Content-Type-Options", result["findings"])
        self.assertIn(
            "Insecure Strict-Transport-Security header: max-age is missing or zero",
            result["findings"],
        )

    @patch("uspector.webscanner.requests.get")
    def test_http_final_url_reports_unencrypted_finding(self, mock_get):
        mock_get.return_value = self._mock_response(
            url="http://example.com/",
            headers={"Content-Type": "text/plain"},
            body=b"ok",
        )

        result = WebScanner().scan("http://example.com")
        self.assertIn(
            "Target served over unencrypted HTTP (HSTS requires HTTPS)",
            result["findings"],
        )

    def test_allow_private_false_blocks_private_ip(self):
        scanner = WebScanner(allow_private=False)
        with patch(
            "uspector.webscanner.socket.getaddrinfo",
            return_value=[(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 80))],
        ):
            result = scanner.scan("http://example.com/")

        self.assertIn("private or restricted", result["error"].lower())

    @patch("uspector.webscanner.requests.get")
    def test_extended_header_cors_html_and_body_security_checks(self, mock_get):
        html = (
            "<html><head>"
            "<script src='https://cdn.example.net/app.js'></script>"
            "<script src='http://insecure.example.net/legacy.js'></script>"
            "</head><body>"
            "<!-- internal host 192.168.10.20 -->"
            "<img src='http://img.example.net/pic.png' alt='ok'>"
            "<a href='https://other.example.net' target='_blank'>Out</a>"
            "<form action='http://login.example.com/auth' method='post'>"
            "<input type='password' name='pw'>"
            "</form>"
            "<script>//# sourceMappingURL=app.js.map</script>"
            "</body></html>"
        ).encode("utf-8")

        resp = self._mock_response(
            url="https://example.com/",
            headers={
                "Content-Type": "text/html; charset=utf-8",
                "Server": "nginx/1.24.0",
                "X-Content-Type-Options": "invalid",
                "X-Frame-Options": "ALLOW-FROM https://evil.example",
                "Content-Security-Policy": "default-src 'self' 'unsafe-inline' *",
                "Referrer-Policy": "unsafe-url",
                "Permissions-Policy": "geolocation=()",
                "Strict-Transport-Security": "max-age=3600",
                "Cross-Origin-Opener-Policy": "same-origin",
                "X-Permitted-Cross-Domain-Policies": "all",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
                "Cache-Control": "public, max-age=60",
            },
            body=html,
        )
        resp.raw.headers.getlist.return_value = ["sid=1; Secure; HttpOnly; SameSite=Lax"]
        mock_get.return_value = resp

        result = WebScanner().scan("https://example.com")
        findings = result["findings"]
        self.assertIn("CSP allows 'unsafe-inline' scripts", findings)
        self.assertIn("CSP allows wildcard '*' script source", findings)
        self.assertIn("CSP missing 'frame-ancestors' directive", findings)
        self.assertIn("CSP missing 'object-src' directive", findings)
        self.assertIn("Invalid X-Content-Type-Options header (expected 'nosniff')", findings)
        self.assertIn("Weak or non-standard X-Frame-Options header", findings)
        self.assertIn("Weak Referrer-Policy value configured", findings)
        self.assertIn("HSTS max-age is below recommended 1 year (31536000 seconds)", findings)
        self.assertIn("HSTS header missing includeSubDomains directive", findings)
        self.assertEqual(result["security_headers"]["Cross-Origin-Opener-Policy"], "same-origin")
        self.assertIn("Permissive X-Permitted-Cross-Domain-Policies: all", findings)
        self.assertIn("Insecure CORS configuration: wildcard origin with credentials", findings)
        self.assertIn("Response sets cookies without Cache-Control: no-store or private", findings)
        self.assertIn("Server technology version disclosed in Server header", findings)
        self.assertTrue(any("Mixed active/form content" in f for f in findings))
        self.assertTrue(any("Mixed passive content" in f for f in findings))
        self.assertTrue(any("Subresource Integrity (SRI)" in f for f in findings))
        self.assertTrue(any("target='_blank'" in f for f in findings))
        self.assertIn("Password input served or submitted over unencrypted HTTP", findings)
        self.assertIn("sourcemappingurl=", result["body_indicators"])
        self.assertIn("internal-ip-comment", result["body_indicators"])

    @patch("uspector.webscanner.requests.get")
    def test_opt_in_metadata_endpoints(self, mock_get):
        main_resp = self._mock_response(url="https://example.com/", body=b"<html></html>")
        sec_resp = self._mock_response(
            url="https://example.com/.well-known/security.txt",
            headers={"Content-Type": "text/plain"},
            body=b"Contact: mailto:sec@example.com\nExpires: 2027-01-01T00:00:00Z\n",
        )
        rob_resp = self._mock_response(
            url="https://example.com/robots.txt",
            headers={"Content-Type": "text/plain"},
            body=b"User-agent: *\nDisallow: /admin-panel\n",
        )
        http_resp = self._mock_response(url="http://example.com/", body=b"ok")
        mock_get.side_effect = [main_resp, sec_resp, rob_resp, http_resp]

        result = WebScanner(check_metadata=True).scan("https://example.com")
        self.assertTrue(result["metadata"]["security_txt"]["present"])
        self.assertEqual(result["metadata"]["robots_txt"]["sensitive_disallows"], ["/admin-panel"])
        self.assertFalse(result["metadata"]["https_redirect"])
        self.assertIn("robots.txt references potentially sensitive disallowed paths", result["findings"])
        self.assertIn("HTTP endpoint does not redirect to HTTPS", result["findings"])


if __name__ == "__main__":
    unittest.main()
