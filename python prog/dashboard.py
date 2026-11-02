"""Serve the local dashboard for the passive security-header scanner."""

from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import URLError

import scanner

HOST = "127.0.0.1"
PORT = 8765
MAX_BODY_BYTES = 4096
DASHBOARD_FILE = Path(__file__).with_name("dashboard.html")


def _checks(url: str, headers) -> list[dict[str, str]]:
    normalized = {name.lower(): value.strip() for name, value in headers.items()}
    csp = normalized.get("content-security-policy", "").lower()
    frame_protected = "x-frame-options" in normalized or "frame-ancestors" in csp
    secure_transport = url.startswith("https://")
    header_specs = [
        ("Strict-Transport-Security", "strict-transport-security", secure_transport),
        ("Content-Security-Policy", "content-security-policy", True),
        ("X-Content-Type-Options", "x-content-type-options", True),
        ("Clickjacking protection", "x-frame-options", True),
        ("Referrer-Policy", "referrer-policy", True),
        ("Permissions-Policy", "permissions-policy", True),
    ]
    results: list[dict[str, str]] = []
    for label, key, relevant in header_specs:
        value = normalized.get(key, "")
        if label == "Strict-Transport-Security" and not secure_transport:
            status = "n/a"
            value = "Not applicable over HTTP"
        elif label == "Clickjacking protection":
            status = "pass" if frame_protected else "missing"
            value = normalized.get("x-frame-options") or ("CSP frame-ancestors" if frame_protected else "Not detected")
        elif label == "X-Content-Type-Options":
            status = "pass" if value.lower() == "nosniff" else "missing"
            value = value or "Not detected"
        else:
            status = "pass" if value else "missing"
            value = value or "Not detected"
        if relevant:
            results.append({"name": label, "status": status, "value": value})

    allow_origin = normalized.get("access-control-allow-origin", "")
    allow_credentials = normalized.get("access-control-allow-credentials", "").lower() == "true"
    if not allow_origin:
        cors_status = "pass"
        cors_value = "No cross-origin allow header"
    elif allow_origin == "*":
        cors_status = "review"
        cors_value = "Wildcard origin" + ("; credentials also enabled" if allow_credentials else "")
    elif allow_origin == scanner.TEST_ORIGIN:
        cors_status = "warning" if allow_credentials else "review"
        cors_value = "Arbitrary test Origin was reflected" + (" with credentials" if allow_credentials else "")
    else:
        cors_status = "review"
        cors_value = f"Configured origin: {allow_origin}"
    results.append({"name": "CORS policy", "status": cors_status, "value": cors_value})
    return results


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "LocalHeaderAudit/1.0"

    def _send(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            pass

    def do_GET(self) -> None:
        if self.path not in {"/", "/dashboard.html"}:
            self._send(404, b"Not found", "text/plain; charset=utf-8")
            return
        try:
            payload = DASHBOARD_FILE.read_bytes()
        except OSError:
            self._send(500, b"Dashboard file could not be read", "text/plain; charset=utf-8")
            return
        self._send(200, payload, "text/html; charset=utf-8")

    def do_POST(self) -> None:
        if self.path != "/api/scan":
            self._send(404, b'{"error":"Not found"}', "application/json; charset=utf-8")
            return
        try:
            body_length = int(self.headers.get("Content-Length", "0"))
            if body_length < 1 or body_length > MAX_BODY_BYTES:
                raise ValueError("Invalid request size.")
            request_data = json.loads(self.rfile.read(body_length))
            if not isinstance(request_data, dict):
                raise ValueError("Request body must be a JSON object.")
            raw_url = request_data.get("url")
            if not isinstance(raw_url, str) or not raw_url.strip():
                raise ValueError("Enter a website URL.")
            url = scanner.normalize_url(raw_url)
            started = time.monotonic()
            status_code, final_url, headers = scanner.fetch_headers(url)
            findings = scanner.audit_headers(final_url, headers)
            checks = _checks(final_url, headers)
            elapsed_ms = round((time.monotonic() - started) * 1000)
            result = {
                "url": final_url,
                "http_status": status_code,
                "elapsed_ms": elapsed_ms,
                "findings": [finding.__dict__ for finding in findings],
                "checks": checks,
                "scope": "One GET response only. No crawling, form submission, or exploit testing.",
            }
            self._send(200, json.dumps(result).encode("utf-8"), "application/json; charset=utf-8")
        except (ValueError, json.JSONDecodeError) as error:
            self._send(400, json.dumps({"error": str(error)}).encode("utf-8"), "application/json; charset=utf-8")
        except (URLError, OSError) as error:
            reason = getattr(error, "reason", error)
            self._send(502, json.dumps({"error": f"Could not reach website: {reason}"}).encode("utf-8"), "application/json; charset=utf-8")

    def log_message(self, format: str, *args) -> None:
        print(f"[dashboard] {self.address_string()} - {format % args}")


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), DashboardHandler)
    print(f"Dashboard running at http://{HOST}:{PORT}")
    print("Only this computer can access it. Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
