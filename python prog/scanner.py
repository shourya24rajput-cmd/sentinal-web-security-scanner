

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen


TEST_ORIGIN = "https://scanner-test.invalid"
USER_AGENT = "AuthorizedSecurityHeaderAudit/1.0"


@dataclass(frozen=True)
class Finding:
	severity: str
	title: str
	detail: str


def normalize_url(value: str) -> str:
	"""Validate and normalize a single HTTP(S) URL."""
	candidate = value.strip()
	if "://" not in candidate:
		candidate = "https://" + candidate

	parts = urlsplit(candidate)
	if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
		raise ValueError("Enter a valid http:// or https:// URL.")
	if parts.username is not None or parts.password is not None:
		raise ValueError("Do not include credentials in the URL.")

	# Fragments are not sent in HTTP requests and are removed for clarity.
	return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", parts.query, ""))


def fetch_headers(url: str, timeout: float = 10.0):
	"""Make one GET request with a harmless test Origin and return response data."""
	request = Request(
		url,
		headers={"User-Agent": USER_AGENT, "Origin": TEST_ORIGIN},
		method="GET",
	)
	try:
		response = urlopen(request, timeout=timeout)
	except HTTPError as error:
		# HTTP error responses still provide useful headers for this audit.
		response = error

	with response:
		return response.status, response.geturl(), response.headers


def audit_headers(url: str, headers) -> list[Finding]:
	"""Evaluate common response-header and basic CORS configuration signals."""
	findings: list[Finding] = []
	normalized = {name.lower(): value.strip() for name, value in headers.items()}
	is_https = urlsplit(url).scheme == "https"

	if is_https and "strict-transport-security" not in normalized:
		findings.append(Finding("WARN", "HSTS missing", "HTTPS sites should consider Strict-Transport-Security."))
	if "content-security-policy" not in normalized:
		findings.append(Finding("WARN", "Content Security Policy missing", "A suitable CSP can reduce the impact of injected content."))
	if normalized.get("x-content-type-options", "").lower() != "nosniff":
		findings.append(Finding("WARN", "X-Content-Type-Options missing or weak", "Set X-Content-Type-Options: nosniff."))

	csp = normalized.get("content-security-policy", "").lower()
	if "x-frame-options" not in normalized and "frame-ancestors" not in csp:
		findings.append(Finding("WARN", "Clickjacking protection not detected", "Set X-Frame-Options or a CSP frame-ancestors directive."))
	if "referrer-policy" not in normalized:
		findings.append(Finding("INFO", "Referrer-Policy missing", "Consider setting a policy such as strict-origin-when-cross-origin."))
	if "permissions-policy" not in normalized:
		findings.append(Finding("INFO", "Permissions-Policy missing", "Consider disabling browser features the site does not use."))

	allow_origin = normalized.get("access-control-allow-origin")
	allow_credentials = normalized.get("access-control-allow-credentials", "").lower() == "true"
	vary_tokens = {token.strip().lower() for token in normalized.get("vary", "").split(",")}

	if allow_origin == "*":
		if allow_credentials:
			findings.append(Finding(
				"WARN",
				"CORS wildcard with credentials header",
				"Browsers reject credentialed CORS when Access-Control-Allow-Origin is '*'; verify the intended policy.",
			))
		else:
			findings.append(Finding(
				"INFO",
				"CORS allows any origin",
				"The response is marked readable by any origin; this may be intentional for public resources.",
			))
	elif allow_origin == TEST_ORIGIN:
		severity = "WARN" if allow_credentials else "INFO"
		detail = "The response reflected the scanner's arbitrary test Origin."
		if allow_credentials:
			detail += " With credentials enabled, review whether untrusted sites can read sensitive data."
		if "origin" not in vary_tokens:
			detail += " Vary: Origin is also absent; review intermediary-cache behavior."
		findings.append(Finding(severity, "CORS reflects the test Origin", detail))
	elif allow_origin:
		findings.append(Finding(
			"INFO",
			"CORS allows a specific origin",
			f"Access-Control-Allow-Origin is set to {allow_origin!r}; confirm it is an intended trusted origin.",
		))
	else:
		findings.append(Finding("INFO", "No CORS allow-origin header", "This response did not grant cross-origin read access through CORS."))

	return findings


def main() -> int:
	parser = argparse.ArgumentParser(
		description="Check common security response headers and a basic CORS signal for one authorized website."
	)
	parser.add_argument("url", nargs="?", help="Website URL to check, e.g. https://example.com")
	parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds (default: 10)")
	args = parser.parse_args()
	if args.url is None:
		try:
			args.url = input("Website URL to check (e.g. https://example.com): ").strip()
		except EOFError:
			print("No URL provided. Run again and enter a website URL.", file=sys.stderr)
			return 2
		if not args.url:
			print("No URL provided. Run again and enter a website URL.", file=sys.stderr)
			return 2

	if args.timeout <= 0:
		parser.error("--timeout must be greater than zero")

	try:
		url = normalize_url(args.url)
		status, final_url, headers = fetch_headers(url, args.timeout)
	except (ValueError, URLError, OSError) as error:
		print(f"Error: {error}", file=sys.stderr)
		return 2

	findings = audit_headers(final_url, headers)
	print(f"Website: {final_url}")
	print(f"HTTP status: {status}")
	print("\nFindings:")
	for finding in findings:
		print(f"[{finding.severity}] {finding.title}: {finding.detail}")
	print("\nScope: one GET response only; OPTIONS/preflight behavior and application-specific risks were not tested.")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
