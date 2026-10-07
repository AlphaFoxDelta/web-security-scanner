#!/usr/bin/env python3
"""
A small web security scanner I built to practice the basics:
security headers, cookie flags, and a few light active probes
(reflected XSS, error-based SQLi, open redirect).

Nothing fancy. Every finding gets a severity and a short
explanation of why it matters.

Only scan sites you own or have written permission to test.
Seriously. Don't be that person.
"""

import argparse
import json
import sys
import urllib.parse

import requests

SEVERITY_ORDER = ["info", "low", "medium", "high"]

# header name -> (severity if missing, title, why it matters)
HEADER_CHECKS = {
    "content-security-policy": (
        "medium",
        "Missing Content-Security-Policy header",
        "CSP is the primary defense against XSS: it restricts which origins "
        "can load scripts, styles, and other resources. Without it, a single "
        "injected script can run with full page privileges.",
    ),
    "strict-transport-security": (
        "medium",
        "Missing Strict-Transport-Security header",
        "HSTS tells browsers to always use HTTPS for this site, blocking "
        "SSL-stripping man-in-the-middle attacks. Without it, the first visit "
        "can be intercepted and downgraded to HTTP.",
    ),
    "x-frame-options": (
        "low",
        "Missing X-Frame-Options header",
        "Without X-Frame-Options (or the CSP frame-ancestors directive), the "
        "page can be embedded in an attacker's iframe, enabling clickjacking "
        "attacks that trick users into clicking hidden controls.",
    ),
    "x-content-type-options": (
        "low",
        "Missing X-Content-Type-Options header",
        "Without 'nosniff', browsers may MIME-sniff responses and execute "
        "uploaded text files as JavaScript, turning an upload feature into a "
        "stored-XSS vector.",
    ),
    "referrer-policy": (
        "info",
        "Missing Referrer-Policy header",
        "Without Referrer-Policy, the full URL (which may contain tokens or "
        "identifiers) leaks to third parties via the Referer header. "
        "'strict-origin-when-cross-origin' is a good default.",
    ),
}


def check_headers(url, response, findings):
    """Flag missing security response headers."""
    for header, (severity, title, explanation) in HEADER_CHECKS.items():
        if header not in response.headers:
            findings.append(
                {
                    "severity": severity,
                    "category": "security-header",
                    "title": title,
                    "detail": f"Response from {url} does not include this header.",
                    "explanation": explanation,
                }
            )


# cookies
def check_cookies(response, findings):
    """Flag cookies missing HttpOnly / Secure / SameSite flags."""
    raw = response.headers.get("Set-Cookie", "")
    if not raw:
        findings.append(
            {
                "severity": "info",
                "category": "cookie",
                "title": "No cookies set",
                "detail": "The response set no cookies, so no cookie-flag checks apply.",
                "explanation": "Session and auth cookies should carry HttpOnly, "
                "Secure, and SameSite attributes. Nothing to check here.",
            }
        )
        return

    for cookie in response.cookies:
        missing = []
        c = response.cookies
        # requests stashes flags in _rest; HttpOnly lands there too
        jar_cookie = next((k for k in c if k.name == cookie.name), None)
        attrs = jar_cookie._rest if jar_cookie else {}
        flags = {k.lower() for k in attrs}
        if "httponly" not in flags:
            missing.append("HttpOnly")
        if "secure" not in flags:
            missing.append("Secure")
        samesite = attrs.get("SameSite", attrs.get("samesite"))
        if not samesite:
            missing.append("SameSite")

        if missing:
            sev = "medium" if "HttpOnly" in missing or "Secure" in missing else "low"
            findings.append(
                {
                    "severity": sev,
                    "category": "cookie",
                    "title": f"Cookie '{cookie.name}' missing flags: {', '.join(missing)}",
                    "detail": f"Set-Cookie for '{cookie.name}' lacks: {', '.join(missing)}.",
                    "explanation": "HttpOnly keeps JavaScript from reading the cookie "
                    "(XSS mitigation). Secure restricts it to HTTPS. SameSite "
                    "restricts cross-site sending (CSRF mitigation).",
                }
            )


# active probes. payloads are deliberately boring/benign.
XSS_PAYLOAD = "<script>alert(1)</script>"
SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "1' OR '1'='1' -- "]
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "syntax error",
    "ora-01756",
    "sqlite3::sqlexception",
    "pg_query()",
]
REDIRECT_PAYLOAD = "https://evil.example.com"


def probe_reflected_xss(session, url, timeout, findings):
    """Send a benign script payload in a query param; check reflection."""
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    probe_param = "q" if "q" not in params else "scanner_test_param"
    probe_params = dict(params)
    probe_params[probe_param] = XSS_PAYLOAD
    probe_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(probe_params)))
    try:
        r = session.get(probe_url, timeout=timeout)
    except requests.RequestException:
        return
    if XSS_PAYLOAD in r.text:
        findings.append(
            {
                "severity": "high",
                "category": "xss",
                "title": "Possible reflected XSS",
                "detail": f"The payload sent in query parameter '{probe_param}' was "
                f"reflected verbatim in the response body of {probe_url}.",
                "explanation": "Unescaped reflection of user input is the classic "
                "reflected-XSS pattern. An attacker can craft a link that runs "
                "JavaScript in a victim's session (session theft, defacement). "
                "Confirm manually and fix by context-appropriate output encoding.",
            }
        )
    else:
        findings.append(
            {
                "severity": "info",
                "category": "xss",
                "title": "No reflected XSS detected",
                "detail": f"Payload in parameter '{probe_param}' was not reflected verbatim.",
                "explanation": "A single benign probe is not proof of safety — stored "
                "XSS, DOM XSS, and filtered contexts need deeper testing.",
            }
        )


def probe_sqli(session, url, timeout, findings):
    """Send quote-based payloads; look for database error strings."""
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    probe_param = "id" if "id" not in params else "scanner_test_param"
    hit = None
    for payload in SQLI_PAYLOADS:
        probe_params = dict(params)
        probe_params[probe_param] = payload
        probe_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(probe_params)))
        try:
            r = session.get(probe_url, timeout=timeout)
        except requests.RequestException:
            continue
        body = r.text.lower()
        for err in SQL_ERRORS:
            if err in body:
                hit = (payload, err)
                break
        if hit:
            break
    if hit:
        payload, err = hit
        findings.append(
            {
                "severity": "high",
                "category": "sqli",
                "title": "Possible error-based SQL injection",
                "detail": f"Payload {payload!r} in parameter '{probe_param}' triggered a "
                f"response containing a database error signature ({err!r}).",
                "explanation": "Database errors returned to the browser suggest user "
                "input reaches a SQL query unsafely. Error-based SQLi can lead to "
                "full database extraction. Confirm manually and fix with "
                "parameterized queries / prepared statements.",
            }
        )
    else:
        findings.append(
            {
                "severity": "info",
                "category": "sqli",
                "title": "No SQL error signatures detected",
                "detail": "Quote-based probes did not trigger recognizable database errors.",
                "explanation": "Blind and time-based SQLi do not produce error text; "
                "this probe only catches the noisy error-based variant.",
            }
        )


def probe_open_redirect(session, url, timeout, findings):
    """Check common redirect params for unvalidated external redirects."""
    candidates = ["next", "url", "redirect", "return", "target", "dest", "destination"]
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    hit = None
    for name in candidates:
        probe_params = dict(params)
        probe_params[name] = REDIRECT_PAYLOAD
        probe_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(probe_params)))
        try:
            r = session.get(probe_url, timeout=timeout, allow_redirects=False)
        except requests.RequestException:
            continue
        location = r.headers.get("Location", "")
        if location.startswith(REDIRECT_PAYLOAD):
            hit = (name, location)
            break
    if hit:
        name, location = hit
        findings.append(
            {
                "severity": "medium",
                "category": "open-redirect",
                "title": "Possible open redirect",
                "detail": f"Parameter '{name}' caused a redirect to {location}.",
                "explanation": "Attackers abuse open redirects in phishing: the link "
                "looks like your trusted domain but lands on a malicious site. "
                "Fix by validating redirect targets against an allowlist.",
            }
        )
    else:
        findings.append(
            {
                "severity": "info",
                "category": "open-redirect",
                "title": "No open redirect detected",
                "detail": "Common redirect parameters did not redirect to an external URL.",
                "explanation": "Only a handful of common parameter names were tried; "
                "application-specific redirect endpoints need manual review.",
            }
        )


# puts it all together
def scan(target, timeout):
    findings = []
    session = requests.Session()
    session.headers["User-Agent"] = "web-security-scanner/1.0 (educational)"

    try:
        response = session.get(target, timeout=timeout)
    except requests.RequestException as exc:
        return [
            {
                "severity": "high",
                "category": "connectivity",
                "title": "Could not reach target",
                "detail": str(exc),
                "explanation": "The scan could not run because the target did not "
                "respond. Check the URL and network access.",
            }
        ]

    findings.append(
        {
            "severity": "info",
            "category": "target",
            "title": f"Scanned {target}",
            "detail": f"HTTP {response.status_code} in {response.elapsed.total_seconds():.2f}s, "
            f"{len(response.content)} bytes.",
            "explanation": "Baseline response information for this scan.",
        }
    )

    check_headers(target, response, findings)
    check_cookies(response, findings)
    probe_reflected_xss(session, target, timeout, findings)
    probe_sqli(session, target, timeout, findings)
    probe_open_redirect(session, target, timeout, findings)

    findings.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]), reverse=True)
    return findings


def print_text(target, findings):
    print(f"\nScan results for {target}\n{'=' * (18 + len(target))}")
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] += 1
    print(
        "Summary: "
        + ", ".join(f"{counts[s]} {s}" for s in reversed(SEVERITY_ORDER))
        + "\n"
    )
    for f in findings:
        print(f"[{f['severity'].upper():6}] {f['title']}  ({f['category']})")
        print(f"         Detail: {f['detail']}")
        print(f"         Why it matters: {f['explanation']}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Lightweight educational web security scanner.",
        epilog="Only scan sites you own or have explicit written permission to test.",
    )
    parser.add_argument("url", help="Target URL to scan (include http:// or https://)")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit findings as JSON instead of human-readable text",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-request timeout in seconds (default: 10)",
    )
    args = parser.parse_args()

    if not args.url.startswith(("http://", "https://")):
        parser.error("URL must start with http:// or https://")

    findings = scan(args.url, args.timeout)
    if args.json:
        print(json.dumps({"target": args.url, "findings": findings}, indent=2))
    else:
        print_text(args.url, findings)


if __name__ == "__main__":
    main()
