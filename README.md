# Web Security Scanner

A small Python scanner I put together while studying for my cybersecurity
degree. It checks a site's security headers and cookie flags, then runs a few
light active probes (reflected XSS, error-based SQLi, open redirect) and
reports everything with a severity and a plain-English explanation.

I built it because I kept reading about these checks in class and wanted to
actually see them work instead of just memorizing header names. Turns out
writing the scanner taught me more about how HTTP responses fit together than
the textbook chapters did.

Please don't scan sites you don't own. I mean it. Running even light
probes against someone else's site without written permission can get you in
real legal trouble, and it's just not worth it. This is for your own projects,
labs, and authorized work.

## What it checks

Passive stuff first:

- `Content-Security-Policy` (medium if missing): the main defense against XSS
- `Strict-Transport-Security` (medium): forces HTTPS, stops SSL-stripping
- `X-Frame-Options` (low): keeps your page out of other people's iframes
- `X-Content-Type-Options` (low): `nosniff`, stops MIME-sniffing tricks
- `Referrer-Policy` (info): keeps tokens out of the Referer header
- Cookie flags: `HttpOnly`, `Secure`, `SameSite` (medium/low when missing)

Then three active probes, all benign and read-only:

- Reflected XSS: drops `<script>alert(1)</script>` in a query param and
  checks if it comes back unescaped. High severity if it does.
- Error-based SQLi: sends quote payloads and looks for database error
  strings in the response. High if it finds any.
- Open redirect: tries the usual redirect param names (`next`, `url`,
  `redirect`...) with an external URL and watches the `Location` header.
  Medium if it follows.

Every probe also reports an `info` finding when it finds nothing, so you can
see what actually ran. A clean result here doesn't mean you're safe. It just
means these particular light probes didn't catch anything. Stored XSS, blind
SQLi, all that still needs real testing.

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
# basic scan
python scanner.py https://example.com

# JSON output if you want to pipe it somewhere
python scanner.py https://example.com --json

# shorter timeout per request
python scanner.py https://example.com --timeout 5
```

## What the output looks like

Ran against a plain `python -m http.server` on localhost:

```
Scan results for http://127.0.0.1:8777
=======================================
Summary: 0 high, 2 medium, 2 low, 6 info

[MEDIUM] Missing Content-Security-Policy header  (security-header)
         Detail: Response from http://127.0.0.1:8777 does not include this header.
         Why it matters: CSP is the primary defense against XSS: it restricts which origins can load scripts, styles, and other resources. Without it, a single injected script can run with full page privileges.

[LOW   ] Missing X-Frame-Options header  (security-header)
         Detail: Response from http://127.0.0.1:8777 does not include this header.
         Why it matters: Without X-Frame-Options (or the CSP frame-ancestors directive), the page can be embedded in an attacker's iframe, enabling clickjacking attacks that trick users into clicking hidden controls.

[INFO  ] No reflected XSS detected  (xss)
         Detail: Payload in parameter 'q' was not reflected verbatim.
         Why it matters: A single benign probe is not proof of safety. Stored XSS, DOM XSS, and filtered contexts need deeper testing.
```

## What's in the repo

```
web-security-scanner/
├── scanner.py        # the whole scanner, one file
├── requirements.txt  # just requests
└── README.md         # you're reading it
```

## Things that tripped me up

- Getting cookie flags out of `requests` was annoying. The flags live in a
  `_rest` dict on the underlying cookie object, and `HttpOnly` shows up there
  as a key with an empty value. Took me longer than I'd like to admit to
  figure that out.
- The open-redirect probe has to use `allow_redirects=False`, or `requests`
  happily follows the redirect and you never see the `Location` header. I
  burned a good half hour wondering why nothing was detected before I caught
  that.
- Severity ratings are judgment calls. I went back and forth on whether a
  missing CSP should be medium or high, and settled on medium since the header
  alone doesn't mean the site is exploitable.

## What I'd do differently next time

- Check TLS cert expiry. It's an easy win and I just didn't get to it.
- Flag `Server` / `X-Powered-By` version disclosure.
- Add an `--output` flag to save the report to a file instead of just
  printing it.
- Respect robots.txt and add some rate limiting before pointing this at
  anything bigger than a lab.
