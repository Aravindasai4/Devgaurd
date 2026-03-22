# DevGuard

**Black-box HTTP security hygiene scanner for vibe-coded and AI-generated applications.**

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python) ![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green?logo=fastapi) ![License](https://img.shields.io/badge/License-MIT-yellow)

---

## What is DevGuard

DevGuard is a lightweight, black-box HTTP security scanner written in Python. It inspects any publicly accessible URL and checks for misconfigured security headers, insecure cookie policies, and dangerous CORS configurations — without requiring access to source code, build systems, or deployment infrastructure. You give it a URL; it gives you a verdict.

It was built specifically to address a gap in how "vibe-coded" applications get deployed. Vibe-coded apps are built using AI-assisted code generation tools — Replit AI, GitHub Copilot, Cursor, ChatGPT, Claude — or no-code/low-code platforms like Lovable, Bubble, and Webflow. These tools generate functional application logic quickly, but they rarely emit HTTP security headers, CORS policies, or cookie flags unless the developer explicitly asks for them — and most developers building with these tools don't know to ask.

The result is a wave of deployed applications that look and work correctly but are silently misconfigured at the HTTP layer. A missing `Content-Security-Policy` doesn't break anything visually — it just leaves the door open for XSS. A misconfigured CORS policy won't affect normal users — it just lets attacker-controlled sites make credentialed cross-origin requests. DevGuard surfaces these issues in seconds, without requiring the developer to be a security engineer. For AI governance teams, the structured JSON output integrates directly into approval workflows: a `"verdict": "Red"` response becomes an automated gate before deployment promotion.

---

## What It Detects

| Check | What's Tested | Severity | OWASP / RFC Reference |
|---|---|---|---|
| **HTTPS + HSTS** | Presence of `Strict-Transport-Security` header with valid `max-age > 0` | Medium | OWASP A02, RFC 6797 |
| **HTTP Redirect** | `http://` variant returns 301/308 with `https://` `Location` header (opt-in via `--http-check`) | Medium | OWASP A02, RFC 6797 |
| **CSP Missing** | No `Content-Security-Policy` header present | Medium | OWASP A03, W3C CSP Level 3 |
| **CSP Weak: wildcard** | `default-src` or `script-src` contains `*` | Medium | OWASP A03, W3C CSP Level 3 |
| **CSP Weak: unsafe-inline** | `default-src` or `script-src` contains `'unsafe-inline'` | Medium | OWASP A03, W3C CSP Level 3 |
| **CSP Weak: unsafe-eval** | `default-src` or `script-src` contains `'unsafe-eval'` | Medium | OWASP A03, W3C CSP Level 3 |
| **CORS: wildcard + credentials** | `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` | **High** | OWASP A01, RFC 6454 |
| **CORS: origin reflection + credentials** | Server echoes `Origin: https://evil.example` back with `Access-Control-Allow-Credentials: true` | Medium | OWASP A01, RFC 6454 |
| **Cookie: missing Secure** | `Set-Cookie` header lacks `Secure` attribute on an HTTPS site | Low | OWASP A07, RFC 6265 |
| **Cookie: missing HttpOnly** | `Set-Cookie` header lacks `HttpOnly` attribute | Low | OWASP A07, RFC 6265 |

CORS checks use a live OPTIONS preflight with `Origin: https://evil.example` to detect both static wildcard configs and dynamic origin-reflection behaviors. Cookie headers are inspected individually using raw `urllib3` header access (`response.raw.headers.getlist("Set-Cookie")`) to avoid the `requests` library's header-merge behavior.

---

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                         INPUT                               │
│  Web UI (POST /scan)  │  CLI (python devguard.py <url>)     │
│  API (POST /scan JSON)│  Demo mode (uses example.org)       │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
                 normalize_url()
           (strip whitespace, prepend https://)
                        │
                        ▼
              is_safe_url() — SSRF check
         (blocks localhost, private IPs, metadata endpoints)
                        │
                        ▼
           ┌────────────────────────┐
           │  requests.get(url)     │  ← Primary HTTP GET (timeout: 15s)
           │  User-Agent: DevGuard  │    All 4 checks run on this response
           └────────────┬───────────┘
                        │
          ┌─────────────┼──────────────────────┐
          ▼             ▼             ▼         ▼
   check_https_hsts  check_csp  check_cors  check_cookies
          │                        │
          │ (if --http-check)      │ requests.options(url,
          └─ requests.get(http://) │   Origin: https://evil.example)
                                   │
          └─────────────┬──────────┘
                        ▼
              SecurityScanner.score
              SecurityScanner.verdict()
              → "Green" / "Yellow" / "Red"
                        │
          ┌─────────────┼───────────────────┐
          ▼             ▼                   ▼
      JSON API      Web UI            CLI (Rich)
   (POST /scan)  findings cards    colored table +
                 + health bar      verdict panel +
                                   exit code 0/1
```

All scanning is performed server-side. The browser client never contacts the scan target directly — it sends a single `POST /scan` request to the FastAPI backend, which handles all outbound HTTP requests to the target URL. Each full scan issues 2–3 outbound requests: one `GET` (always), one `OPTIONS` for CORS (always), and one `GET` to the `http://` variant (only if `http_check` is enabled).

If the target URL is unreachable (timeout, DNS failure, SSL error, connection refused), `scan_url()` returns a clean JSON error response with `"verdict": "Error"` rather than raising an unhandled exception.

---

## Scoring & Verdicts

**Penalty model** — points are added per finding. Lower score = better security posture.

| Severity | Points | Examples |
|---|---|---|
| High | +3 | CORS wildcard + credentials |
| Medium | +2 | Missing HSTS, missing CSP, weak CSP directive, CORS origin reflection |
| Low | +1 | Missing cookie `Secure` or `HttpOnly` flag |
| Cookie cap | max +2 total | All cookie findings combined never exceed +2 points |

**Verdict thresholds:**

| Score | Verdict | Governance Meaning |
|---|---|---|
| 0–2 | ✅ Green | Acceptable security posture — no blocking issues detected |
| 3–4 | ⚠️ Yellow | Notable misconfigurations — review recommended before production |
| 5+ | 🚨 Red | Significant vulnerabilities — flag for security review; block deployment promotion |

The CLI exits with code `1` on Red and `0` on Green or Yellow, enabling use as a CI/CD pipeline gate.

> **Note for governance integrations:** The `score` field is an additive penalty value (lower = better), not a 0–100 percentage. The web UI displays an inverted **Security Health** percentage (higher = better) for human readability. Use `verdict` as the primary decision signal in automated workflows.

---

## Quick Start

**Requirements:** Python 3.11+

```bash
# Install dependencies
pip install -r requirements.txt

# Start the web server
python3 -m uvicorn server:app --host 0.0.0.0 --port 5000

# Open the web UI
# → http://localhost:5000/ui

# Or use the CLI directly
python devguard.py https://example.org

# With optional HTTP redirect check
python devguard.py https://example.org --http-check

# Write JSON output to file
python devguard.py https://example.org --json-out result.json
```

**Example CLI output:**

```
╭─────────────── Security Verdict ───────────────╮
│ ⚠️  Yellow  (Score: 4, Findings: 2)            │
╰────────────────────────────────────────────────╯

╭──────────────── Response Summary ──────────────╮
│ Status: 200  |  Content Length: 648 bytes      │
╰────────────────────────────────────────────────╯

              Security Findings
┏━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Type       ┃ Message                                  ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ MEDIUM   │ https_hsts │ Missing Strict-Transport-Security header │
│ MEDIUM   │ csp        │ Missing Content-Security-Policy header   │
└──────────┴────────────┴──────────────────────────────────────────┘
```

---

## API Reference

### `POST /scan`

Run a security scan against a target URL.

**Request — scan a URL:**
```json
{
  "url": "https://target.example.com",
  "http_check": false
}
```

**Request — run demo scan (uses `example.org` as target):**
```json
{
  "demo": true
}
```

**Response — successful scan:**
```json
{
  "url": "https://example.com",
  "score": 4,
  "verdict": "Yellow",
  "stats": {
    "status": 200,
    "content_length": 648
  },
  "findings": [
    {
      "type": "https_hsts",
      "severity": "medium",
      "message": "Missing Strict-Transport-Security header on HTTPS site",
      "evidence": null
    },
    {
      "type": "csp",
      "severity": "medium",
      "message": "Missing Content-Security-Policy header",
      "evidence": null
    }
  ]
}
```

**Response — scan error (target unreachable):**
```json
{
  "url": "https://unreachable.example.com",
  "error": "Request timed out. The target did not respond within 15 seconds.",
  "score": 0,
  "verdict": "Error",
  "stats": {},
  "findings": []
}
```

**Finding field reference:**

| Field | Values | Notes |
|---|---|---|
| `type` | `https_hsts` \| `csp` \| `cors` \| `cookie` | Category of the finding |
| `severity` | `high` \| `medium` \| `low` | Determines penalty points applied to score |
| `message` | String | Human-readable description of the issue |
| `evidence` | String or `null` | Raw header value when available, otherwise `null` |

---

### `GET /ui`

Web-based scan interface. Supports URL input, demo mode, and quick-pick public test targets (`httpbin.org`, `badssl.com`, `jsonplaceholder.typicode.com`, `example.org`). Displays findings as severity-badged cards with a colour-coded Security Health bar (0–100, higher = better). No authentication required.

### `GET /docs`

Swagger UI — auto-generated interactive API documentation provided by FastAPI.

### `GET /report.pdf`

Returns a minimal placeholder PDF stub. **PDF report generation is not implemented.** This endpoint exists solely to prevent 404 errors from external tooling that links to it.

---

## CI/CD Integration

The CLI exits with code `1` on a Red verdict and `0` on Green or Yellow. Use this to gate deployments in any shell-based pipeline.

**GitHub Actions example:**

```yaml
name: Security Gate

on:
  push:
    branches: [main]
  pull_request:

jobs:
  devguard-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install DevGuard
        run: pip install -r requirements.txt

      - name: Run security scan
        run: |
          python devguard.py ${{ secrets.DEPLOY_URL }} \
            --http-check \
            --json-out scan-result.json

      - name: Upload scan result
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: devguard-scan-result
          path: scan-result.json
```

A Red verdict causes the `Run security scan` step to exit with code `1`, failing the workflow and blocking any dependent deployment steps. The JSON artifact is uploaded regardless of outcome to preserve an audit trail.

---

## Governance Use Case

DevGuard is part of a 4-layer AI governance portfolio, positioned as the **Security Posture Layer**. It addresses a specific gap: AI-generated and no-code applications ship without systematic HTTP security review because no lightweight, code-free tooling existed for this purpose.

**How governance teams use the JSON output:**

The `POST /scan` response is machine-readable and designed for direct integration into approval workflows. The `verdict` field is the primary signal:

```python
import requests

result = requests.post(
    "https://your-devguard-instance/scan",
    json={"url": app_url}
).json()

if result["verdict"] == "Red":
    block_deployment(app_id, reason=result["findings"])
elif result["verdict"] == "Yellow":
    flag_for_review(app_id, findings=result["findings"])
else:
    approve_deployment(app_id)
```

**Integration points for governance workflows:**

| Use Case | How DevGuard Is Used |
|---|---|
| **Pre-deployment gate** | Scan staging URL before promoting to production; block on Red verdict |
| **Periodic audit** | Schedule scans against all live app URLs; store results; alert on verdict regressions |
| **Third-party / vendor review** | Scan supplier-provided app URLs without source code or infrastructure access |
| **AI app registry** | Attach DevGuard verdict to each entry in an internal registry of AI-generated tools |
| **Compliance evidence** | Store `findings` array (`type`, `severity`, `message`, `evidence`) as field-level audit trail data |

The `stats.status` field confirms the target was reachable and returned a live response. The `stats.content_length` field confirms a non-empty response body. Both are included in every scan result to validate scan integrity.

---

## Known Limitations

These are current limitations of the implementation, documented without omission.

- **No remediation guidance.** Findings describe what is wrong (e.g., `"Missing Content-Security-Policy header"`) but do not explain how to fix it or provide example correct header values.
- **No persistent storage.** Scan results are not saved server-side. There is no scan history, no dashboard, and no trend tracking across multiple scans or time periods.
- **No batch scanning.** One URL per `POST /scan` request. No queue, no scheduling, no multi-target sweep mode.
- **No functional PDF export.** `GET /report.pdf` returns a minimal stub file with a valid PDF header but no content. It is not a real report.
- **Runtime-only, black-box scanning.** DevGuard does not scan source code, `.env` files, `config.yaml`, `package.json`, infrastructure definitions, or any static artifact. It only inspects live HTTP responses from a deployed, running application.
- **HTTP redirect check is opt-in.** The `http://` → `https://` redirect check is disabled by default and must be explicitly enabled via `--http-check` (CLI) or `"http_check": true` in the API request body. Scans without this flag will not detect missing or misconfigured HTTP redirects.
- **Cookie `Secure` flag detection uses substring matching.** The check uses `"secure" not in cookie_header.lower()`, which could theoretically false-positive on a cookie name containing the word "secure" (e.g., `insecure_token`). In practice this is extremely unlikely but is a known edge case.

---

## Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.11 |
| Backend framework | FastAPI |
| ASGI server | Uvicorn |
| HTTP client | `requests` |
| CLI | Click |
| Terminal rendering | Rich |
| Request validation | Pydantic v2 |
| Frontend | Inline HTML/CSS/JS (no build step, no bundler) |
| API docs | Swagger UI (built into FastAPI at `/docs`) |
| Vulnerability databases | None — fully rule-based |
| ML / AI models | None |

---

## Project Structure

```
devguard/
├── devguard.py        # Scanner engine: SecurityFinding, SecurityScanner,
│                      # scan_url() API, normalize_url(), Click CLI entry point
├── server.py          # FastAPI app: /scan endpoint, /ui inline web interface,
│                      # /report.pdf stub, ScanReq Pydantic model, SSRF protection
├── main.py            # Uvicorn entry point
├── requirements.txt   # Python dependencies
├── results.json       # Sample scan output for example.com (Yellow verdict)
└── generated-icon.png # Project icon asset
```

**Key internals:**

- `SecurityFinding` — data class holding `type`, `severity`, `message`, and `evidence` per finding
- `SecurityScanner` — stateful accumulator: collects findings, computes penalty score, returns verdict via `verdict()`
- `scan_url(url, http_check)` — shared programmatic API called by both the FastAPI route handler and the Click CLI command; returns a clean error dict on connection failures rather than raising exceptions
- `is_safe_url(url)` — SSRF protection: validates the target resolves to a globally routable IP before allowing the scan to proceed
- `ScanReq` — Pydantic model for `POST /scan` request body validation (`url`, `demo`, `http_check` fields)

---

## Built With

This project was built using AI-assisted development — Replit AI, Claude, and ChatGPT — as part of an AI governance portfolio demonstrating that vibe-coded tools can be audited, assessed, and governed. DevGuard is itself an example of what it scans: an AI-generated application that has been reviewed for HTTP security hygiene.

GitHub: [Aravindasai4](https://github.com/Aravindasai4)

---

## License

MIT License. See `LICENSE` for details.
