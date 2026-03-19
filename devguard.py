#!/usr/bin/env python3
"""
DevGuard (lean) — quick web security hygiene scanner
Checks only 4 high-impact items with minimal requests:
  1) HTTPS + HSTS
  2) Content-Security-Policy (CSP)
  3) CORS preflight
  4) Cookie flags
"""

import json
import re
import sys
from urllib.parse import urlparse, urlunparse

import click
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
TIMEOUT = 15
DEFAULT_HEADERS = {"User-Agent": "DevGuard/1.0 (+https://example.dev)"}


# --------------------------- Models ---------------------------

class SecurityFinding:
    def __init__(self, type_: str, severity: str, message: str, evidence: str | None = None):
        self.type = type_          # "https_hsts" | "csp" | "cors" | "cookie"
        self.severity = severity   # "low" | "medium" | "high"
        self.message = message
        self.evidence = evidence

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "severity": self.severity,
            "message": self.message,
            "evidence": self.evidence,
        }


class SecurityScanner:
    """
    Scoring (lean):
      - CSP missing/weak:            +2  (medium)
      - HSTS missing/invalid:        +2  (medium)
      - CORS * + credentials:        +3  (high)
      - CORS reflect origin + creds: +2  (medium)
      - Cookie missing flags:        +1 each (low), cookie points CAP at +2 total
    Verdict:
      - score >= 5  -> Red
      - score >= 3  -> Yellow
      - else        -> Green
    """
    def __init__(self):
        self.findings: list[SecurityFinding] = []
        self.score = 0
        self._cookie_points = 0  # cap at 2

    def _add_points(self, severity: str, override_pts: int | None = None) -> int:
        if override_pts is not None:
            return override_pts
        return 3 if severity == "high" else 2 if severity == "medium" else 1

    def add_finding(self, finding: SecurityFinding, pts_override: int | None = None):
        pts = self._add_points(finding.severity, pts_override)
        self.findings.append(finding)
        self.score += pts

    def add_cookie_finding(self, finding: SecurityFinding):
        if self._cookie_points >= 2:
            return
        pts = self._add_points(finding.severity)  # low -> +1
        grant = min(pts, 2 - self._cookie_points)
        self.findings.append(finding)
        self.score += grant
        self._cookie_points += grant

    def verdict(self) -> tuple[str, str]:
        if self.score >= 5:
            return "Red", "🚨"
        if self.score >= 3:
            return "Yellow", "⚠️"
        return "Green", "✅"

    # ----------------------- Checks -----------------------

    def check_https_hsts(self, response: requests.Response, url: str, http_check: bool):
        """
        If URL is HTTPS:
          - Require Strict-Transport-Security with positive max-age
          - Optional: test http:// variant (no follow) → must 301/308 to https
        """
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return

        hsts = response.headers.get("Strict-Transport-Security", "")
        if not hsts:
            self.add_finding(SecurityFinding(
                "https_hsts", "medium",
                "Missing Strict-Transport-Security header on HTTPS site"
            ))
        else:
            m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
            if not m or int(m.group(1)) <= 0:
                self.add_finding(SecurityFinding(
                    "https_hsts", "medium",
                    "HSTS header has zero/invalid max-age",
                    hsts
                ))

        if http_check:
            try:
                http_url = urlunparse(parsed._replace(scheme="http"))
                r = requests.get(http_url, allow_redirects=False, timeout=TIMEOUT, headers=DEFAULT_HEADERS)
                if r.status_code not in (301, 308):
                    self.add_finding(SecurityFinding(
                        "https_hsts", "medium",
                        f"HTTP variant returned {r.status_code}, expected 301/308 redirect",
                        f"Status: {r.status_code}"
                    ))
                else:
                    loc = r.headers.get("Location", "")
                    if not loc.startswith("https://"):
                        self.add_finding(SecurityFinding(
                            "https_hsts", "medium",
                            "HTTP redirect did not target HTTPS",
                            loc or "<no Location header>"
                        ))
            except requests.RequestException:
                pass  # network issue not counted as finding

    def check_csp(self, response: requests.Response):
        """
        CSP:
          - Missing → finding (medium)
          - Weak if "*" or 'unsafe-inline' or 'unsafe-eval' present in default-src or script-src
        """
        csp = response.headers.get("Content-Security-Policy", "")
        if not csp:
            self.add_finding(SecurityFinding("csp", "medium", "Missing Content-Security-Policy header"))
            return

        def _get_dir(name: str) -> str | None:
            m = re.search(rf"{name}\s+([^;]+)", csp, re.IGNORECASE)
            return m.group(1) if m else None

        weak_tokens = ["*", "'unsafe-inline'", "'unsafe-eval'"]
        for dname in ("default-src", "script-src"):
            dval = _get_dir(dname)
            if not dval:
                continue
            for tok in weak_tokens:
                if tok in dval:
                    self.add_finding(SecurityFinding(
                        "csp", "medium",
                        f"Weak CSP: {dname} contains {tok}",
                        csp
                    ))
                    break

    def check_cors(self, url: str):
        """
        CORS preflight:
          - High: ACAO '*' AND ACC 'true'
          - Medium: ACAO reflects our Origin AND ACC 'true'
        """
        try:
            headers = {
                **DEFAULT_HEADERS,
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "GET",
            }
            r = requests.options(url, headers=headers, timeout=TIMEOUT)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acc = r.headers.get("Access-Control-Allow-Credentials", "").lower()
            if acao == "*" and acc == "true":
                self.add_finding(SecurityFinding(
                    "cors", "high",
                    "CORS allows any origin (*) with credentials",
                    f"ACAO: {acao}, ACC: {acc}"
                ))
            elif acao == "https://evil.example" and acc == "true":
                self.add_finding(SecurityFinding(
                    "cors", "medium",
                    "CORS reflects arbitrary Origin with credentials",
                    f"ACAO: {acao}, ACC: {acc}"
                ))
        except requests.RequestException:
            pass

    def check_cookies(self, response: requests.Response, url: str):
        """
        Cookie flags:
          - On HTTPS pages: missing Secure → finding (low)
          - Missing HttpOnly → finding (low)   (cookie points capped at +2)
        """
        is_https = urlparse(url).scheme == "https"

        # requests.Response.headers doesn't support getlist(), but raw.headers (urllib3) does
        set_cookie_headers: list[str] = []
        try:
            set_cookie_headers = response.raw.headers.getlist("Set-Cookie") or []
        except Exception:
            single = response.headers.get("Set-Cookie")
            if single:
                set_cookie_headers = [single]

        for hdr in set_cookie_headers:
            low = hdr.lower()

            if is_https and "secure" not in low:
                self.add_cookie_finding(SecurityFinding(
                    "cookie", "low",
                    "Cookie missing Secure flag on HTTPS site",
                    hdr if len(hdr) <= 120 else hdr[:117] + "..."
                ))

            if "httponly" not in low:
                self.add_cookie_finding(SecurityFinding(
                    "cookie", "low",
                    "Cookie missing HttpOnly flag",
                    hdr if len(hdr) <= 120 else hdr[:117] + "..."
                ))


# ---------------------- Programmatic API ----------------------

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url

def scan_url(url: str, http_check: bool = False) -> dict:
    """Programmatic wrapper used by FastAPI."""
    url = normalize_url(url)
    scanner = SecurityScanner()

    resp = requests.get(url, timeout=TIMEOUT, headers=DEFAULT_HEADERS)
    scanner.check_https_hsts(resp, url, http_check=http_check)
    scanner.check_csp(resp)
    scanner.check_cors(url)
    scanner.check_cookies(resp, url)

    verdict, _ = scanner.verdict()
    stats = {
        "status": resp.status_code,
        "content_length": int(resp.headers.get("Content-Length", len(resp.content) if resp.content else 0)),
    }
    return {
        "url": url,
        "score": scanner.score,
        "verdict": verdict,
        "stats": stats,
        "findings": [f.to_dict() for f in scanner.findings],
    }


# --------------------------- CLI ---------------------------

@click.command()
@click.argument("url", type=str)
@click.option("--json-out", type=click.Path(dir_okay=False), help="Write JSON result to this file.")
@click.option("--http-check", is_flag=True, help="Also test http:// variant for proper redirect to HTTPS.")
def scan(url: str, json_out: str | None, http_check: bool):
    """CLI scan."""
    try:
        results = scan_url(url, http_check=http_check)
    except requests.RequestException as e:
        console.print(f"[red]Error connecting to {url}:[/red] {e}")
        sys.exit(1)

    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        console.print(f"[green]Wrote JSON:[/green] {json_out}")
    else:
        click.echo(json.dumps(results, indent=2))

    verdict = results["verdict"]
    verdict_text = f"{'🚨' if verdict=='Red' else '⚠️' if verdict=='Yellow' else '✅'} [bold]{verdict}[/bold]  (Score: {results['score']}, Findings: {len(results['findings'])})"
    console.print(Panel(verdict_text, title="Security Verdict",
                        border_style=("green" if verdict == "Green" else "yellow" if verdict == "Yellow" else "red")))

    stats = results["stats"]
    stats_text = f"[bold]Status:[/bold] {stats['status']}  |  [bold]Content Length:[/bold] {stats['content_length']:,} bytes"
    console.print(Panel(stats_text, title="Response Summary"))

    table = Table(title="Security Findings")
    table.add_column("Severity", style="bold")
    table.add_column("Type")
    table.add_column("Message")
    table.add_column("Evidence", overflow="fold", max_width=80)
    if results["findings"]:
        for f in results["findings"]:
            style = "red bold" if f["severity"] == "high" else "yellow bold" if f["severity"] == "medium" else "blue"
            table.add_row(f["severity"].upper(), f["type"], f["message"], f.get("evidence") or "", style=style)
    else:
        table.add_row("—", "—", "No findings", "—")
    console.print(table)

    sys.exit(1 if verdict == "Red" else 0)


if __name__ == "__main__":
    scan()
