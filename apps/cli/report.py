"""Shared Markdown report generator for all scan types."""

import re
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console

console = Console()

# Map API module names → (step key, display label)
_MODULE_META: dict[str, tuple[str, str]] = {
    "dns": ("dns", "DNS & Reachability"),
    "dns_enum": ("dns_enum", "DNS Record Enumeration"),
    "headers": ("headers", "HTTP Security Headers"),
    "sslyze": ("ssl", "SSL/TLS Assessment"),
    "nuclei": ("nuclei", "Vulnerability Scan (Nuclei)"),
    "nikto": ("nikto", "Web Server Scan (Nikto)"),
    "zap": ("zap", "ZAP Active Scan"),
    "testssl": ("testssl", "TestSSL Assessment"),
    "sqlmap": ("sqlmap", "SQL Injection Scan (SQLMap)"),
    "wapiti": ("wapiti", "Web Application Audit (Wapiti)"),
    "xsstrike": ("xss", "XSS Detection (XSStrike)"),
}

_SEV_BADGE = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH": "🟠 HIGH",
    "MEDIUM": "🟡 MEDIUM",
    "LOW": "🔵 LOW",
    "INFO": "⚪ INFO",
}

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ── Normalisation helpers ──────────────────────────────────────────────────────


def normalise_single(result: dict) -> list[dict]:
    """Convert a single CheckResult dict into a step_results list."""
    module = result.get("module", "unknown")
    key, label = _MODULE_META.get(module, (module, module.capitalize()))
    return [{**result, "_step": key, "_label": label}]


def normalise_full_scan(scan: dict) -> list[dict]:
    """Convert a full ScanResponse dict (with .results[]) into a step_results list."""
    out = []
    for r in scan.get("results", []):
        module = r.get("module", "unknown")
        key, label = _MODULE_META.get(module, (module, module.capitalize()))
        out.append({**r, "_step": key, "_label": label})
    return out


# ── Public save entry-point ───────────────────────────────────────────────────


def save_report(url: str, step_results: list[dict], scan_type: str = "check") -> Path:
    """Generate a Markdown report and save it to outputs/.

    Returns the Path of the written file.
    """
    content = generate_markdown_report(url, step_results, scan_type=scan_type)

    outputs_dir = Path("outputs")
    outputs_dir.mkdir(exist_ok=True)

    safe_host = re.sub(r"[^\w.-]", "_", url.removeprefix("https://").removeprefix("http://"))
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    filename = outputs_dir / f"report_{scan_type}_{safe_host}_{timestamp}.md"

    filename.write_text(content, encoding="utf-8")
    console.print(f"\n[bold green]📄 Report saved:[/bold green] [cyan]{filename}[/cyan]")
    return filename


# ── Report generator ──────────────────────────────────────────────────────────


def generate_markdown_report(
    url: str, step_results: list[dict], *, scan_type: str = "check"
) -> str:
    """Build a full Markdown security report from any step_results list."""
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: list[str] = []

    # ── Header ───────────────────────────────────────────────────────────────
    type_label = {
        "check": "Complete Security Check",
        "full": "Full Multi-Module Scan",
        "quick": "Quick DNS Scan",
        "ssl": "SSL/TLS Assessment",
        "nuclei": "Nuclei Vulnerability Scan",
        "nikto": "Nikto Web Server Scan",
        "headers": "HTTP Security Headers Scan",
        "dns": "DNS Enumeration",
    }.get(scan_type, scan_type.capitalize())

    lines += [
        "# 🔒 Web-Check Security Report",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Scan Type** | {type_label} |",
        f"| **Target** | {url} |",
        f"| **Date** | {now} |",
        f"| **Steps** | {' → '.join(r.get('_label', '?') for r in step_results)} |",
        "",
        "---",
        "",
    ]

    # ── Executive summary ────────────────────────────────────────────────────
    all_findings = _collect_findings(step_results)
    sev_counts: dict[str, int] = {}
    for f in all_findings:
        s = (f.get("severity") or "info").upper()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    total = len(all_findings)
    risk = (
        "✅ Clean"
        if total == 0
        else "🔴 Critical"
        if sev_counts.get("CRITICAL")
        else "🟠 High"
        if sev_counts.get("HIGH")
        else "🟡 Medium"
        if sev_counts.get("MEDIUM")
        else "🔵 Low"
        if sev_counts.get("LOW")
        else "⚪ Informational"
    )

    lines += [
        "## Executive Summary",
        "",
        f"**Overall Risk:** {risk}  ",
        f"**Total Findings:** {total}  ",
        "",
    ]
    if total:
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            n = sev_counts.get(sev, 0)
            if n:
                lines.append(f"- {_SEV_BADGE[sev]}: **{n}**")
        lines.append("")

    # ── Scan summary table ────────────────────────────────────────────────────
    lines += [
        "## Scan Summary",
        "",
        "| Step | Status | Duration | Findings | Details |",
        "|------|:------:|:--------:|:--------:|---------|",
    ]
    for r in step_results:
        status = r.get("status", "?")
        findings = r.get("findings", [])
        detail = _step_detail(r) or (r.get("error", "") if status != "success" else "—")
        icon = "✅" if status == "success" else ("⏱" if status == "timeout" else "❌")
        lines.append(
            f"| {r.get('_label', '?')} | {icon} {status} "
            f"| {_fmt_dur(r.get('duration_ms', 0))} "
            f"| {len(findings)} "
            f"| {detail} |"
        )

    lines += ["", "---", ""]

    # ── Per-step details ──────────────────────────────────────────────────────
    lines += ["## Step Details", ""]
    for r in step_results:
        key = r.get("_step", "")
        label = r.get("_label", "")
        data = r.get("data") or {}
        status = r.get("status", "unknown")
        err = r.get("error")

        lines += [f"### {label}", ""]

        if err and status != "success":
            lines += [f"> ❌ **Error:** {err}", ""]
            continue

        if key == "dns" and data:
            lines += _prop_table(
                [
                    ("Domain", f"`{data.get('domain', 'N/A')}`"),
                    ("Resolvable", "✅ Yes" if data.get("resolvable") else "❌ No"),
                    ("HTTP Status", f"`{data.get('http_status', 'N/A')}`"),
                ]
            )
        elif key == "dns_enum" and data:
            records = data.get("records") or {}
            lines += _prop_table(
                [
                    ("Domain", f"`{data.get('domain', 'N/A')}`"),
                    ("A Records", ", ".join(f"`{v}`" for v in records.get("A", [])) or "—"),
                    ("AAAA Records", ", ".join(f"`{v}`" for v in records.get("AAAA", [])) or "—"),
                    ("MX Records", ", ".join(f"`{v}`" for v in records.get("MX", [])) or "—"),
                    ("NS Records", ", ".join(f"`{v}`" for v in records.get("NS", [])) or "—"),
                    ("SPF", "✅ Present" if data.get("spf") else "❌ Missing"),
                    ("DMARC", "✅ Present" if data.get("dmarc") else "❌ Missing"),
                    ("DKIM", "✅ Found" if data.get("dkim_found") else "❌ Not found"),
                ]
            )
            # Show TXT records if any
            txt = records.get("TXT", [])
            if txt:
                lines += ["**TXT Records:**", ""]
                for t in txt:
                    lines.append(f"- `{t}`")
                lines.append("")
        elif key == "headers" and data:
            present = data.get("headers_present") or []
            missing = data.get("headers_missing") or []
            lines += _prop_table(
                [
                    ("Status Code", f"`{data.get('status_code', 'N/A')}`"),
                    ("Headers Present", f"`{len(present)}`"),
                    ("Headers Missing", f"`{len(missing)}`"),
                    ("Server", f"`{data.get('server', '—')}`" if data.get("server") else "—"),
                    (
                        "X-Powered-By",
                        f"`{data.get('x_powered_by', '—')}`" if data.get("x_powered_by") else "—",
                    ),
                ]
            )
            if present:
                lines += ["**Security Headers Present:**", ""]
                for h in present:
                    lines.append(f"- ✅ `{h}`")
                lines.append("")
            if missing:
                lines += ["**Security Headers Missing:**", ""]
                for h in missing:
                    lines.append(f"- ❌ `{h}`")
                lines.append("")
        elif key == "ssl" and data:
            lines += _prop_table(
                [
                    ("Hostname", f"`{data.get('hostname', 'N/A')}`"),
                    ("Port", f"`{data.get('port', 443)}`"),
                    ("Protocol/Cipher Issues", f"`{len(r.get('findings', []))}`"),
                ]
            )
        elif key == "nuclei" and data:
            lines += _prop_table(
                [
                    ("Templates Matched", f"`{data.get('templates_matched', 0)}`"),
                    ("Duration", f"`{_fmt_dur(r.get('duration_ms', 0))}`"),
                ]
            )
        elif key == "nikto" and data:
            lines += _prop_table(
                [
                    ("Issues Detected", f"`{data.get('findings_count', 0)}`"),
                    ("Duration", f"`{_fmt_dur(r.get('duration_ms', 0))}`"),
                ]
            )
        elif key == "zap" and data:
            lines += _prop_table(
                [
                    ("Alerts", f"`{data.get('alerts_count', len(r.get('findings', [])))}`"),
                    ("Duration", f"`{_fmt_dur(r.get('duration_ms', 0))}`"),
                ]
            )
        else:
            # Generic fallback for other modules
            rows = [(k, f"`{v}`") for k, v in data.items() if not isinstance(v, (dict, list))]
            if rows:
                lines += _prop_table(rows)
            else:
                lines += [f"- **Status:** {status}", ""]

    lines += ["---", ""]

    # ── Findings overview table ───────────────────────────────────────────────
    lines += [f"## Findings ({total} total)", ""]

    if not all_findings:
        lines += ["✅ **No security findings detected.**", ""]
    else:
        lines += [
            "| # | Severity | Scanner | Title | CVE | CVSS |",
            "|:-:|----------|---------|-------|:---:|:----:|",
        ]
        for i, f in enumerate(all_findings, 1):
            sev = (f.get("severity") or "unknown").upper()
            badge = _SEV_BADGE.get(sev, sev)
            cve = f"`{f['cve']}`" if f.get("cve") else "—"
            cvss = f"`{f['cvss_score']:.1f}`" if f.get("cvss_score") is not None else "—"
            title = f.get("title", "N/A").replace("|", "\\|")
            step = f.get("_step_label", "")
            lines.append(f"| {i} | {badge} | {step} | {title} | {cve} | {cvss} |")

        lines += [""]

        # ── Detail block for every single finding ─────────────────────────────
        lines += ["---", "", "## Finding Details", ""]

        grouped: dict[str, list[dict]] = {}
        for f in all_findings:
            grouped.setdefault(f.get("_step_label", "Unknown"), []).append(f)

        idx = 1
        for step_label, step_findings in grouped.items():
            lines += [f"### {step_label}", ""]
            step_findings.sort(
                key=lambda x: _SEV_ORDER.get((x.get("severity") or "info").upper(), 99)
            )

            for f in step_findings:
                sev = (f.get("severity") or "info").upper()
                badge = _SEV_BADGE.get(sev, sev)
                title = f.get("title", "N/A")
                desc = (f.get("description") or "").strip()
                ref = f.get("reference") or ""
                cve = f.get("cve") or ""
                cvss = f.get("cvss_score")

                lines += [f"#### [{idx}] {title}", "", f"**Severity:** {badge}  "]

                if cve:
                    lines.append(f"**CVE / ID:** `{cve}`  ")
                if cvss is not None:
                    lines.append(f"**CVSS Score:** `{cvss:.1f}`  ")

                lines.append("")

                if desc:
                    lines += ["**Description:**", "", f"> {desc}", ""]

                if ref and ref != "https://cirt.net/nikto2":
                    lines += [f"**Reference:** [{ref}]({ref})", ""]
                elif ref:
                    lines += [f"**Reference:** {ref}", ""]

                lines += ["---", ""]
                idx += 1

    # ── Recommendations ───────────────────────────────────────────────────────
    recs = _generate_recommendations(all_findings)
    if recs:
        lines += ["", "---", "", "## 🛡️ Recommendations", ""]
        lines += [
            "_Prioritised actions based on findings:_",
            "",
            "| Priority | Category | Action |",
            "|:--------:|----------|--------|",
        ]
        for priority, category, action in recs:
            lines.append(f"| {priority} | {category} | {action} |")
        lines.append("")

    lines += ["", "---", "", "*Generated by Web-Check CLI*", ""]
    return "\n".join(lines)


# ── Internal helpers ──────────────────────────────────────────────────────────


def _collect_findings(step_results: list[dict]) -> list[dict]:
    """Flatten findings from all steps, tagging each with _step_label."""
    out = []
    for r in step_results:
        label = r.get("_label", r.get("_step", "?"))
        for f in r.get("findings", []):
            out.append({**f, "_step_label": label})
    return out


def _prop_table(rows: list[tuple[str, str]]) -> list[str]:
    """Render a simple 2-column property table."""
    lines = ["| Property | Value |", "|----------|-------|"]
    for k, v in rows:
        lines.append(f"| {k} | {v} |")
    lines.append("")
    return lines


def _step_detail(r: dict) -> str:
    """One-line detail hint for the summary table."""
    key = r.get("_step", "")
    data = r.get("data") or {}
    if key == "dns":
        code = data.get("http_status")
        return (
            f"HTTP {code}" if code else ("resolvable" if data.get("resolvable") else "unresolvable")
        )
    if key == "dns_enum":
        types = list(data.get("records", {}).keys())
        return f"{len(types)} record type(s)" if types else "no records"
    if key == "headers":
        missing = len(data.get("headers_missing") or [])
        present = len(data.get("headers_present") or [])
        return f"{present} present, {missing} missing"
    if key == "ssl":
        host = data.get("hostname", "")
        port = data.get("port", 443)
        return f"{host}:{port}" if host else ""
    if key == "nuclei":
        n = data.get("templates_matched", 0)
        return f"{n} template(s) matched" if n else ""
    if key == "nikto":
        n = data.get("findings_count", 0)
        return f"{n} issue(s) detected" if n else ""
    if key == "zap":
        n = data.get("alerts_count", len(r.get("findings", [])))
        return f"{n} alert(s)" if n else ""
    # Generic
    return ", ".join(f"{k}={v}" for k, v in data.items() if not isinstance(v, (dict, list)))[:60]


def _fmt_dur(ms: int) -> str:
    """Format milliseconds as human-readable duration."""
    if ms < 1000:
        return f"{ms}ms"
    secs = ms / 1000
    if secs < 60:
        return f"{secs:.1f}s"
    mins = int(secs // 60)
    return f"{mins}m{secs % 60:.0f}s"


# ── Recommendations engine ────────────────────────────────────────────────────

# Maps title keywords → (priority emoji, category, recommendation text)
_RECOMMENDATION_RULES: list[tuple[str, str, str, str]] = [
    # keyword in title (lowercase)        priority  category           action
    ("zone transfer", "🔴 P1", "DNS", "Restrict AXFR to authorised secondaries only"),
    (
        "spf record uses +all",
        "🔴 P1",
        "Email Security",
        "Change SPF `+all` to `-all` or `~all` immediately",
    ),
    (
        "credentials allowed with wildcard",
        "🔴 P1",
        "CORS",
        "Remove Allow-Credentials or restrict Allow-Origin to specific domains",
    ),
    ("sql injection", "🔴 P1", "Injection", "Sanitise all user inputs; use parameterised queries"),
    ("xss", "🔴 P1", "Injection", "Implement output encoding and a strict CSP"),
    (
        "remote code execution",
        "🔴 P1",
        "RCE",
        "Patch immediately and review server-side input handling",
    ),
    ("heartbleed", "🔴 P1", "SSL/TLS", "Upgrade OpenSSL and rotate all certificates/keys"),
    ("ssl 2.0", "🟠 P2", "SSL/TLS", "Disable SSLv2 — it is broken and deprecated"),
    ("ssl 3.0", "🟠 P2", "SSL/TLS", "Disable SSLv3 — vulnerable to POODLE attack"),
    ("tls 1.0", "🟠 P2", "SSL/TLS", "Disable TLS 1.0; use TLS 1.2+ only"),
    ("tls 1.1", "🟠 P2", "SSL/TLS", "Disable TLS 1.1; use TLS 1.2+ only"),
    (
        "content security policy",
        "🟠 P2",
        "Headers",
        "Define a strict Content-Security-Policy header",
    ),
    (
        "strict-transport-security",
        "🟠 P2",
        "Headers",
        "Enable HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    (
        "hsts",
        "🟠 P2",
        "Headers",
        "Enable HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    ("x-frame-options", "🟠 P2", "Headers", "Add X-Frame-Options: DENY to prevent clickjacking"),
    ("multiple spf", "🟠 P2", "Email Security", "Consolidate into a single SPF TXT record"),
    ("no spf", "🟠 P2", "Email Security", "Add an SPF TXT record to prevent email spoofing"),
    ("no dmarc", "🟠 P2", "Email Security", "Add a DMARC record at _dmarc.yourdomain.com"),
    ("wildcard access-control", "🟠 P2", "CORS", "Restrict CORS to specific trusted origins"),
    ("cookie missing secure", "🟠 P2", "Cookies", "Set the Secure flag on all cookies"),
    (
        "cookie missing httponly",
        "🟠 P2",
        "Cookies",
        "Set the HttpOnly flag on all cookies to prevent XSS theft",
    ),
    ("x-content-type-options", "🔵 P3", "Headers", "Add X-Content-Type-Options: nosniff"),
    ("referrer-policy", "🔵 P3", "Headers", "Add Referrer-Policy: strict-origin-when-cross-origin"),
    (
        "dmarc policy set to none",
        "🔵 P3",
        "Email Security",
        "Upgrade DMARC policy from p=none to p=quarantine or p=reject",
    ),
    ("no dkim", "🔵 P3", "Email Security", "Configure DKIM signing and publish your public key"),
    (
        "cookie missing samesite",
        "🔵 P3",
        "Cookies",
        "Add SameSite=Strict or SameSite=Lax to cookies",
    ),
    ("server version", "⚪ P4", "Info Disclosure", "Suppress or genericise the Server header"),
    ("x-powered-by", "⚪ P4", "Info Disclosure", "Remove the X-Powered-By header"),
    (
        "permissions-policy",
        "⚪ P4",
        "Headers",
        "Add a Permissions-Policy header to restrict browser features",
    ),
    (
        "cache-control",
        "⚪ P4",
        "Headers",
        "Set Cache-Control: no-store for sensitive/authenticated pages",
    ),
]


def _generate_recommendations(findings: list[dict]) -> list[tuple[str, str, str]]:
    """Derive deduplicated, prioritised recommendations from findings.

    Returns a list of (priority, category, action) tuples.
    """
    seen: set[str] = set()
    results: list[tuple[str, str, str]] = []

    for finding in findings:
        title_lower = (finding.get("title") or "").lower()
        # Also check remediation field if present
        remediation = (finding.get("remediation") or "").strip()

        for keyword, priority, category, action in _RECOMMENDATION_RULES:
            if keyword in title_lower and action not in seen:
                seen.add(action)
                results.append((priority, category, action))
                break  # One rule per finding
        else:
            # No rule matched — use remediation text from the finding itself if available
            if remediation and remediation not in seen:
                sev = (finding.get("severity") or "info").upper()
                priority_map = {
                    "CRITICAL": "🔴 P1",
                    "HIGH": "🟠 P2",
                    "MEDIUM": "🟠 P2",
                    "LOW": "🔵 P3",
                    "INFO": "⚪ P4",
                }
                p = priority_map.get(sev, "⚪ P4")
                cat = finding.get("_step_label", "General")
                seen.add(remediation)
                results.append((p, cat, remediation))

    # Sort: P1 → P4
    _order = {"🔴 P1": 0, "🟠 P2": 1, "🔵 P3": 2, "⚪ P4": 3}
    results.sort(key=lambda x: _order.get(x[0], 9))
    return results
