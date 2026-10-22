"""Compliance reporting for scans.

Generates a deterministic, offline Markdown/HTML evidence report for a finished
scan against a chosen reference standard. The mapping is control -> finding
predicate (severity/verdict), so the output is reproducible for any scan and
never requires a network round-trip. Politeness: the report never claims an
audit outcome, it only lists what TRACE observed.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any

STANDARDS: list[dict[str, Any]] = [
    {
        "id": "pci-dss-4.0",
        "name": "PCI DSS 4.0",
        "basis": "Requirement 6 genuine vulnerabilities and critical alerts are addressed.",
        "controls": [
            {"id": "6.3.3", "name": "Vulnerabilities managed, fixed or risk-accepted", "severity": "high"},
            {"id": "6.2.3", "name": "Critical alerts addressed in timeframes", "severity": "critical"},
            {"id": "10.2.7", "name": "Knowledge of system state (evidence kept)", "severity": "low"},
        ],
    },
    {
        "id": "iso-27001",
        "name": "ISO/IEC 27001:2022",
        "basis": "Annex A.8.8 technical vulnerability management.",
        "controls": [
            {"id": "A.8.8", "name": "Technical vulnerability management", "severity": "high"},
            {"id": "A.8.25", "name": "Secure development life cycle", "severity": "medium"},
            {"id": "A.5.8", "name": "Information security event evidence", "severity": "low"},
        ],
    },
    {
        "id": "nist-800-53",
        "name": "NIST SP 800-53 Rev.5",
        "basis": "RA-5 vulnerability monitoring and scanning.",
        "controls": [
            {"id": "RA-5", "name": "Vulnerability monitoring and scanning", "severity": "high"},
            {"id": "SI-2", "name": "Flaw remediation", "severity": "high"},
            {"id": "CM-8", "name": "System component inventory and SBOM", "severity": "medium"},
        ],
    },
    {
        "id": "soc-2-cc",
        "name": "SOC 2 (CC7/CC8)",
        "basis": "CC7.2 system components monitored for anomalies.",
        "controls": [
            {"id": "CC7.2", "name": "Monitor system components for anomalies", "severity": "high"},
            {"id": "CC8.1", "name": "Changes evaluated for risk to controls", "severity": "medium"},
        ],
    },
]


def _iso(scan: Any) -> str:
    ts = scan.scanned_at
    if ts is None:
        return ""
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _standard(standard_id: str) -> dict[str, Any]:
    found = next((s for s in STANDARDS if s["id"] == standard_id), None)
    if found is None:
        raise ValueError(f"unknown standard: {standard_id}")
    return found


def _affected(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [f for f in findings if f.get("verdict") == "affected" and f.get("reachability") == "reachable"]


def _gap_count(standard: dict[str, Any], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    affected = _affected(findings)
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    rows = []
    for control in standard["controls"]:
        gap = [f for f in affected if order.get(str(f.get("severity")).lower(), 0) >= order.get(control["severity"], 0)]
        open_count = len(gap)
        rows.append(
            {
                "control": control["id"],
                "requirement": control["name"],
                "status": "open" if open_count else "ok",
                "count": open_count,
                "examples": [f"{f.get('cve') or f.get('packageName')} [{f.get('severity')}]" for f in gap[:8]],
            }
        )
    return rows


def _remediation(findings: list[dict[str, Any]]) -> list[str]:
    affected = _affected(findings)
    steps: list[str] = []
    fixed = sorted({f.get("fixedIn") for f in affected if f.get("fixedIn")})
    if fixed:
        steps.append("Upgrade fixed releases tracked for: " + ", ".join(fixed) + ".")
    cvss = [f for f in affected if f.get("severity") == "critical"]
    if cvss:
        steps.append(f"{len(cvss)} critical finding(s) — Level A within 48h or blast-radius reduction.")
    steps.append("Pin the risk decision per finding via VEX (triage) to remove needs_review noise.")
    steps.append("Re-run the release gate: POST /api/v1/scans/{scan_id}/gate until exit code 0.")
    return steps


def _finding_row(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve": finding.get("cve") or "-",
        "package": finding.get("packageName"),
        "version": finding.get("version"),
        "severity": finding.get("severity"),
        "reachability": finding.get("reachability"),
        "verdict": finding.get("verdict"),
        "confidence": finding.get("confidence"),
        "fixedIn": finding.get("fixedIn") or "-",
    }


def _engines(scan: Any) -> str:
    engines = scan.engines or ["trivy", "semgrep"]
    return ", ".join(str(e.get("name") or e) if isinstance(e, dict) else str(e) for e in engines)


def report_markdown(scan: Any, findings: list[dict[str, Any]], standard_id: str) -> str:
    standard = _standard(standard_id)
    affected = _affected(findings)
    rows = _gap_count(standard, findings)
    open_rows = [r for r in rows if r["status"] == "open"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: list[str] = [
        f"# Compliance report — {scan.repository}",
        "",
        f"**Standard:** {standard['name']} · **Based on:** {standard['basis']}",
        "",
        "| | |",
        "|---|---|",
        f"| Commit | `{scan.commit_short}` {scan.branch} |",
        f"| Scanned | {_iso(scan)} |",
        f"| Engines | {_engines(scan)} |",
        f"| Generated | {now} (local, offline) |",
        "",
        "## Summary",
        "",
        f"- Findings: **{len(findings)}**",
        f"- Affected (reachable + verified): **{len(affected)}**",
        f"- Controls challenged: **{len(open_rows)}** / **{len(rows) - len(open_rows)}** ok",
        "",
        "## Affected findings",
        "",
        "| Package | Version | CVE | Severity | Verdict | Confidence | Fixed in |",
        "|---|---|---|---|---|---|---|",
    ]
    for f in find_findings_affected(affected):
        lines.append(
            "| " + " | ".join(
                [
                    html.escape(str(f["package"])),
                    html.escape(str(f["version"])),
                    html.escape(str(f["cve"])),
                    str(f["severity"]),
                    str(f["verdict"]),
                    str(f.get("confidence", "")),
                    html.escape(str(f.get("fixedIn") or "-")),
                ]
            ) + " |"
        )
    lines += [
        "",
        "## Control assessment",
        "",
        "| Control | Requirement | Status | Evidence |",
        "|---|---|---|---|",
    ]
    for row in rows:
        evidence = ", ".join(row["examples"]) if row["examples"] else "—"
        lines.append(
            f"| {row['control']} | {html.escape(row['requirement'])} | {'OPEN' if row['status'] == 'open' else 'ok'} | {html.escape(evidence)} |"
        )
    lines += ["", "## Remediation", ""]
    lines += [f"- {html.escape(step)}" for step in _remediation(findings)]
    lines.append("")
    lines.append("> Disclaimer: observed state from TRACE's scan, not a formal audit opinion.")
    return "\n".join(lines)


def find_findings_affected(affected: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [_finding_row(f) for f in affected]


def report_html(scan: Any, findings: list[dict[str, Any]], standard_id: str) -> str:
    md = report_markdown(scan, findings, standard_id)
    standard = _standard(standard_id)
    esc = html.escape
    md_escaped = esc(md)
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        f"<title>Compliance — {esc(scan.repository)}</title>"
        "<style>"
        "body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:960px;margin:40px auto;color:#1e293b;"
        "line-height:1.55;padding:0 16px}"
        "h1,h2{border-bottom:1px solid #e2e8f0;padding-bottom:8px}"
        "table{border-collapse:collapse;width:100%;font-size:13px}"
        "th,td{border:1px solid #cbd5e1;padding:6px 10px;text-align:left;vertical-align:top}"
        "pre{background:#f1f5f9;padding:12px;border-radius:8px;overflow:auto;font-size:12px}"
        "</style></head><body>"
        f"<pre>{md_escaped}</pre>"
        "<p style=\"font-size:small;color:#64748b\">Generated deterministically offline by TRACE; "
        f"standard: {esc(standard['name'])}</p>"
        "</body></html>"
    )


def build_report(scan: Any, findings: list[dict[str, Any]], standard_id: str, output_format: str) -> dict[str, Any]:
    if output_format not in ("md", "html"):
        raise ValueError("format must be md or html")
    body = report_html(scan, findings, standard_id) if output_format == "html" else report_markdown(scan, findings, standard_id)
    standard = _standard(standard_id)
    return {
        "scanId": scan.id,
        "repository": scan.repository,
        "standard": standard["id"],
        "standardName": standard["name"],
        "format": output_format,
        "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "report": body,
    }