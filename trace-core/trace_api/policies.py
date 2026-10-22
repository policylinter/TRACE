"""Policy evaluation & CI gate.

Small deterministic engine (no model, no DB) that answers the only question CI
cares about: does this scan clear the release bar? It is evaluated against the
persisted policy (``app_settings['policy']``); every active finding produces a
machine-readable decision so the gate output doubles as an audit report.

Policy shape (see :func:`default_policy`):

- ``blockOn`` — severities that fail the gate when affected+reachable;
- ``exemptions`` — a CVE allowlist that downgrades a block to a warning;
- ``warnOnReview`` — surface reachable-but-unverified findings as warnings.
"""

from __future__ import annotations

from typing import Any

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


def default_policy() -> dict[str, Any]:
    return {
        "name": "TRACE-OS-BASE",
        "defaultAction": "block",
        "blockOn": ["critical", "high"],
        "exemptions": [],
        "warnOnReview": True,
    }


def _rule(finding: dict[str, Any], decision: str, reason: str) -> dict[str, Any]:
    return {
        "cve": str(finding.get("cve") or "").upper(),
        "packageName": finding.get("packageName", ""),
        "severity": str(finding.get("severity") or "unknown").lower(),
        "decision": decision,
        "reason": reason,
    }


def _decide(finding: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    cve = str(finding.get("cve") or "").upper()
    severity = str(finding.get("severity") or "unknown").lower()
    verdict = str(finding.get("verdict") or "")
    reachability = str(finding.get("reachability") or "")
    block_on = {str(s) for s in (policy.get("blockOn") or [])}
    exemptions = {(str(e) or "").upper() for e in (policy.get("exemptions") or [])}

    if verdict == "affected" and reachability == "reachable":
        if cve in exemptions:
            return _rule(finding, "warn", f"{cve} exempted by policy")
        if severity in block_on:
            return _rule(finding, "fail", f"{severity} affected and reachable — blocks the gate")
        return _rule(finding, "warn", f"{severity} affected and reachable — below the block bar")
    if verdict == "needs_review" and reachability == "reachable" and policy.get("warnOnReview", True):
        return _rule(finding, "warn", "reachable but unverified — review and pin the verdict")
    return _rule(finding, "pass", "not blocking")


def evaluate_policy(
    scan_id: str,
    findings: list[dict[str, Any]],
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate every finding against the policy. Stdlib-only, no I/O."""
    policy = dict(policy or default_policy())
    rules = [_decide(f, policy) for f in findings]
    order = {"fail": 0, "warn": 1, "pass": 2}
    rules.sort(key=lambda r: (order.get(r["decision"], 3), r.get("severity", "")))

    blocking = [r for r in rules if r["decision"] == "fail"]
    warnings = [r for r in rules if r["decision"] == "warn"]
    passed = sum(1 for r in rules if r["decision"] == "pass")
    return {
        "scanId": scan_id,
        "policy": policy,
        "gate": "blocked" if blocking else "passed",
        "exitCode": 1 if blocking else 0,
        "summary": {
            "blocking": len(blocking),
            "warnings": len(warnings),
            "passed": passed,
            "total": len(findings),
        },
        "rules": rules,
        "blocking": [
            {"cve": r["cve"], "packageName": r["packageName"], "severity": r["severity"]}
            for r in blocking
        ],
    }