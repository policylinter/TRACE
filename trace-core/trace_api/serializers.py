"""Model -> API (camelCase) serialisation.

The React client consumes the exact shape declared in ``src/data/findings.ts``,
so serialisation is explicit rather than generic: no field is accidentally
renamed by a config change.
"""

from __future__ import annotations

from typing import Any
from datetime import datetime, timezone

from .models import Finding, Project, Scan, TriageEvent


def _iso(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value,datetime) and value.tzinfo is None:
        value=value.replace(tzinfo=timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


def serialize_project(project: Project, scans: list[Scan] | None = None) -> dict[str, Any]:
    items = list(scans) if scans is not None else list(project.scans)
    last = max((s.scanned_at for s in items), default=None)
    return {
        "id": project.id,
        "workspaceId": project.workspace_id,
        "name": project.name,
        "repoUrl": project.repo_url,
        "createdAt": _iso(project.created_at),
        "updatedAt": _iso(project.updated_at),
        "scanCount": len(items),
        "lastScanAt": _iso(last),
    }


def serialize_event(event: TriageEvent, finding: Finding | None = None) -> dict[str, Any]:
    return {
        "id": event.id,
        "findingId": event.finding_id,
        "action": event.action,
        "actor": event.actor,
        "detail": event.detail,
        "createdAt": _iso(event.created_at),
        "cve": finding.cve if finding else None,
        "packageName": finding.package_name if finding else None,
    }


def serialize_finding(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "cve": finding.cve,
        "packageName": finding.package_name,
        "version": finding.version,
        "ecosystem": finding.ecosystem,
        "rawCount": finding.raw_count,
        "severity": finding.severity,
        "cvss": finding.cvss,
        "reachability": finding.reachability,
        "verdict": finding.verdict,
        "usage": finding.usage or "unknown",
        "confidence": finding.confidence,
        "cwe": finding.cwe or [],
        "fixedIn": finding.fixed_in,
        "dependencyPath": finding.dependency_path or [],
        "frames": finding.frames or [],
        "blocker": finding.blocker,
        "suppressReason": finding.suppress_reason,
        "evidence": finding.evidence or {},
        "reviewed": finding.reviewed,
        "assignee": finding.assignee or "",
        "workflowStatus": finding.workflow_status or "new",
        "dueDate": finding.due_date or "",
        "triageNote": finding.triage_note or "",
    }


def _count(findings: list[Finding]) -> dict[str, Any]:
    actionable = [f for f in findings if f.reachability == "reachable" and f.verdict == "affected"]
    raw_total = sum(f.raw_count for f in findings)
    return {
        "total": len(findings),
        "reachable": sum(1 for f in findings if f.reachability == "reachable"),
        "unreachable": sum(1 for f in findings if f.reachability == "unreachable"),
        "unknown": sum(1 for f in findings if f.reachability == "unknown"),
        "suppressed": sum(1 for f in findings if f.reachability == "suppressed"),
        "actionable": len(actionable),
        "affected": sum(1 for f in findings if f.verdict == "affected"),
        "notAffected": sum(1 for f in findings if f.verdict == "not_affected"),
        "needsReview": sum(1 for f in findings if f.verdict == "needs_review"),
        "reviewed": sum(1 for f in findings if f.reviewed),
        "usageImported": sum(1 for f in findings if (f.usage or "unknown") == "imported"),
        "usageAbsent": sum(1 for f in findings if (f.usage or "unknown") == "absent"),
        "rawTotal": raw_total,
    }


def funnel_stages(scan: Scan, findings: list[Finding]) -> list[dict[str, Any]]:
    c = _count(findings)
    return [
        {
            "key": "raw",
            "label": "Raw findings ingested",
            "value": scan.raw_count,
            "engine": "Trivy · Grype · OSV-Scanner",
            "operation": "Filesystem, dependency and SBOM matchers, no dedup",
        },
        {
            "key": "packages",
            "label": "Unique package groups",
            "value": c["total"],
            "engine": "TRACE indexer",
            "operation": "Collapse on (package, version, CVE) + SHA-256 artifact prefix",
        },
        {
            "key": "reachable",
            "label": "Reachable in call graph",
            "value": c["reachable"],
            "engine": "Semgrep taint",
            "operation": "Bounded Python AST observations; no dataflow or exploitation verification" if any(f.evidence.get("nativeObservations") for f in findings) else "Symbol reachability from Semgrep taint evidence; no evidence → needs review",
        },
        {
            "key": "exploitable",
            "label": "Contextually exploitable",
            "value": c["actionable"],
            "engine": scan.ai_engine,
            "operation": "Local inference: taint survives to sink with no sanitiser",
        },
    ]


def serialize_scan(scan: Scan) -> dict[str, Any]:
    findings = list(scan.findings)
    return {
        "id": scan.id,
        "workspaceId": scan.workspace_id,
        "projectId": scan.project_id,
        "repository": scan.repository,
        "branch": scan.branch,
        "commit": scan.commit_short,
        "commitLong": scan.commit_long,
        "pipeline": scan.pipeline,
        "triggeredBy": scan.triggered_by,
        "sbom": scan.sbom,
        "duration": scan.duration,
        "status": scan.status,
        "scannedAt": _iso(scan.scanned_at),
        "rawCount": scan.raw_count,
        "engines": scan.engines or [],
        "scannerResults": scan.scanner_results or [],
        "aiRuntime": scan.ai_runtime or {},
        "aiEngine": scan.ai_engine,
        "profile": scan.profile,
        "counts": _count(findings),
        "funnel": funnel_stages(scan, findings),
    }
