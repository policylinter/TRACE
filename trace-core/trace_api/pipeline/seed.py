"""Bundled demo dataset.

Loading this gives a fresh TRACE install a complete, realistic scan so the UI
is never empty. The data originates from ``src/data/findings.ts`` and is
exported by ``trace-frontend/scripts/export-seed.mjs``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Finding, Project, Scan

SEED_PATH = Path(__file__).resolve().parent.parent / "seed" / "seed.json"
DEMO_SCAN_ID = "scan-8f21a3c"
DEFAULT_PROJECT_ID = 1


def load_seed() -> dict:
    return json.loads(SEED_PATH.read_text(encoding="utf-8"))


def _parse_dt(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def ensure_default_project(db: Session) -> Project:
    """Guarantee the default workspace (id=1) and adopt any orphan scans.

    Older installs predate multi-project support: their scans have a NULL
    ``project_id``. Moving them under the default project keeps the demo/seed
    data isolated without destroying history.
    """
    project = db.get(Project, DEFAULT_PROJECT_ID)
    if project is None:
        project = Project(id=DEFAULT_PROJECT_ID, name="Default workspace", repo_url="")
        db.add(project)
        db.commit()
        db.refresh(project)

    orphans = db.execute(select(Scan).where(Scan.project_id.is_(None))).scalars().all()
    if orphans:
        for scan in orphans:
            scan.project_id = project.id
        db.commit()
    return project


def ensure_demo_scan(db: Session) -> Scan:
    existing = db.get(Scan, DEMO_SCAN_ID)
    if existing is not None:
        return existing

    ensure_default_project(db)
    seed = load_seed()
    meta = seed["scanMeta"]
    ai = seed["aiRuntime"]
    raw_count = seed["funnelStages"][0]["value"]

    scan = Scan(
        id=DEMO_SCAN_ID,
        project_id=DEFAULT_PROJECT_ID,
        repository=meta["repository"],
        branch=meta.get("branch", "main"),
        commit_short=meta.get("commit", ""),
        commit_long=meta.get("commitLong", ""),
        pipeline=meta.get("pipeline", "trace-scan/local"),
        triggered_by=meta.get("triggeredBy", "manual"),
        sbom=meta.get("sbom", "CycloneDX"),
        duration=meta.get("duration", "0s"),
        status="completed",
        raw_count=raw_count,
        engines=seed.get("engines", []),
        ai_runtime={"model": ai.get("model"), "quantisation": ai.get("quantisation"), "device": ai.get("device"), "egress": ai.get("egress", "0 bytes"), "host": ai.get("host")},
        ai_engine=ai.get("model", "rules"),
        profile="prod-eu-1",
        scanned_at=_parse_dt(meta.get("scannedAt", "")),
    )

    for item in seed["findings"]:
        scan.findings.append(_to_finding(item, scan.id))

    db.add(scan)
    db.commit()
    return scan


def _to_finding(item: dict, scan_id: str) -> Finding:
    return Finding(
        id=item["id"],
        scan_id=scan_id,
        cve=item["cve"],
        package_name=item["packageName"],
        version=item.get("version", ""),
        ecosystem=item.get("ecosystem", "maven"),
        raw_count=item.get("rawCount", 1),
        severity=item["severity"],
        cvss=float(item.get("cvss", 0.0)),
        reachability=item["reachability"],
        verdict=item["verdict"],
        confidence=float(item.get("confidence", 0.0)),
        cwe=item.get("cwe", []),
        fixed_in=item.get("fixedIn", ""),
        dependency_path=item.get("dependencyPath", []),
        frames=item.get("frames", []),
        evidence=item.get("evidence", {}),
        blocker=item.get("blocker"),
        suppress_reason=item.get("suppressReason"),
        reviewed=False,
    )
