"""Scan orchestration.

Ties the pipeline together: ingest -> deduplicate -> reachability -> model
verdict -> persist. Kept framework-agnostic so it can be called from the API,
a Celery worker, or a test.
"""

from __future__ import annotations

import hashlib
import uuid
import time
from datetime import datetime, timezone
from typing import Any, Callable

from sqlalchemy.orm import Session

from .config import ENGINES, OLLAMA_MODEL
from .models import Finding, Scan
from .pipeline.ai import active_engine, active_provider, assess
from .pipeline.dedup import Candidate, deduplicate
from .pipeline.ingest import CVSS_BY_SEVERITY, parse_many
from .pipeline.reachability import analyze, ReachabilityResult
from .pipeline.usage import UsageIndex, build_usage_index, usage_for
from .settings import resolve_ai_settings


def _finding_id(scan_id: str, cve: str, package: str) -> str:
    # Scoped to the scan: findings are per-scan rows, so re-scanning the same
    # repo must not collide on the primary key.
    digest = hashlib.sha1(f"{scan_id}:{cve}:{package}".encode()).hexdigest()[:8].upper()
    return f"FND-{digest}"


_SEV_FROM_SEMGREP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def _code_candidates(
    semgrep_results: list[dict[str, Any]],
    existing: list[Candidate],
) -> list[Candidate]:
    """Surface curated SAST matches as standalone findings.

    Rules in ``pipeline/rules/*.yaml`` carry ``metadata.cve`` +
    ``metadata.package``. When no SCA record exists for that advisory, the match
    still becomes a code-level candidate — so a trivy-less (from-source) run
    yields real reachable findings instead of an empty scan.
    """
    known_cves = {c.cve.lower() for c in existing}
    out: list[Candidate] = []
    seen: set[tuple[str, str]] = set()
    for result in semgrep_results:
        extra = result.get("extra") or {}
        meta = extra.get("metadata") or {}
        cve = str(meta.get("cve") or "").strip()
        package = str(meta.get("package") or "").strip()
        if not cve or not package:
            continue
        key = (cve.lower(), package.lower())
        if key in seen or cve.lower() in known_cves:
            continue
        seen.add(key)
        sev = _SEV_FROM_SEMGREP.get(str(extra.get("severity") or "").upper(), "unknown")
        out.append(
            Candidate(
                cve=cve,
                package=package,
                version="(source)",
                ecosystem="code",
                severity=sev,
                cvss=CVSS_BY_SEVERITY.get(sev, 0.0),
                raw_count=1,
                scanners={"Semgrep"},
            )
        )
    return out


def run_scan(
    db: Session,
    *,
    repository: str,
    commit_sha: str,
    branch: str = "main",
    payloads: list[tuple[str, Any]] | None = None,
    explicit_graph: dict[str, dict[str, Any]] | None = None,
    triggered_by: str = "manual",
    profile: str = "prod-eu-1",
    project_id: int | None = None,
    ai_settings: dict[str, Any] | None = None,
    usage_index: UsageIndex | None = None,
) -> Scan:
    started = time.perf_counter()
    records, semgrep_results, scanners = parse_many(payloads or [])
    candidates = deduplicate(records)
    candidates += _code_candidates(semgrep_results, candidates)

    ai_config = resolve_ai_settings(db, ai_settings)
    ai_engine = active_engine(ai_config)
    ai_model = (ai_config.get("models") or [OLLAMA_MODEL])[0]
    provider = active_provider(ai_config)
    runtime_label = provider.runtime if provider else "local · no egress"
    short = commit_sha[:7] if commit_sha else "0000000"
    if scanners == ["TRACE Python AST"]:
        ai_engine = "TRACE Python AST"
        ai_model = "TRACE Python AST"
    if scanners == ["ZAP"]:
        ai_engine = ai_model = 'ZAP · imported report'
    if scanners == ['TRACE HTTP Baseline']:
        ai_engine = ai_model = 'TRACE HTTP Baseline'
    scan = Scan(
        id=f"scan-{short}-{uuid.uuid4().hex[:12]}",
        project_id=project_id,
        repository=repository,
        branch=branch,
        commit_short=short,
        commit_long=commit_sha,
        pipeline="trace-scan/local",
        triggered_by=triggered_by,
        sbom="SBOM не сформирован" if scanners in (["TRACE Python AST"],["ZAP"],['TRACE HTTP Baseline']) else f"CycloneDX 1.6 · {len(records)} records",
        status="completed",
        raw_count=len(records),
        engines=[{"name": name, "version": "не указана в отчёте"} for name in scanners if name != "unknown"],
        scanner_results=[{"id": name.lower(), "label": name, "role": {'ZAP':'dast','Trivy':'sca','Grype':'sca','OSV-Scanner':'sca','Semgrep':'sast','TRACE Python AST':'sast'}.get(name,'report'), "status": "imported", "detail": "Получен внешний отчёт; запуск движка не подтверждён"} for name in scanners if name != "unknown"],
        ai_runtime={
            "model": ai_model,
            "quantisation": "не определено",
            "device": "local",
            "egress": "не измерено",
            "host": "не определено",
        },
        ai_engine=ai_engine,
        profile=profile,
        scanned_at=datetime.now(timezone.utc),
    )

    seen: set[str] = set()
    for candidate in candidates:
        explicit = (explicit_graph or {}).get(f"{candidate.cve}:{candidate.package}") or (
            explicit_graph or {}
        ).get(candidate.cve)
        reached = analyze(candidate, semgrep_results, explicit)
        usage_kind, usage_hits, usage_note = usage_for(candidate, usage_index)
        reached.usage = usage_kind
        reached.usage_hits = usage_hits
        reached.usage_note = usage_note
        if candidate.web_observations:
            observations=candidate.web_observations
            baseline='TRACE HTTP Baseline' in candidate.scanners
            reached=ReachabilityResult(reachability='unknown',blocker='HTTP baseline не подтверждает эксплуатацию и полное покрытие.' if baseline else 'Импорт ZAP не подтверждает выполнение сканера TRACE или эксплуатацию.',frames=[])
            result=dict(verdict='needs_review',confidence=0.0,evidence=dict(model='TRACE HTTP Baseline' if baseline else 'ZAP · imported report',runtime='local · one GET' if baseline else 'external report',confidence=0.0,
                headline=observations[0]['title'],reasoning='\n'.join(o['description'] for o in observations),signals=[],webObservations=observations,
                remediation=list(dict.fromkeys(o['solution'] for o in observations if o['solution']))))
        elif candidate.observations:
            reached=ReachabilityResult(reachability="unknown",blocker="AST-паттерн не подтверждает недоверенный ввод, достижимость или эксплуатацию.",frames=[dict(kind="internal",symbol=candidate.cve,location=o["path"],line=o["line"],note=o["message"],vulnerable=False) for o in candidate.observations])
            result=dict(verdict="needs_review",confidence=0.0,evidence=dict(model="TRACE Python AST",runtime="local · AST only",confidence=0.0,
                headline=candidate.observations[0]["message"],reasoning="\n".join(f"{o['path']}:{o['line']} — {o['message']}" for o in candidate.observations),
                signals=[],remediation=["Проверьте происхождение входных данных и необходимость этой операции.","Примените безопасный API или явную проверку данных, затем повторите анализ."],nativeObservations=candidate.observations))
        else:
            result = assess(candidate, reached, [repository, candidate.package], profile, ai_config)

        fid = _finding_id(scan.id, candidate.cve, candidate.package)
        while fid in seen:
            fid += "X"
        seen.add(fid)

        evidence = result["evidence"]
        evidence["usage"] = usage_kind
        evidence["usageHits"] = usage_hits
        if usage_note:
            evidence["usageNote"] = usage_note

        scan.findings.append(
            Finding(
                id=fid,
                cve=candidate.cve,
                package_name=candidate.package,
                version=candidate.version,
                ecosystem=candidate.ecosystem,
                raw_count=candidate.raw_count,
                severity=candidate.severity,
                cvss=candidate.cvss,
                reachability=reached.reachability,
                verdict=result["verdict"],
                confidence=result["confidence"],
                usage=usage_kind,
                cwe=[],
                fixed_in=", ".join(sorted(candidate.fixed_versions)),
                dependency_path=[repository, candidate.package],
                frames=reached.frames,
                evidence=evidence,
                blocker=reached.blocker,
            )
        )

    scan.duration = f"{time.perf_counter() - started:.2f}s"
    db.add(scan)
    db.commit()
    return scan


def scan_source(
    db: Session,
    *,
    source: str,
    ref: str | None = None,
    repository: str | None = None,
    profile: str = "prod-eu-1",
    triggered_by: str = "api",
    project_id: int | None = None,
    ai_settings: dict[str, Any] | None = None,
) -> tuple[Scan, dict[str, Any], list[str]]:
    """Fetch ``source``, run the installed scanners, and analyse the results.

    Returns ``(scan, source_meta, scanners_used)``. Missing scanners are simply
    skipped — an empty scanner fleet still yields a (finding-less) scan.
    """
    from .scanners import run_available
    from .sources import fetch

    path, meta = fetch(source, ref)
    scanner_results: list[dict[str, Any]] = []
    payloads, used, components = run_available(path, scanner_results)
    usage_index = None if used == ["TRACE Python AST"] else build_usage_index(path)

    scan = run_scan(
        db,
        repository=repository or meta.get("repository") or source,
        commit_sha=str(meta.get("commit") or ""),
        branch=meta.get("branch") or "main",
        payloads=payloads,
        triggered_by=triggered_by,
        profile=profile,
        project_id=project_id,
        ai_settings=ai_settings,
        usage_index=usage_index,
    )

    # Only claim the engines that actually ran, and the SBOM we actually built.
    scan.scanner_results = scanner_results
    scan.status = "completed" if scanner_results and all(r["status"] == "completed" for r in scanner_results) else "partial" if used else "failed"
    scan.engines = [e for e in ENGINES if e["name"] in used]
    if components:
        scan.sbom = f"CycloneDX 1.6 · {len(components)} components"
    from .job_recovery import record_receipt
    record_receipt(db, scan, used)
    db.commit()
    return scan, meta, used


def rescan(
    db: Session,
    scan: Scan,
    on_phase: Callable[[str, float, str | None], None] | None = None,
    ai_settings: dict[str, Any] | None = None,
) -> Scan:
    """Re-run the reachability + model stages over an existing scan's findings.

    Used by the UI "re-evaluate" action: the dependency set is unchanged, only
    the contextual verdicts are recomputed (e.g. after the model comes online).
    """
    from .pipeline.dedup import Candidate

    ai_config = resolve_ai_settings(db, ai_settings)
    ai_engine = active_engine(ai_config)
    if on_phase:
        on_phase("graph", 0.15, "контекст находок")
    if on_phase:
        on_phase("reachability", 0.55, "анализ достижимости")
    if on_phase:
        on_phase("ai", 0.60, "оценка находок")
    for index, finding in enumerate(scan.findings):
        if finding.evidence.get("nativeObservations") or finding.evidence.get('webObservations'):
            continue
        candidate = Candidate(
            cve=finding.cve,
            package=finding.package_name,
            version=finding.version,
            ecosystem=finding.ecosystem,
            severity=finding.severity,
            cvss=finding.cvss,
            raw_count=finding.raw_count,
        )
        explicit = {
            "reachability": finding.reachability,
            "frames": finding.frames,
            "blocker": finding.blocker,
            "taint_source": finding.evidence.get("taintSource"),
            "sink": finding.evidence.get("sink"),
            "propagation": finding.evidence.get("taintPropagation") or [],
        }
        reached = analyze(candidate, None, explicit)
        result = assess(candidate, reached, finding.dependency_path, scan.profile, ai_config)
        finding.verdict = result["verdict"]
        finding.confidence = result["confidence"]
        finding.evidence = result["evidence"]
        if on_phase and scan.findings:
            fraction = 0.60 + (0.25 * (index + 1) / len(scan.findings))
            on_phase("ai", fraction, f"оценка {index + 1}/{len(scan.findings)}")
    if on_phase:
        on_phase("ai", 0.85, "финализация")
    scan.ai_engine = "TRACE Python AST" if scan.findings and all(f.evidence.get("nativeObservations") for f in scan.findings) else ai_engine
    if scan.findings and all(f.evidence.get('webObservations') for f in scan.findings):scan.ai_engine=scan.findings[0].evidence['model']
    scan.scanned_at = datetime.now(timezone.utc)
    from .job_recovery import record_receipt
    record_receipt(db, scan, [])
    db.commit()
    if on_phase:
        on_phase("done", 1.0, "завершено")
    return scan
