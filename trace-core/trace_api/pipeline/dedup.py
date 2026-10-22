"""Deduplicate exact (ecosystem, package, version, advisory) coordinates.

Separate artifacts remain separate findings; a shared group does not prove
that packages are aliases or that their vulnerable code is interchangeable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .ingest import CVSS_BY_SEVERITY, SEVERITY_ORDER, RawRecord


@dataclass
class Candidate:
    cve: str
    package: str
    version: str
    ecosystem: str
    severity: str = "unknown"
    cvss: float = 0.0
    raw_count: int = 0
    scanners: set[str] = field(default_factory=set)
    aliases: list[str] = field(default_factory=list)
    fixed_versions: set[str] = field(default_factory=set)
    observations: list[dict] = field(default_factory=list)
    web_observations: list[dict] = field(default_factory=list)


def deduplicate(records: list[RawRecord]) -> list[Candidate]:
    groups: dict[tuple[str, str, str, str], Candidate] = {}
    for rec in records:
        if not rec.cve or not rec.package:
            continue
        key = (rec.ecosystem, rec.package, rec.version, rec.cve)
        cand = groups.get(key)
        if cand is None:
            cand = Candidate(
                cve=rec.cve,
                package=rec.package,
                version=rec.version,
                ecosystem=rec.ecosystem,
                severity=rec.severity,
                cvss=rec.cvss,
            )
            groups[key] = cand
        else:
            if SEVERITY_ORDER.get(rec.severity, 4) < SEVERITY_ORDER.get(cand.severity, 4):
                cand.severity = rec.severity
            cand.cvss = max(cand.cvss, rec.cvss)
        cand.fixed_versions.update(rec.fixed_versions)
        if rec.scanner in ('ZAP','TRACE HTTP Baseline'):
            item=rec.dataflow['web']
            if item not in cand.web_observations:cand.web_observations.append(item)
        if rec.scanner=="TRACE Python AST":
            cand.observations.append(dict(path=rec.path,line=rec.line,message=rec.message))
        cand.raw_count += 1
        cand.scanners.add(rec.scanner)

    # Artifact names in the same Maven group are not interchangeable. Keep
    # separate coordinates unless an explicit alias mapping proves identity.
    return list(groups.values())


def normalize_cvss(cand: Candidate) -> float:
    return cand.cvss or CVSS_BY_SEVERITY.get(cand.severity, 0.0)
