"""Scanner ingestion.

Normalises the raw output of the tools in the TRACE fleet (Trivy, Grype,
OSV-Scanner, Semgrep) into a single record shape. Each parser is intentionally
tolerant of unknown optional fields. Malformed recognized structures are rejected
before persistence; a filename alone never proves a valid report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
CVSS_BY_SEVERITY = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 2.0, "unknown": 0.0}


def _sev(value: str | None) -> str:
    value = (value or "unknown").strip().lower()
    if value == 'moderate':value='medium'
    return value if value in SEVERITY_ORDER else "unknown"


@dataclass
class RawRecord:
    scanner: str
    cve: str
    package: str
    version: str
    ecosystem: str = "maven"
    severity: str = "unknown"
    cvss: float = 0.0
    fixed_versions: tuple[str, ...] = ()
    # Semgrep provenance — used by the reachability stage.
    path: str | None = None
    line: int | None = None
    message: str | None = None
    dataflow: dict[str, Any] = field(default_factory=dict)


@dataclass
class RawBatch:
    scanner: str
    records: list[RawRecord] = field(default_factory=list)
    semgrep_results: list[dict[str, Any]] = field(default_factory=list)

    def __len__(self) -> int:  # pragma: no cover - convenience
        return len(self.records) + len(self.semgrep_results)


# --------------------------------------------------------------------------- #
# Trivy (filesystem / image JSON)
# --------------------------------------------------------------------------- #
def parse_trivy(data: dict[str, Any]) -> list[RawRecord]:
    if not isinstance(data, dict):
        return []
    out: list[RawRecord] = []
    for result in data.get("Results", []) or []:
        target = result.get("Target") or result.get("Class") or ""
        for vuln in result.get("Vulnerabilities", []) or []:
            cvss = 0.0
            for key in ("CVSS", "CVSSv3", "CVSSv2"):
                block = vuln.get(key)
                if isinstance(block, dict):
                    for provider in block.values():
                        if isinstance(provider, dict) and provider.get("V3Score"):
                            cvss = max(cvss, float(provider["V3Score"]))
                        elif isinstance(provider, dict) and provider.get("Score"):
                            cvss = max(cvss, float(provider["Score"]))
            sev = _sev(vuln.get("Severity"))
            if cvss == 0.0:
                cvss = CVSS_BY_SEVERITY[sev]
            out.append(
                RawRecord(
                    scanner="Trivy",
                    cve=vuln.get("VulnerabilityID", ""),
                    package=vuln.get("PkgName", ""),
                    version=vuln.get("InstalledVersion", ""),
                    ecosystem=result.get("Type", "maven").lower(),
                    severity=sev,
                    cvss=cvss,
                    fixed_versions=tuple(x.strip() for x in (vuln.get("FixedVersion") or "").split(",") if x.strip()),
                    path=(vuln.get("PkgIdentifier") or {}).get("PURL") or target,
                )
            )
    return out


# --------------------------------------------------------------------------- #
# Grype
# --------------------------------------------------------------------------- #
def parse_grype(data: dict[str, Any]) -> list[RawRecord]:
    if not isinstance(data, dict):
        return []
    out: list[RawRecord] = []
    for match in data.get("matches", []) or []:
        vuln = match.get("vulnerability", {}) or {}
        artifact = match.get("artifact", {}) or {}
        cvss = 0.0
        for entry in vuln.get("cvss", []) or []:
            metrics = entry.get("metrics", {}) if isinstance(entry, dict) else {}
            score = metrics.get("baseScore")
            if score:
                cvss = max(cvss, float(score))
        sev = _sev(vuln.get("severity"))
        if cvss == 0.0:
            cvss = CVSS_BY_SEVERITY[sev]
        out.append(
            RawRecord(
                scanner="Grype",
                cve=vuln.get("id", ""),
                package=artifact.get("name", ""),
                version=artifact.get("version", ""),
                ecosystem=(artifact.get("type") or "maven").lower(),
                fixed_versions=tuple((vuln.get("fix") or {}).get("versions") or []),
                severity=sev,
                cvss=cvss,
            )
        )
    return out


# --------------------------------------------------------------------------- #
# OSV-Scanner
# --------------------------------------------------------------------------- #
def _objects(value):
    if value is None:return []
    if not isinstance(value,list) or any(not isinstance(item,dict) for item in value):
        raise ValueError('Report entries must be a list of objects')
    return value


def parse_osv(data: dict[str, Any] | list[Any]) -> list[RawRecord]:
    if not isinstance(data,(dict,list)):return []
    results=_objects(data.get('results',[]) if isinstance(data,dict) else data)
    out=[]
    for result in results:
        packages=_objects(result['packages']) if 'packages' in result else [result]
        for item in packages:
            if not ('package' in item or 'vulnerabilities' in item):raise ValueError('Missing OSV package structure')
            pkg=item.get('package') or {}
            if not isinstance(pkg,dict):raise ValueError('Invalid OSV package')
            for vuln in _objects(item.get('vulnerabilities',[])):
                sev=_sev((vuln.get('database_specific') or {}).get('severity'))
                fixed=[]
                for affected in _objects(vuln.get('affected',[])):
                    coordinate=affected.get('package') or {}
                    if coordinate.get('name')!=pkg.get('name') or str(coordinate.get('ecosystem','')).lower()!=str(pkg.get('ecosystem','')).lower():continue
                    for span in _objects(affected.get('ranges',[])):
                        for event in _objects(span.get('events',[])):
                            if 'fixed' in event:fixed.append(event['fixed'])
                out.append(RawRecord(scanner='OSV-Scanner',cve=vuln.get('id',''),package=pkg.get('name',''),
                    version=pkg.get('version',''),ecosystem=(pkg.get('ecosystem') or 'maven').lower(),severity=sev,cvss=CVSS_BY_SEVERITY[sev],fixed_versions=tuple(fixed)))
    return out


# --------------------------------------------------------------------------- #
# Semgrep (taint / call-graph evidence)
# --------------------------------------------------------------------------- #
def parse_semgrep(data: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    return list(data.get("results", []) or [])


def _checked(batch):
    import math
    for row in batch.records:
        if (not isinstance(row.cve,str) or not row.cve.strip() or not isinstance(row.package,str) or not row.package.strip()
                or not isinstance(row.version,str) or not isinstance(row.ecosystem,str)
                or any(not isinstance(x,str) or not x.strip() for x in row.fixed_versions)
                or not math.isfinite(row.cvss) or not 0<=row.cvss<=10):
            raise ValueError('Invalid vulnerability coordinates or score')
    return batch


def detect_and_parse(filename: str, data: Any) -> RawBatch:
    """Recognize content, never infer a successful report from its filename."""
    if not isinstance(data,(dict,list)):return RawBatch(scanner='unknown')
    try:
        if isinstance(data,dict) and data.get('schemaVersion')=='trace.http-baseline/1':
            from ..http_baseline import records
            return _checked(RawBatch(scanner='TRACE HTTP Baseline',records=records(data)))
        if isinstance(data,dict) and 'site' in data and '@version' in data:
            from .zap import parse
            return _checked(RawBatch(scanner='ZAP',records=parse(data)))
        if isinstance(data,dict) and data.get('schemaVersion')=='trace.python-sast/1':
            from ..python_sast import RULES
            records=[]
            if data.get('scanner')!='TRACE Python AST' or not isinstance(data.get('results'),list) or not isinstance(data.get('errors'),list) or not isinstance(data.get('coverage'),dict):
                raise ValueError('Invalid native SAST report')
            _objects(data['errors'])
            for item in _objects(data.get('results')):
                if item.get('ruleId') not in RULES or not isinstance(item.get('path'),str) or not item['path'] or type(item.get('line')) is not int or item['line']<1:
                    raise ValueError('Invalid native SAST observation')
                if item['path'].startswith('/') or '\\' in item['path'] or ':' in item['path'] or any(part in ('','.', '..') for part in item['path'].split('/')) or any(ord(c)<32 for c in item['path']):
                    raise ValueError('Invalid native SAST path')
                records.append(RawRecord(scanner='TRACE Python AST',cve=item['ruleId'],package=item['path'],version='',ecosystem='code',severity=RULES[item['ruleId']][0],cvss=0.0,path=item['path'],line=item['line'],message=RULES[item['ruleId']][1]))
            return _checked(RawBatch(scanner='TRACE Python AST',records=records))
        if isinstance(data,dict) and 'results' in data and 'errors' in data:
            results=_objects(data['results']);_objects(data['errors'])
            for item in results:
                extra=item.get('extra') or {}
                if not isinstance(extra,dict) or not isinstance(extra.get('metadata') or {},dict):raise ValueError('Invalid Semgrep metadata')
            return RawBatch(scanner='Semgrep',semgrep_results=results)
        if isinstance(data,dict) and 'matches' in data:
            _objects(data['matches'])
            records=parse_grype(data)
            return _checked(RawBatch(scanner='Grype',records=records))
        if isinstance(data,list) or (isinstance(data,dict) and 'results' in data):
            return _checked(RawBatch(scanner='OSV-Scanner',records=parse_osv(data)))
        if isinstance(data,dict) and 'Results' in data:
            for item in _objects(data['Results']):_objects(item.get('Vulnerabilities',[]))
            return _checked(RawBatch(scanner='Trivy',records=parse_trivy(data)))
    except (AttributeError,TypeError,ValueError,OverflowError) as exc:
        raise ValueError('Malformed scanner report') from exc
    return RawBatch(scanner='unknown')


def parse_many(payloads: Iterable[tuple[str, Any]]) -> tuple[list[RawRecord], list[dict[str, Any]], list[str]]:
    records: list[RawRecord] = []
    semgrep: list[dict[str, Any]] = []
    scanners: list[str] = []
    for filename, data in payloads:
        batch = detect_and_parse(filename, data)
        if batch.scanner != "unknown" and batch.scanner not in scanners:
            scanners.append(batch.scanner)
        records.extend(batch.records)
        semgrep.extend(batch.semgrep_results)
    return records, semgrep, scanners
