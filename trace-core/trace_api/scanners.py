"""Scanner integration (plugs).

Every scanner is an optional external binary. TRACE probes for it, runs it over
a checkout when present, and skips it with a surfaced status when absent — the
pipeline never breaks because a tool is missing.

Roles (a tool is not a tool): ``sca`` flags vulnerable packages, ``sast``
produces the taint/call-graph evidence reachability needs, ``sbom`` only emits a
bill of materials.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import (
    GRYPE_BIN,
    OSV_BIN,
    SCANNER_TIMEOUT,
    SEMGREP_BIN,
    SEMGREP_CONFIG,
    SYFT_BIN,
    TRIVY_BIN,
)


@dataclass(frozen=True)
class ScannerSpec:
    id: str
    label: str
    role: str  # sca | sast | sbom
    bin: str
    install: str


SCANNERS: list[ScannerSpec] = [
    ScannerSpec("trivy", "Trivy", "sca", TRIVY_BIN, "https://trivy.dev — package/file vulnerability + SBOM"),
    ScannerSpec("grype", "Grype", "sca", GRYPE_BIN, "https://github.com/anchore/grype"),
    ScannerSpec("osv", "OSV-Scanner", "sca", OSV_BIN, "https://google.github.io/osv-scanner/"),
    ScannerSpec("semgrep", "Semgrep", "sast", SEMGREP_BIN, "pip install semgrep — taint/reachability source"),
    ScannerSpec("syft", "Syft", "sbom", SYFT_BIN, "https://github.com/anchore/syft — emits CycloneDX SBOM"),
    ScannerSpec("python-ast", "TRACE Python AST", "sast", sys.executable, "Встроенные AST-проверки Python: eval/exec, pickle, yaml.load, shell=True. Не подтверждают эксплуатацию."),
]

SPECS = {spec.id: spec for spec in SCANNERS}


def is_available(scanner_id: str) -> bool:
    spec = SPECS.get(scanner_id)
    return bool(spec and shutil.which(spec.bin))


def scanner_status() -> list[dict[str, Any]]:
    out = []
    for spec in SCANNERS:
        out.append(
            {
                "id": f"scanner.{spec.id}",
                "kind": "scanner",
                "role": spec.role,
                "label": spec.label,
                "available": is_available(spec.id),
                "detail": spec.bin,
                "knob": f"TRACE_{spec.id.upper()}_BIN",
                "install": spec.install,
            }
        )
    return out


def available_scanners() -> list[str]:
    return [spec.id for spec in SCANNERS if is_available(spec.id)]


def _run(cmd: list[str], cwd: Path | None = None, env: dict[str,str] | None = None) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=SCANNER_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _load(path_to_json: str) -> Any | None:
    try:
        return json.loads(Path(path_to_json).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


# --------------------------------------------------------------------------- #
# Individual runners — each returns ``(filename, payload)`` or ``None``.
# --------------------------------------------------------------------------- #
def run_trivy(path: Path) -> tuple[str, Any] | None:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "trivy.json"
        proc = _run([TRIVY_BIN, "fs", "--format", "json", "--output", str(out), "--quiet", str(path)])
        if proc is None or proc.returncode not in (0, 1) or not out.exists():
            return None
        data = _load(str(out))
    return ("trivy.json", data) if data else None


def run_grype(path: Path) -> tuple[str, Any] | None:
    proc = _run([GRYPE_BIN, f"dir:{path}", "-o", "json"])
    if proc is None or proc.returncode not in (0, 1) or not proc.stdout.strip():
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    return ("grype.json", data)


def run_osv(path: Path) -> tuple[str, Any] | None:
    proc = _run([OSV_BIN, "--format", "json", "--all-packages", str(path)])
    if proc is None or proc.returncode not in (0, 1) or not proc.stdout.strip():
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    return ("osv.json", data)


def run_semgrep(path: Path) -> tuple[str, Any] | None:
    cmd = [SEMGREP_BIN, "scan"]
    cmd += [f"--config={cfg}" for cfg in SEMGREP_CONFIG]
    # Curated TRACE rules carry cve/package metadata that links code findings to
    # SCA advisories (see pipeline/rules/*.yaml). Local files: no network needed,
    # so SAST works even when the registry is unreachable.
    rules_dir = Path(__file__).resolve().parent / "pipeline" / "rules"
    if rules_dir.exists():
        for rule_file in sorted(rules_dir.glob("*.yaml")):
            cmd.append(f"--config={rule_file}")
    cmd += ["--json", "--metrics=off", "--disable-version-check", "--no-secrets-validation", "--quiet", str(path)]
    from tools.run_sast_local import clean_env
    with tempfile.TemporaryDirectory(prefix='trace-semgrep-home-') as home:
        proc = _run(cmd,env=clean_env(Path(home)))
    if proc is None or proc.returncode not in (0,1) or not proc.stdout.strip():
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    return ("semgrep.json", data)


def run_syft(path: Path) -> tuple[str, Any] | None:
    proc = _run([SYFT_BIN, f"dir:{path}", "-o", "cyclonedx-json", "--quiet"])
    if proc is None or proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    return ("syft.cdx.json", data)


def run_python_ast(path: Path) -> tuple[str,Any]:
    from .python_sast import scan
    return ("trace-python-sast.json",scan(path))

_RUNNERS = {
    "python-ast":run_python_ast,
    "trivy": run_trivy,
    "grype": run_grype,
    "osv": run_osv,
    "semgrep": run_semgrep,
    "syft": run_syft,
}


def cyclonedx_components(payload: Any) -> list[str]:
    """Pull component coordinates out of a CycloneDX SBOM (Syft output)."""
    if not isinstance(payload, dict):
        return []
    names = []
    for component in payload.get("components", []) or []:
        name = component.get("name")
        version = component.get("version")
        if name:
            names.append(f"{name}@{version}" if version else str(name))
    return names


def run_available(path: Path, statuses: list[dict[str, Any]] | None = None) -> tuple[list[tuple[str, Any]], list[str], list[str]]:
    """Run every installed scanner over ``path``.

    Returns ``(payloads, scanners_used, sbom_components)``. Payloads are the raw
    JSON dicts, ready for :func:`trace_api.pipeline.ingest.parse_many`.
    """
    payloads: list[tuple[str, Any]] = []
    used: list[str] = []
    components: list[str] = []
    for spec in SCANNERS:
        status = {"id": spec.id, "label": spec.label, "role": spec.role, "status": "skipped", "detail": "Движок недоступен"}
        if statuses is not None:
            statuses.append(status)
        if not is_available(spec.id):
            continue
        result = _RUNNERS[spec.id](path)
        if result is None:
            status.update(status="failed", detail="Не удалось получить корректный отчёт")
            continue
        filename, payload = result
        try:
            if spec.role == "sbom":
                if not isinstance(payload,dict) or payload.get("bomFormat")!="CycloneDX" or not isinstance(payload.get("components",[]),list):
                    raise ValueError("Invalid SBOM")
                if any(not isinstance(item,dict) for item in payload.get("components",[])):
                    raise ValueError("Invalid component")
            else:
                from .pipeline.ingest import detect_and_parse
                parsed = detect_and_parse(filename,payload)
                if parsed.scanner != {"trivy":"Trivy","grype":"Grype","osv":"OSV-Scanner","semgrep":"Semgrep","python-ast":"TRACE Python AST"}.get(spec.id):
                    raise ValueError("Unrecognized report")
        except (ValueError,TypeError,KeyError,AttributeError):
            status.update(status="failed",detail="Движок вернул некорректную структуру отчёта")
            continue
        status.update(status="completed", detail="Отчёт получен")
        if spec.id=='semgrep' and isinstance(payload,dict):
            paths=payload.get('paths')
            if payload.get('errors') or payload.get('skipped_rules') or (isinstance(paths,dict) and paths.get('skipped')):
                status.update(status='partial',detail='Semgrep сообщил об ошибках или пропусках; отчёт частичный')
        if spec.id=="python-ast":
            coverage=payload["coverage"]
            if payload["errors"] or coverage["filesSkipped"] or coverage["limited"] or not coverage["filesScanned"]:
                status.update(status="partial",detail=f"Python: {coverage['filesScanned']} файлов; есть пропуски, ошибки или неподдерживаемые входные данные. Ограниченные AST-правила, без проверки эксплуатации.")
            else:
                status.update(detail=f"Python: {coverage['filesScanned']} файлов, {coverage['ruleCount']} AST-правила. Эксплуатация не проверялась; другие языки не анализировались.")
        if spec.role == "sbom":
            components.extend(cyclonedx_components(payload))
        payloads.append((filename, payload))
        used.append(spec.label)
    return payloads, used, components
