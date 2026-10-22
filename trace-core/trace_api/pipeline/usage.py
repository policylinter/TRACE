"""Usage analysis — "is this dependency actually referenced in the code?".

Reachability to a *third-party* symbol is not provable from the checkout alone:
the vulnerable implementation lives inside the package (node_modules, .m2,
site-packages), not in the repository TRACE scans. So the honest, repo-agnostic
signal we can always produce is **usage**: does first-party code import or
reference this package at all?

We index import/require/using statements (and a bounded set of identifiers) per
source file, then answer ``imported`` / ``referenced`` / ``absent`` / ``unknown``
for each candidate. Combined with the strict reachability result this turns the
noisy ``unknown`` bucket into actionable buckets:

    reachable            -> affected
    unreachable (barrier)-> not_affected
    unknown + imported   -> needs_review (high signal — reach it and fix it)
    unknown + absent     -> needs_review (low signal — likely unused)

Absence is a hint, never a verdict: dynamic imports, reflection and generated
code mean we will not claim a dependency is unused just because we did not find
a textual import.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .dedup import Candidate

SOURCE_EXTS = {
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".scala": "scala",
    ".groovy": "groovy",
    ".py": "python",
    ".pyi": "python",
    ".js": "js",
    ".jsx": "js",
    ".mjs": "js",
    ".cjs": "js",
    ".ts": "ts",
    ".tsx": "ts",
    ".vue": "js",
    ".svelte": "js",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".fs": "fsharp",
    ".rs": "rust",
    ".swift": "swift",
    ".dart": "dart",
    ".ex": "elixir",
    ".exs": "elixir",
}

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "bower_components",
    "vendor",
    "dist",
    "build",
    "out",
    "target",
    "bin",
    "obj",
    ".venv",
    ".tools",
    "venv",
    "env",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".gradle",
    ".idea",
    "coverage",
    ".next",
    ".nuxt",
    ".terraform",
}

_IMPORT_LINE_RE = re.compile(r"(?im)^\s*(?:import|from|using|require|export)\b[^\n]{0,320}$")
_QUOTED_RE = re.compile(r"""["']([^"'\n]+)["']""")
_DOTTED_RE = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)+)\b")
_BARE_IMPORT_RE = re.compile(r"(?im)^\s*(?:import|using|package)\s+([a-zA-Z0-9_.]+)")
_FROM_IMPORT_RE = re.compile(r"(?im)^\s*from\s+([a-zA-Z0-9_.]+)\s+import\b")
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")

MAX_FILE_BYTES = 512 * 1024
MAX_IDENTIFIERS = 200_000


@dataclass
class UsageIndex:
    """Import targets and identifiers harvested from a checkout."""

    available: bool = False
    files_scanned: int = 0
    imports: set[str] = field(default_factory=set)
    identifiers: set[str] = field(default_factory=set)

    def has_import(self, probe: str) -> bool:
        if len(probe) < 4:
            return False
        return any(probe in target for target in self.imports)

    def has_identifier(self, probe: str) -> bool:
        return probe in self.identifiers


def build_usage_index(root: Path | str | None) -> UsageIndex:
    """Walk a checkout and index imports/references. Never raises."""
    if root is None:
        return UsageIndex(available=False)
    root_path = Path(root)
    if not root_path.is_dir():
        return UsageIndex(available=False)

    index = UsageIndex(available=True)
    seen: set[str] = set()
    for path in _iter_files(root_path):
        if len(seen) >= MAX_IDENTIFIERS:
            break
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        index.files_scanned += 1
        for line in _IMPORT_LINE_RE.findall(text):
            for spec in _QUOTED_RE.findall(line):
                index.imports.add(spec.strip().lower())
            for dotted in _DOTTED_RE.findall(line):
                index.imports.add(dotted.lower())
        # Bare (non-dotted) module names: `import requests`, `from flask import`.
        for match in _BARE_IMPORT_RE.findall(text):
            index.imports.add(match.lower())
        for match in _FROM_IMPORT_RE.findall(text):
            index.imports.add(match.lower())
        for token in _IDENT_RE.findall(text):
            key = token.lower()
            if key not in seen:
                seen.add(key)
                index.identifiers.add(key)
                if len(seen) >= MAX_IDENTIFIERS:
                    break
    return index


def _iter_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTS:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


def _probes(candidate: Candidate) -> list[str]:
    """Strings that, if found in an import/reference, imply usage."""
    package = (candidate.package or "").strip()
    lower = package.lower()
    eco = (candidate.ecosystem or "").lower()
    probes: list[str] = []

    if ":" in package or eco in ("maven", "gradle", "java"):
        group, _, artifact = package.partition(":")
        if group:
            probes.append(group.lower())
            probes.append(group.replace(".", "/").lower())
        if artifact:
            probes.append(artifact.lower())
    elif lower.startswith("@") or eco in ("npm", "node", "nodejs", "javascript", "yarn"):
        probes.append(lower)
        if "/" in lower:
            probes.append(lower.split("/", 1)[1])
    elif eco in ("pypi", "python", "pip"):
        probes.append(lower)
        probes.append(lower.replace("-", "_"))
        probes.append(lower.replace("_", "-"))
    elif eco in ("golang", "go"):
        probes.append(lower.rsplit("/", 1)[-1])
    else:
        probes.append(lower)
        if "/" in lower:
            probes.append(lower.rsplit("/", 1)[-1])

    # De-duplicate, drop empty and overly generic probes.
    out: list[str] = []
    for probe in probes:
        probe = probe.strip().strip("@").strip()
        if probe and probe not in out and probe not in ("-", "_", "/"):
            out.append(probe)
    return out


def usage_for(candidate: Candidate, index: UsageIndex | None) -> tuple[str, list[str], str | None]:
    """Return ``(kind, hits, note)`` for a candidate against a checkout index."""
    if index is None or not index.available:
        return "unknown", [], "No source checkout available to assess usage."

    probes = _probes(candidate)
    if not probes:
        return "unknown", [], None

    imported = [p for p in probes if index.has_import(p)]
    if imported:
        return (
            "imported",
            imported,
            f"Imported in first-party code (matched: {', '.join(imported[:3])}).",
        )

    referenced = [p for p in probes if index.has_identifier(p)]
    if referenced:
        return (
            "referenced",
            referenced,
            f"Referenced as an identifier (matched: {', '.join(referenced[:3])}).",
        )

    return (
        "absent",
        [],
        f"No import or reference to {candidate.package} found in {index.files_scanned} source files.",
    )
