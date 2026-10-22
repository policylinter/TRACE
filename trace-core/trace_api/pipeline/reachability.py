"""Reachability analysis.

The engine consumes Semgrep taint/dataflow results (the same artefacts the
``semgrep --config=p/security`` run produces) and reconstructs the inter
procedural path from an entrypoint to the vulnerable symbol. When a caller
supplies an explicit call graph (as the bundled demo dataset does) that graph
is authoritative and the Semgrep stage is skipped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .dedup import Candidate


@dataclass
class ReachabilityResult:
    reachability: str = "unreachable"  # reachable | unreachable | suppressed | unknown
    frames: list[dict[str, Any]] = field(default_factory=list)
    blocker: str | None = None
    taint_source: str | None = None
    sink: str | None = None
    propagation: list[str] = field(default_factory=list)
    rule: str | None = None
    matched: bool = False
    # Usage signal (see pipeline/usage.py): imported | referenced | absent | unknown
    usage: str = "unknown"
    usage_hits: list[str] = field(default_factory=list)
    usage_note: str | None = None


def _loc(location: dict[str, Any] | None) -> tuple[str, int | None]:
    if not location:
        return ("", None)
    path = location.get("path", "")
    line = (location.get("start") or {}).get("line")
    return (path, line)


def _content(node: dict[str, Any] | None) -> str:
    if not node:
        return ""
    return (node.get("content") or "").strip()


def _match_loc(match: dict[str, Any]) -> tuple[str, int | None]:
    """Match location: Semgrep puts ``path``/``start`` at the top level, while
    dataflow nodes nest them under ``location``."""
    path = match.get("path") or (match.get("location") or {}).get("path", "")
    line = (match.get("start") or {}).get("line") or (
        (match.get("location") or {}).get("start") or {}
    ).get("line")
    return path, line


def _result_matches(result: dict[str, Any], candidate: Candidate) -> bool:
    meta = (result.get("extra") or {}).get("metadata") or {}
    haystack = " ".join(
        str(x)
        for x in (
            result.get("check_id", ""),
            (result.get("extra") or {}).get("message", ""),
            meta.get("cve", ""),
            meta.get("package", ""),
            meta.get("technology", ""),
        )
    ).lower()
    return candidate.cve.lower() in haystack or candidate.package.lower() in haystack


def analyze(
    candidate: Candidate,
    semgrep_results: list[dict[str, Any]] | None = None,
    explicit: dict[str, Any] | None = None,
) -> ReachabilityResult:
    # An explicit call graph (demo dataset / imported graph) wins outright.
    if explicit:
        return ReachabilityResult(
            reachability=explicit.get("reachability", "unreachable"),
            frames=explicit.get("frames", []),
            blocker=explicit.get("blocker"),
            taint_source=explicit.get("taint_source"),
            sink=explicit.get("sink"),
            propagation=explicit.get("propagation", []),
            rule=explicit.get("rule"),
            matched=True,
        )

    results = semgrep_results or []
    match = next((r for r in results if _result_matches(r, candidate)), None)
    if match is None:
        # Absence of evidence is not evidence of absence: without a call graph
        # that reaches (or explicitly rules out) this symbol we must not claim
        # the advisory is unaffected — surface it for review instead.
        if results:
            blocker = (
                "Semgrep produced code findings but none maps this advisory to a "
                "package symbol; no call graph ties the package to a live entrypoint."
            )
        else:
            blocker = (
                "No reachability evidence available — no call graph (Semgrep) was "
                "produced for this scan."
            )
        return ReachabilityResult(reachability="unknown", blocker=blocker)

    extra = match.get("extra") or {}
    meta = extra.get("metadata") or {}
    trace = extra.get("dataflow_trace") or {}

    if not trace:
        # A curated rule can assert reachability by metadata when the vulnerable
        # API is invoked directly (no interprocedural trace available). Anything
        # else without a trace stays inconclusive — never a false "reachable".
        if str(meta.get("reachability", "")).lower() != "reachable":
            return ReachabilityResult(
                reachability="unknown",
                blocker=(
                    "Semgrep matched this advisory but produced no source-to-sink "
                    "dataflow path; reachability stays inconclusive."
                ),
                rule=match.get("check_id"),
            )
        path, line = _match_loc(match)
        sink_symbol = (
            str(meta.get("vulnerable_symbol") or "")
            or _content(match)[:120]
            or match.get("check_id", "vulnerable symbol")
        )
        frames = [
            {
                "symbol": str(meta.get("entry") or "first-party code"),
                "location": path,
                "line": 1,
                "kind": "entrypoint",
                "note": "Code path exercising the vulnerable API.",
                "edge": "invokes",
            },
            {
                "symbol": sink_symbol,
                "location": path,
                "line": line,
                "kind": "sink",
                "note": extra.get("message", "Vulnerable API invoked."),
                "vulnerable": True,
            },
        ]
        return ReachabilityResult(
            reachability="reachable",
            frames=frames,
            taint_source=str(meta.get("source")) if meta.get("source") else None,
            sink=sink_symbol,
            rule=match.get("check_id"),
            matched=True,
        )

    source = trace.get("taint_source")
    sink_node = trace.get("taint_sink") or match
    inter = trace.get("intermediate_vars") or []

    frames: list[dict[str, Any]] = []

    src_path, src_line = _loc(source.get("location") if source else None)
    frames.append(
        {
            "symbol": _content(source)[:120] or "entrypoint",
            "location": src_path,
            "line": src_line,
            "kind": "entrypoint",
            "note": "Taint source identified by Semgrep.",
            "edge": "taint introduced",
        }
    )

    propagation: list[str] = []
    for step in inter:
        path, line = _loc(step.get("location"))
        content = _content(step)
        propagation.append(f"{path}:{line or '?'} — {content or 'value propagated'}")
        frames.append(
            {
                "symbol": content[:120] or "propagation",
                "location": path,
                "line": line,
                "kind": "internal",
                "note": "Value carried forward; no sanitiser applied.",
            }
        )

    sink_path, sink_line = _loc(sink_node.get("location"))
    frames.append(
        {
            "symbol": _content(sink_node)[:120] or match.get("check_id", "sink"),
            "location": sink_path,
            "line": sink_line,
            "kind": "sink",
            "note": extra.get("message", "Vulnerable symbol reached."),
            "vulnerable": True,
        }
    )

    if len(frames) < 2:
        return ReachabilityResult(
            reachability="unknown",
            blocker="Semgrep reported a match without a resolvable source-to-sink path.",
            rule=match.get("check_id"),
        )

    return ReachabilityResult(
        reachability="reachable",
        frames=frames,
        taint_source=_content(source) or "untrusted input",
        sink=_content(sink_node),
        propagation=propagation,
        rule=match.get("check_id"),
        matched=True,
    )
