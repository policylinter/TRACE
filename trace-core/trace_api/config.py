"""Runtime configuration.

Everything is env-overridable so the same image runs in a laptop, in CI and in
a customer VPC. Defaults are chosen so that `uvicorn trace_api.main:app` works
with zero setup (SQLite file next to the package, Ollama on localhost).
"""

from __future__ import annotations

import os
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent


def _env(name: str, default: str) -> str:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


# --- Persistence ----------------------------------------------------------
# Postgres in production (`postgresql+psycopg2://...`), SQLite for local runs.
DATABASE_URL = _env(
    "TRACE_DATABASE_URL",
    _env("DATABASE_URL", f"sqlite:///{(BASE_DIR / 'trace.db').as_posix()}"),
)

# --- Local model inference (no egress) ------------------------------------
OLLAMA_URL = _env("TRACE_OLLAMA_URL", _env("OLLAMA_URL", "http://127.0.0.1:11434"))
OLLAMA_MODEL = _env("TRACE_OLLAMA_MODEL", "qwen2.5-coder:7b")
OLLAMA_TIMEOUT = float(_env("TRACE_OLLAMA_TIMEOUT", "90"))
# When the model is unreachable TRACE falls back to a deterministic rules
# engine so the pipeline never blocks on infrastructure.
AI_REQUIRE_MODEL = _env("TRACE_AI_REQUIRE_MODEL", "0") == "1"

# --- AI providers & multi-model cascade -----------------------------------
# A provider is a plug. `auto` prefers a local (no-egress) backend, then an
# OpenAI-compatible one, then the rules engine — so the tool works with zero
# setup but a user can point it at whatever they have.
#   ollama -> local Ollama daemon (default)
#   openai -> any OpenAI-compatible endpoint (DeepSeek, vLLM, LM Studio, ...)
AI_PROVIDER = _env("TRACE_AI_PROVIDER", "auto")  # auto | ollama | openai | rules
# Models are tried in order as a cascade: each one reviews the previous verdict.
# e.g. TRACE_AI_MODELS="qwen2.5-coder:7b,qwen2.5-coder:14b,qwen2.5-coder:32b"
AI_MODELS = [m.strip() for m in _env("TRACE_AI_MODELS", OLLAMA_MODEL).split(",") if m.strip()]
AI_BASE_URL = _env("TRACE_AI_BASE_URL", "")  # OpenAI-compatible base, e.g. https://api.deepseek.com/v1
AI_API_KEY = _env("TRACE_AI_API_KEY", "")
AI_TIMEOUT = float(_env("TRACE_AI_TIMEOUT", str(OLLAMA_TIMEOUT)))

# --- Scanner integration ---------------------------------------------------
# Optional external binaries. TRACE degrades gracefully when they are absent:
# every scanner is a plug with an install hint surfaced by /api/v1/integrations.
TRIVY_BIN = _env("TRACE_TRIVY_BIN", "trivy")
GRYPE_BIN = _env("TRACE_GRYPE_BIN", "grype")
_LOCAL_SEMGREP = PROJECT_DIR / '.tools' / 'semgrep' / ('Scripts/pysemgrep.exe' if os.name == 'nt' else 'bin/semgrep')
def _local_semgrep_ready() -> bool:
    # Installing a binary does not prove that its native engine can scan.
    try:
        marker = json.loads((PROJECT_DIR / ".tools/semgrep-readiness.json").read_text(encoding="utf-8"))
        return _LOCAL_SEMGREP.is_file() and marker.get("ready") is True
    except (OSError, ValueError, AttributeError):
        return False

SEMGREP_BIN = _env("TRACE_SEMGREP_BIN", str(_LOCAL_SEMGREP) if _local_semgrep_ready() else "semgrep")
# Semgrep registry rulesets, tried in order (each becomes a --config). The code
# findings double as the taint/call-graph evidence reachability consumes.
SEMGREP_CONFIG = [c.strip() for c in _env("TRACE_SEMGREP_CONFIG", "").split(",") if c.strip()]
_LOCAL_OSV = PROJECT_DIR / '.tools/osv-scanner/osv-scanner.exe'
def _local_osv_ready() -> bool:
    try:
        import hashlib
        marker=json.loads((_LOCAL_OSV.parent/'readiness.json').read_text(encoding='utf-8'))
        return marker.get('ready') is True and hashlib.sha256(_LOCAL_OSV.read_bytes()).hexdigest()==marker.get('binarySha256')
    except (OSError,ValueError,AttributeError):return False
OSV_BIN = _env("TRACE_OSV_BIN", str(_LOCAL_OSV) if _local_osv_ready() else "osv-scanner")
SYFT_BIN = _env("TRACE_SYFT_BIN", "syft")
REDIS_URL = _env("TRACE_REDIS_URL", _env("REDIS_URL", "redis://127.0.0.1:6379/0"))
SCANNER_TIMEOUT = float(_env("TRACE_SCANNER_TIMEOUT", "600"))

# --- Source integration (GitLab / local) -----------------------------------
# When a token is present TRACE can clone and read a GitLab project itself;
# otherwise it analyses a local checkout or uploaded scanner reports.
GITLAB_URL = _env("TRACE_GITLAB_URL", "https://gitlab.com")
GITLAB_TOKEN = _env("TRACE_GITLAB_TOKEN", "")
GITLAB_INSECURE = _env("TRACE_GITLAB_INSECURE", "0") == "1"
GIT_BIN = _env("TRACE_GIT_BIN", "git")
WORK_DIR = Path(_env("TRACE_WORK_DIR", str(PROJECT_DIR / ".trace-work")))

# --- Admin ----------------------------------------------------------------
# Optional shared secret guarding settings mutations. When empty the API is
# open (single-tenant / trusted-network deployments); when set, write endpoints
# require the `X-Admin-Token` header to match.
ADMIN_TOKEN = _env("TRACE_ADMIN_TOKEN", "")

# --- Optional RBAC v1 (opt-in) ---------------------------------------------
# When TRACE_AUTH_ENABLED=1 the API requires login for admin operations and
# bootstrap an admin account from the two variables below on the first start.
AUTH_ENABLED = _env("TRACE_AUTH_ENABLED", "0") == "1"
TRACE_ADMIN_USERNAME = _env("TRACE_ADMIN_USERNAME", "admin")
TRACE_ADMIN_PASSWORD = _env("TRACE_ADMIN_PASSWORD", "")

# --- CORS ------------------------------------------------------------------
CORS_ORIGINS = [
    origin.strip()
    for origin in _env(
        "TRACE_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000",
    ).split(",")
    if origin.strip()
]

ENGINES = [
    {"name":"TRACE Python AST","version":"1"},
    {"name": "Trivy", "version": "0.58.1"},
    {"name": "Grype", "version": "0.87.0"},
    {"name": "Semgrep", "version": "1.99.0"},
    {"name": "OSV-Scanner", "version": "1.9.2"},
    {"name": "Syft", "version": "1.18.1"},
]


# --- Frontend bundle -------------------------------------------------------
# When the React build is present the API also serves it as static files, so a
# single process exposes the UI and the API on one origin. Override the location
# with TRACE_FRONTEND_DIST.
def _frontend_dist() -> Path | None:
    candidates = []
    override = os.environ.get("TRACE_FRONTEND_DIST")
    if override:
        candidates.append(Path(override))
    # Sibling checkout: C:\Users\vlad\trace-frontend\dist
    candidates.append(BASE_DIR.parent.parent / "trace-frontend" / "dist")
    # Bundled into the image next to the app.
    candidates.append(PROJECT_DIR / "frontend" / "dist")
    return next((path for path in candidates if path.is_dir()), None)


FRONTEND_DIST = _frontend_dist()
