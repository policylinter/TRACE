"""Source integration.

TRACE can analyse a local checkout, a plain git URL, or a GitLab project it
clones itself. When ``TRACE_GITLAB_TOKEN`` is set the token is injected into the
clone URL (GitLab's ``oauth2:<token>@host`` form) so private projects work; when
it is absent the clone still runs for public projects.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .config import GIT_BIN, GITLAB_TOKEN, GITLAB_URL, WORK_DIR

_URL_RE = re.compile(r"^(https?://|git@|ssh://)", re.IGNORECASE)
_SLUG_RE = re.compile(r"[^a-zA-Z0-9._-]+")


def git_available() -> bool:
    return shutil.which(GIT_BIN) is not None


def source_status() -> list[dict]:
    return [
        {
            "id": "source.git",
            "kind": "source",
            "label": "git clone",
            "available": git_available(),
            "detail": GIT_BIN,
            "knob": "TRACE_GIT_BIN",
            "install": "install git",
        },
        {
            "id": "source.gitlab",
            "kind": "source",
            "label": "GitLab (token)",
            "available": bool(GITLAB_TOKEN),
            "detail": GITLAB_URL,
            "knob": "TRACE_GITLAB_URL / TRACE_GITLAB_TOKEN",
            "install": "create a personal/project access token with read_repository",
        },
    ]


def _project_path(source: str) -> str:
    """``group/sub/project`` or a full URL → the ``group/sub/project`` path."""
    if _URL_RE.match(source):
        return urlsplit(source).path.strip("/")
    return source.strip("/")


def _slug(source: str) -> str:
    return _SLUG_RE.sub("-", _project_path(source))[-60:]


def _clone_url(source: str) -> str:
    """Return the URL to clone, with a GitLab token injected when available."""
    if _URL_RE.match(source):
        parts = urlsplit(source)
        if GITLAB_TOKEN and parts.scheme in ("http", "https") and not parts.username:
            host = parts.netloc
            netloc = f"oauth2:{GITLAB_TOKEN}@{host}"
            return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
        return source
    # Bare "group/project" → build against the configured GitLab host.
    path = _project_path(source)
    if not path.endswith(".git"):
        path += ".git"
    base = GITLAB_URL.rstrip("/")
    if GITLAB_TOKEN:
        parts = urlsplit(base)
        base = urlunsplit((parts.scheme, f"oauth2:{GITLAB_TOKEN}@{parts.netloc}", "", "", ""))
    return f"{base}/{path}"


def _git(args: list[str], cwd: Path | None = None) -> str:
    proc = subprocess.run(
        [GIT_BIN, *args],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"git {' '.join(args)} failed")
    return proc.stdout.strip()


def fetch(source: str, ref: str | None = None) -> tuple[Path, dict]:
    """Materialise ``source`` on disk. Returns ``(path, meta)``.

    ``meta`` carries ``kind``, ``repository``, ``commit`` (full sha), ``branch``.
    """
    local = Path(source)
    if local.exists() and local.is_dir():
        return local, {
            "kind": "local",
            "repository": local.name,
            "commit": "",
            "branch": ref or "",
        }

    if not git_available():
        raise RuntimeError(
            "git is not available; install git or pass a local directory as the source"
        )

    WORK_DIR.mkdir(parents=True, exist_ok=True)
    dest = WORK_DIR / f"{_slug(source)}-{hashlib.sha1(source.encode()).hexdigest()[:8]}"
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)

    url = _clone_url(source)
    clone_cmd = ["clone", "--depth", "1"]
    if ref:
        clone_cmd += ["--branch", ref]
    clone_cmd += [url, str(dest)]
    # Keep the token out of any error surfaced to the caller.
    try:
        _git(clone_cmd)
        commit = _git(["rev-parse", "HEAD"], cwd=dest)
        branch = ref or _git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=dest)
    except RuntimeError as exc:
        raise RuntimeError(str(exc).replace(GITLAB_TOKEN, "***")) from None

    return dest, {
        "kind": "git",
        "repository": _project_path(source),
        "commit": commit,
        "branch": branch,
    }
