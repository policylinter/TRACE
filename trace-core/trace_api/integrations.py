"""Integration registry.

A single, honest answer to "what is connected, and how do I connect the rest?".
Every entry carries: whether it is live right now, the env knob to point it
somewhere, and an install hint. The rest of the codebase already degrades when a
plug is missing — this is the surface that tells the operator about it.
"""

from __future__ import annotations

from typing import Any

from .config import DATABASE_URL, FRONTEND_DIST, REDIS_URL
from .pipeline import ai
from .scanners import scanner_status
from .sources import source_status


def _redis_available() -> bool:
    try:
        import redis  # type: ignore

        client = redis.Redis.from_url(REDIS_URL, socket_connect_timeout=1.0, socket_timeout=1.0)
        return bool(client.ping())
    except Exception:
        return False


def _store_status() -> dict[str, Any]:
    kind = "postgres" if str(DATABASE_URL).startswith("postgres") else "sqlite"
    return {
        "id": "store.database",
        "kind": "store",
        "label": f"Database ({kind})",
        "available": True,
        "detail": str(DATABASE_URL).split("@")[-1],
        "knob": "TRACE_DATABASE_URL / DATABASE_URL",
        "install": "SQLite out of the box; set a Postgres URL for multi-writer use",
    }


def _queue_status() -> dict[str, Any]:
    live = _redis_available()
    return {
        "id": "queue.redis",
        "kind": "queue",
        "label": "Task queue (Redis/Celery)",
        "available": live,
        "detail": REDIS_URL,
        "knob": "TRACE_REDIS_URL",
        "install": "run redis + the agent service; scans run in-process otherwise",
    }


def _frontend_status() -> dict[str, Any]:
    live = FRONTEND_DIST is not None
    return {
        "id": "ui.bundle",
        "kind": "ui",
        "label": "Web UI bundle",
        "available": live,
        "detail": str(FRONTEND_DIST) if live else "(not built)",
        "knob": "TRACE_FRONTEND_DIST",
        "install": "cd trace-frontend && npm run build",
    }


def registry(settings: dict[str, Any] | None = None) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    entries.extend(ai.provider_status(settings))
    entries.extend(scanner_status())
    entries.extend(source_status())
    entries.append(_queue_status())
    entries.append(_store_status())
    entries.append(_frontend_status())

    cfg = ai.config_from(settings)
    provider = ai.active_provider(settings)
    return {
        "ai": {
            "configured": cfg["provider"],
            "active": provider.name if provider else "rules",
            "models": cfg["models"],
        },
        "integrations": entries,
    }
