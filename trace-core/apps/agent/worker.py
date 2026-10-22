"""Deprecated shim.

The worker used to live here and spoke to an external model API directly. The
single pipeline now lives in ``trace_api`` and the agent is just its Celery
binding — see ``trace_api.worker``. This module re-exports it so the legacy
``celery -A apps.agent.worker`` command keeps working.
"""

from trace_api.worker import celery_app, run_scan_job  # noqa: F401

app = celery_app  # Celery's ``-A`` looks for an ``app``/``celery`` attribute.

__all__ = ["celery_app", "run_scan_job", "app"]
