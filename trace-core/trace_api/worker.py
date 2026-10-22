"""Heavy agent: the Celery worker that runs scans.

This is the same pipeline the API runs in-process — the scan never forks logic.
In the split / cluster deployments the web service enqueues work here; in the
all-in-one deployment this module is simply unused (scans run in a thread).

Run it with::

    celery -A trace_api.worker worker --loglevel=info
"""

from __future__ import annotations

from celery import Celery

from . import jobs
from .config import REDIS_URL

celery_app = Celery("trace_tasks", broker=REDIS_URL, backend=REDIS_URL)
celery_app.conf.update(task_track_started=True, worker_prefetch_multiplier=1)


@celery_app.task(name="trace_api.worker.run_scan_job")
def run_scan_job(job_id: str, params: dict | None = None) -> dict:
    return jobs.run_scan_job(job_id, params)
