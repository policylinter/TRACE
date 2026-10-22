"""Shared database admission limits and bounded, periodic outbox delivery."""
import logging
import threading
from sqlalchemy import select, update, func
from sqlalchemy.exc import IntegrityError
from .job_models import QueueControl, Job

INTERVAL = 2
DELIVERY_COOLDOWN = 30
ENABLED = True
logger = logging.getLogger(__name__)


def ensure_control(factory):
    with factory() as db:
        if db.get(QueueControl, 'default') is None:
            db.add(QueueControl(id='default', revision=0, max_running=2, max_queued=100))
            try: db.commit()
            except IntegrityError: db.rollback()  # Another initializer won.


def locked_control(db):
    # All admission/claim decisions serialize on this row, including on Postgres.
    changed = db.execute(update(QueueControl).where(QueueControl.id == 'default').values(
        revision=QueueControl.revision+1)).rowcount
    if not changed: raise RuntimeError('queue control is not initialized')
    return db.get(QueueControl, 'default')


def count_status(db, status):
    return db.scalar(select(func.count()).select_from(Job).where(Job.organization_id == 'default', Job.status == status))


def available(factory):
    with factory() as db:
        control = db.get(QueueControl, 'default')
        return max(0, control.max_running-count_status(db, 'running')) if control else 0


def configure(factory, max_running=None, max_queued=None):
    if max_running is not None and not 1 <= max_running <= 32: raise ValueError('max_running must be 1..32')
    if max_queued is not None and not 1 <= max_queued <= 10000: raise ValueError('max_queued must be 1..10000')
    with factory() as db:
        control = locked_control(db)
        previous = (control.max_running, control.max_queued)
        if max_running is not None: control.max_running = max_running
        if max_queued is not None: control.max_queued = max_queued
        if previous != (control.max_running, control.max_queued):
            from .platform import audit
            db.info['actor'] = 'system:queue-admin'
            audit(db, 'queue.configured', 'default', f'capacity {previous} -> {(control.max_running, control.max_queued)}')
        db.commit()


class Dispatcher:
    def __init__(self, factory):
        self.factory = factory
        self.stop_event = threading.Event()
        self.thread = None

    def tick(self):
        from .job_store import dispatch_pending
        try: dispatch_pending(self.factory)
        except Exception: logger.warning('TRACE job dispatch tick failed; queued jobs remain in the database')

    def run(self):
        self.tick()
        while not self.stop_event.wait(INTERVAL): self.tick()

    def __enter__(self):
        if ENABLED:
            self.thread = threading.Thread(target=self.run, name='trace-outbox-dispatcher', daemon=True)
            self.thread.start()
        return self

    def __exit__(self, *args):
        self.stop_event.set()
        if self.thread: self.thread.join(timeout=2)
