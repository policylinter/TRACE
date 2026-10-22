"""Operator command: redeliver committed queued jobs; never retry running scans."""
import argparse
import threading
from .database import SessionLocal, init_db
from .job_store import dispatch_pending


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--limit', type=int, default=100)
    parser.add_argument('--max-running', type=int)
    parser.add_argument('--max-queued', type=int)
    args = parser.parse_args()
    if not 1 <= args.limit <= 1000: parser.error('--limit must be between 1 and 1000')
    init_db()
    if args.max_running is not None or args.max_queued is not None:
        from .job_dispatcher import configure
        try: configure(SessionLocal, args.max_running, args.max_queued)
        except ValueError as exc: parser.error(str(exc))
    print(f'Queued jobs offered for delivery: {dispatch_pending(SessionLocal, args.limit, redeliver=True)}')
    # In local mode do not exit while daemon scan threads are still executing.
    for thread in threading.enumerate():
        if thread.name.startswith('scan-'): thread.join()


if __name__ == '__main__': main()
