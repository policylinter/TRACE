"""Inspect lost heartbeats or repair job status from a committed scan receipt."""
import argparse
import json
from .database import SessionLocal, init_db
from .job_store import listing
from .job_recovery import reconcile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', default='default')
    parser.add_argument('--limit', type=int, default=100)
    parser.add_argument('--reconcile', metavar='JOB_ID')
    args = parser.parse_args()
    if not 1 <= args.limit <= 1000: parser.error('--limit must be 1..1000')
    init_db()
    if args.reconcile:
        print(reconcile(SessionLocal, args.reconcile, args.workspace))
    else:
        print(json.dumps([j for j in listing(SessionLocal, args.limit, args.workspace) if j['requiresReview']], ensure_ascii=False, indent=2))


if __name__ == '__main__': main()
