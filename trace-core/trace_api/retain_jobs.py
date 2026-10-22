"""Preview terminal job cleanup, or apply an explicitly reviewed JSON plan."""
import argparse
import json
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', default='default')
    parser.add_argument('--days', type=int, default=90)
    parser.add_argument('--limit', type=int, default=100)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--apply-plan', type=Path)
    args = parser.parse_args()
    if not (os.environ.get('TRACE_DATABASE_URL') or os.environ.get('DATABASE_URL')):
        parser.error('Set an explicit TRACE_DATABASE_URL before preview or apply')
    if args.output and args.apply_plan: parser.error('--output and --apply-plan are mutually exclusive')
    from .database import init_db, SessionLocal
    from .job_retention import preview, apply_plan
    init_db()
    try:
        if args.apply_plan:
            if args.apply_plan.stat().st_size > 2_000_000: raise ValueError('Plan file is too large')
            result = apply_plan(SessionLocal, json.loads(args.apply_plan.read_text(encoding='utf-8')), args.workspace)
        else:
            result = preview(SessionLocal, args.workspace, args.days, args.limit).model_dump()
            if args.output:
                with args.output.open('x', encoding='utf-8') as stream:json.dump(result, stream, ensure_ascii=False, indent=2)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except (ValueError, OSError) as exc: parser.error(str(exc))


if __name__ == '__main__': main()
