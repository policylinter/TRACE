"""Print a passive inventory snapshot of this local host. Never contacts a remote host."""
import argparse
from datetime import datetime,timezone
import json
import platform
from pathlib import Path

def collect(external_id,run_id,name=None):
    snapshot=dict(schemaVersion='trace.inventory/1',externalRunId=run_id,observedAt=datetime.now(timezone.utc).isoformat(),status='complete',errors=[],items=[])
    try:
        snapshot['items']=[dict(externalId=external_id,name=name or platform.node() or external_id,
            kind='server',platform=platform.system(),version=platform.release())]
    except Exception:
        snapshot.update(status='error',errors=[dict(code='collection_failed',message='Local OS inventory could not be read')])
    return snapshot

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--external-id',required=True,help='Operator-assigned stable host ID within this inventory source')
    parser.add_argument('--run-id',required=True,help='Unique snapshot ID; keep output unchanged for retries')
    parser.add_argument('--name')
    parser.add_argument('--output',type=Path,help='Create a new UTF-8 JSON file; existing files are not overwritten')
    args=parser.parse_args()
    if not args.external_id.strip() or len(args.external_id)>128 or not args.run_id.strip() or len(args.run_id)>128:
        parser.error('IDs must contain 1–128 characters')
    if args.name is not None and (not args.name.strip() or len(args.name)>255):parser.error('name must contain 1–255 characters')
    document=json.dumps(collect(args.external_id,args.run_id,args.name),ensure_ascii=False)
    if args.output:
        try:
            with args.output.open('x',encoding='utf-8') as output:output.write(document+'\n')
        except OSError:parser.error('cannot create output file; use a new path and keep existing snapshots for retries')
    else:print(document)

if __name__=='__main__':main()
