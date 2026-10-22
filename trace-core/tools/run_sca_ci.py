"""Real OSV execution and a deterministic CI gate. No TRACE API or secrets needed."""
import argparse,hashlib,json,subprocess,sys,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from trace_api.pipeline.ingest import detect_and_parse,SEVERITY_ORDER

def gate(report,threshold='high'):
    batch=detect_and_parse('osv.json',report)
    if batch.scanner!='OSV-Scanner':raise ValueError('Expected OSV report')
    packages=sum(len(item.get('packages',[])) for item in report.get('results',[]))
    if not packages:raise ValueError('No package coverage in report')
    blocked=[r for r in batch.records if r.severity=='unknown' or SEVERITY_ORDER[r.severity]<=SEVERITY_ORDER[threshold]]
    return dict(status='blocked' if blocked else 'passed',threshold=threshold,packages=packages,findings=len(batch.records),blocking=len(blocked),coverage='OSV-supported dependency files only; not SAST or DAST')

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scanner',default='osv-scanner');parser.add_argument('--source',type=Path,default=Path('.'));parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--threshold',choices=['critical','high','medium','low'],default='high');parser.add_argument('--timeout',type=int,default=180)
    args=parser.parse_args(argv)
    try:
        if not args.source.is_dir() or not 1<=args.timeout<=600:raise ValueError('Invalid source directory or timeout')
        args.output.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryFile() as stream:
            process=subprocess.run([args.scanner,'--format','json','--all-packages',str(args.source.resolve())],stdout=stream,stderr=subprocess.PIPE,timeout=args.timeout)
            if process.returncode not in (0,1):raise ValueError('OSV execution failed; no successful gate')
            stream.seek(0);raw=stream.read(20*1024*1024+1)
        if len(raw)>20*1024*1024:raise ValueError('OSV report exceeds 20 MiB')
        receipt=gate(json.loads(raw),args.threshold)
        receipt.update(reportSha256=hashlib.sha256(raw).hexdigest(),execution='real_osv_process')
        (args.output/'osv.json').write_bytes(raw);(args.output/'gate.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
        print(json.dumps(receipt));return 1 if receipt['blocking'] else 0
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        print('SCA gate failed: '+str(exc),file=sys.stderr);return 2

if __name__=='__main__':raise SystemExit(main())
