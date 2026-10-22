"""Send an operator-provided trace.intake/1 document from CI using only stdlib."""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen, build_opener, HTTPRedirectHandler

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--api-url',required=True)
    parser.add_argument('--source-id',required=True)
    parser.add_argument('--workspace-id',required=True)
    parser.add_argument('--delivery-id',required=True,help='Stable ID for retries of this exact report')
    parser.add_argument('--secret-env',default='TRACE_CI_KEY')
    parser.add_argument('report',type=Path)
    args=parser.parse_args()
    parsed=urlsplit(args.api_url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('','/'):
        parser.error('--api-url must be an origin without credentials, query or path')
    if not parsed.hostname or (parsed.scheme!='https' and not(parsed.scheme=='http' and parsed.hostname in ('127.0.0.1','localhost','::1'))):
        parser.error('HTTPS is required except for a local loopback API')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',args.source_id) or not re.fullmatch(r'[A-Za-z0-9._-]{1,128}',args.delivery_id):
        parser.error('invalid source ID or delivery ID')
    key=os.environ.get(args.secret_env,'')
    if not key:parser.error('CI secret environment variable is empty')
    try:
        with args.report.open('rb') as report:raw=report.read(65537)
        if len(raw)>65536:parser.error('report exceeds 65536 bytes')
        document=json.loads(raw)
        if not isinstance(document,dict) or document.get('sourceId')!=args.source_id:parser.error('report sourceId must match --source-id')
    except (OSError,ValueError):parser.error('cannot read a valid JSON report')
    stamp=str(int(time.time()))
    message=('v1\n'+args.source_id+'\n'+args.workspace_id+'\n'+stamp+'\n'+args.delivery_id+'\n').encode()+raw
    signature='v1='+hmac.new(key.encode(),message,hashlib.sha256).hexdigest()
    request=Request(args.api_url.rstrip('/')+'/api/v1/hooks/results/'+args.source_id,data=raw,
        headers={'Content-Type':'application/json','X-Trace-Timestamp':stamp,'X-Trace-Delivery':args.delivery_id,'X-Trace-Signature':signature})
    try:
        # Redirects are denied to prevent forwarding signed report content to another origin.
        with build_opener(NoRedirect).open(request,timeout=30) as response:result=json.load(response)
    except HTTPError as error:
        print('TRACE rejected delivery: HTTP '+str(error.code)+'. Check configuration; keep delivery ID and exact report bytes for retries.',file=sys.stderr)
        return 1
    except (URLError,TimeoutError,OSError,ValueError):
        print('TRACE delivery outcome is unknown. Retry with the same delivery ID and exact report bytes.',file=sys.stderr)
        return 1
    print(json.dumps({key:result.get(key) for key in ('status','deliveryId','resultId','resultSha256','replayed')}))
    return 0

if __name__=='__main__':raise SystemExit(main())
