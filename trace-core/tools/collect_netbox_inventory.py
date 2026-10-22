"""Read an operator-selected NetBox server role into trace.inventory/1 (GET only)."""
import argparse
from datetime import datetime, timezone
from http.client import HTTPException
import json
import os
from pathlib import Path
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

MAX_ITEMS = 100
MAX_BYTES = 1048576


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def endpoint(url):
    """Accept HTTPS origins; plain HTTP is restricted to literal loopback."""
    parts = urlsplit(url)
    if (parts.scheme not in ('https', 'http') or not parts.hostname or parts.username
            or parts.password or parts.query or parts.fragment or parts.path not in ('', '/')
            or any(ord(c) <= 32 or ord(c) > 126 for c in url)):
        raise ValueError('Use an HTTPS origin without credentials, path, query or fragment')
    if parts.scheme == 'http' and parts.hostname not in ('127.0.0.1', '::1', 'localhost'):
        raise ValueError('HTTP is permitted only for a local test server')
    _ = parts.port  # Reject malformed ports before any network activity.
    return url.rstrip('/') + '/api/dcim/devices/'


def device(row):
    if not isinstance(row, dict) or type(row.get('id')) is not int or not 0 < row['id'] <= 9223372036854775807:
        raise ValueError('invalid device ID')
    name = row.get('name')
    if name is None or name == '':
        name = 'NetBox device #' + str(row['id'])
    if not isinstance(name, str) or not name.strip() or len(name) > 255:
        raise ValueError('invalid device name')
    platform = row.get('platform')
    if platform is None:
        platform = ''
    elif isinstance(platform, dict):
        platform = platform.get('name')
    else:
        raise ValueError('invalid platform')
    if not isinstance(platform, str) or len(platform) > 128:
        raise ValueError('invalid platform name')
    return dict(externalId='netbox:device:' + str(row['id']), name=name,
                kind='server', platform=platform)


def collect(url, run_id, token, role_id, auth_scheme='Token', timeout=5):
    base = endpoint(url)
    if (not isinstance(run_id, str) or not run_id.strip() or len(run_id) > 128
            or type(role_id) is not int or role_id <= 0
            or auth_scheme not in ('Token', 'Bearer')
            or not token or any(ord(c) <= 32 or ord(c) > 126 for c in token)):
        raise ValueError('Invalid run ID, server role ID, authentication scheme or token')
    snapshot = dict(schemaVersion='trace.inventory/1', externalRunId=run_id,
                    observedAt=datetime.now(timezone.utc).isoformat(),
                    status='complete', items=[], errors=[])
    def fail(code, message):
        if not any(e['code'] == code for e in snapshot['errors']):
            snapshot['errors'].append(dict(code=code, message=message))
    opener = build_opener(ProxyHandler({}), NoRedirect())
    offset, expected_count, seen = 0, None, set()
    deadline = time.monotonic() + 30
    for _ in range(10):
        page_limit = min(50, MAX_ITEMS - offset)
        query = urlencode(dict(role_id=role_id, limit=page_limit, offset=offset, ordering='id'))
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            request = Request(base + '?' + query, headers={
                'Authorization': auth_scheme + ' ' + token,
                'Accept': 'application/json', 'Accept-Encoding': 'identity'}, method='GET')
            with opener.open(request, timeout=min(timeout, remaining)) as response:
                chunks, size = [], 0
                while size <= MAX_BYTES:
                    if time.monotonic() >= deadline:
                        raise TimeoutError()
                    chunk = response.read1(min(65536, MAX_BYTES + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                raw = b''.join(chunks)
            if len(raw) > MAX_BYTES:
                fail('limit_reached', 'NetBox response exceeded the page byte limit')
                break
            page = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            if (not isinstance(page, dict) or type(page.get('count')) is not int
                    or page['count'] < 0 or not isinstance(page.get('results'), list)
                    or 'next' not in page or not (page['next'] is None or isinstance(page['next'], str))):
                raise ValueError()
            if expected_count is None:
                expected_count = page['count']
            elif page['count'] != expected_count:
                fail('collection_failed', 'NetBox collection changed during pagination')
            rows = page['results']
            if len(rows) > page_limit:
                fail('limit_reached', 'NetBox returned more records than the requested page size')
                break
            # Never send credentials to a URL returned by the remote server.
            if page['next'] is not None:
                nxt, root = urlsplit(page['next']), urlsplit(base)
                if (nxt.scheme, nxt.netloc, nxt.path) != (root.scheme, root.netloc, root.path) or nxt.fragment:
                    fail('collection_failed', 'NetBox returned an unexpected pagination destination')
                    break
            for row in rows:
                try:
                    if not isinstance(row, dict) or not isinstance(row.get('role'), dict) or row['role'].get('id') != role_id:
                        raise ValueError()
                    item = device(row)
                    if item['externalId'] in seen:
                        raise ValueError()
                    seen.add(item['externalId'])
                    snapshot['items'].append(item)
                except (ValueError, TypeError):
                    fail('invalid_item', 'A NetBox device was invalid or repeated; it was not imported')
            offset += len(rows)
            if page['next'] is None:
                if offset != expected_count:
                    fail('collection_failed', 'NetBox result count did not match the received records')
                break
            if offset >= MAX_ITEMS:
                fail('limit_reached', 'Collection is limited to 100 devices; narrow the server role')
                break
            if not rows:
                fail('collection_failed', 'NetBox pagination made no progress')
                break
        except HTTPError as error:
            code = 'access_denied' if error.code in (401, 403) else 'collection_failed'
            fail(code, 'NetBox denied access' if code == 'access_denied' else 'NetBox HTTP request failed; redirects are not followed')
            error.close()
            break
        except (OSError, URLError, HTTPException, ValueError, TypeError, TimeoutError, RecursionError):
            fail('collection_failed', 'NetBox response could not be read or validated')
            break
    else:
        fail('limit_reached', 'Collection reached the maximum number of pages')
    if snapshot['errors']:
        snapshot['status'] = 'partial' if snapshot['items'] else 'error'
    return snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True, help='NetBox HTTPS origin (no path)')
    parser.add_argument('--server-role-id', required=True, type=int,
                        help='Operator-verified NetBox role containing servers only')
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--token-env', default='TRACE_NETBOX_TOKEN')
    parser.add_argument('--auth-scheme', choices=('Token', 'Bearer'), default='Token')
    parser.add_argument('--output', type=Path, required=True, help='New UTF-8 JSON file; never overwritten')
    args = parser.parse_args()
    try:
        endpoint(args.url)
        if args.output.exists():
            raise ValueError('Output already exists; retain the original snapshot for retries')
        snapshot = collect(args.url, args.run_id, os.environ.get(args.token_env, ''),
                           args.server_role_id, args.auth_scheme)
        with args.output.open('x', encoding='utf-8') as target:
            target.write(json.dumps(snapshot, ensure_ascii=False) + '\n')
    except (ValueError, OSError):
        parser.error('Check URL, server role, run ID, token environment variable and a new writable output path')
    print('Inventory snapshot saved: ' + snapshot['status'] + ', devices=' + str(len(snapshot['items'])))
    return 0 if snapshot['status'] == 'complete' else 2


if __name__ == '__main__':
    raise SystemExit(main())
