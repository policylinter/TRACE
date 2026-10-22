import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from threading import Thread
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import unittest
from urllib.parse import parse_qs, urlsplit

from trace_api.inventory_intake import SnapshotInput

SCRIPT = Path(__file__).resolve().parents[1] / 'tools' / 'collect_netbox_inventory.py'
spec = importlib.util.spec_from_file_location('netbox_collector', SCRIPT)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def row(id):
    return dict(id=id, name='server-' + str(id), platform={'name': 'Linux'}, role={'id': 7},
                tenant={'name': 'not an owner'}, serial='not exported')


class NetBoxConnectorTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        self.reply = lambda offset: dict(count=2, next=None, results=[row(1), row(2)])
        self.status = 200
        test = self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                test.requests.append((self.path, self.headers.get('Authorization')))
                self.send_response(test.status)
                if test.status == 302:
                    self.send_header('Location', 'http://127.0.0.1:1/secret')
                self.end_headers()
                offset = int(parse_qs(urlsplit(self.path).query)['offset'][0])
                payload = test.reply(offset)
                self.wfile.write(payload if isinstance(payload, bytes) else json.dumps(payload).encode())
            def log_message(self, *args): pass
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.url = 'http://127.0.0.1:' + str(self.server.server_port)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def collect(self, **kwargs):
        snapshot = collector.collect(self.url, 'run-1', 'private-fixture-token', 7, **kwargs)
        SnapshotInput.model_validate(snapshot)
        self.assertNotIn('private-fixture-token', json.dumps(snapshot))
        return snapshot

    def test_mapping_and_authentication(self):
        snapshot = self.collect(auth_scheme='Bearer')
        self.assertEqual(snapshot['status'], 'complete')
        self.assertEqual(snapshot['items'][0], dict(externalId='netbox:device:1', name='server-1', kind='server', platform='Linux'))
        self.assertEqual(self.requests[0][1], 'Bearer private-fixture-token')
        self.assertEqual(parse_qs(urlsplit(self.requests[0][0]).query)['role_id'], ['7'])

    def test_pagination_and_count(self):
        self.reply = lambda offset: dict(count=2, next=self.url+'/api/dcim/devices/?offset=1' if offset == 0 else None,
                                         results=[row(offset+1)])
        snapshot = self.collect()
        self.assertEqual(snapshot['status'], 'complete')
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.requests[0][1], 'Token private-fixture-token')
        self.assertEqual(len(snapshot['items']), 2)

    def test_partial_after_http_error(self):
        def reply(offset):
            if offset:
                return b'private-fixture-token invalid JSON'
            return dict(count=2, next=self.url+'/api/dcim/devices/?offset=1', results=[row(1)])
        self.reply = reply
        self.assertEqual(self.collect()['status'], 'partial')

    def test_denied_and_redirect_never_followed(self):
        for status in (401, 403, 302, 500):
            with self.subTest(status=status):
                self.status = status
                self.requests.clear()
                snapshot = self.collect()
                self.assertEqual(snapshot['status'], 'error')
                self.assertEqual(len(self.requests), 1)
                self.assertEqual(snapshot['errors'][0]['code'], 'access_denied' if status in (401,403) else 'collection_failed')
        self.status = 401
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)/'failed.json'
            result = subprocess.run([sys.executable, str(SCRIPT), '--url', self.url,
                '--server-role-id', '7', '--run-id', 'failed-run', '--output', str(output)],
                env=dict(os.environ, TRACE_NETBOX_TOKEN='private-fixture-token'), capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            snapshot = json.loads(output.read_text(encoding='utf-8'))
            SnapshotInput.model_validate(snapshot)
            self.assertEqual(snapshot['status'], 'error')
            self.assertNotIn('private-fixture-token', result.stdout+result.stderr+json.dumps(snapshot))

    def test_foreign_next_is_rejected(self):
        self.reply = lambda _: dict(count=1, next='https://other.example/api/dcim/devices/', results=[row(1)])
        self.assertEqual(self.collect()['status'], 'error')
        self.assertEqual(len(self.requests), 1)

    def test_item_errors_and_role_mismatch(self):
        bad = row(3)
        bad['role'] = {'id': 8}
        self.reply = lambda _: dict(count=4, next=None, results=[row(1), row(1), {'id': True}, bad])
        snapshot = self.collect()
        self.assertEqual(snapshot['status'], 'partial')
        self.assertEqual(len(snapshot['items']), 1)

    def test_limit_does_not_overflow_with_short_pages(self):
        def reply(offset):
            limit = min(30, 100-offset)
            return dict(count=120, next=self.url+'/api/dcim/devices/?offset='+str(offset+limit),
                        results=[row(n) for n in range(offset+1, offset+limit+1)])
        self.reply = reply
        snapshot = self.collect()
        self.assertEqual(snapshot['status'], 'partial')
        self.assertEqual(len(snapshot['items']), 100)
        self.assertEqual(snapshot['errors'][0]['code'], 'limit_reached')

    def test_empty_complete_and_count_mismatch(self):
        self.reply = lambda _: dict(count=0, next=None, results=[])
        self.assertEqual(self.collect()['status'], 'complete')
        self.reply = lambda _: dict(count=2, next=None, results=[row(1)])
        self.assertEqual(self.collect()['status'], 'partial')

    def test_schema_and_byte_limits(self):
        for payload in (b'not json', b'['*2000+b']'*2000, b'x'*(collector.MAX_BYTES+1), {'count': True, 'next': None, 'results': []}):
            self.reply = lambda _, payload=payload: payload
            self.assertEqual(self.collect()['status'], 'error')

    def test_configuration_and_output_collision_do_not_request(self):
        for url in ('http://outside.example', 'https://user:secret@example.com', self.url+'/path', self.url+'?x=1'):
            with self.assertRaises(ValueError):
                collector.collect(url, 'run', 'token', 7)
        with self.assertRaises(ValueError):
            collector.collect(self.url, 'run', 'token\nsecret', 7)
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)/'snapshot.json'
            output.write_text('preserved')
            result = subprocess.run([sys.executable, str(SCRIPT), '--url', self.url,
                '--server-role-id', '7', '--run-id', 'run', '--output', str(output)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_text(), 'preserved')
        self.assertEqual(self.requests, [])


if __name__ == '__main__': unittest.main()
