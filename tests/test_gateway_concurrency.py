"""Real local HTTP concurrency; no PC actions and no production credentials."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import secrets
import socket
import sys
import tempfile
import threading
import time
import unittest
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from deploy.gateway_production_server import GatewayHTTPServer
from deploy.vm.server import VMDatabase, VMHandler


class Concurrency(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1] / 'build')
        self.accepted = threading.Event()
        accepted = self.accepted

        class Handler(VMHandler):
            def setup(self):
                super().setup()
                accepted.set()

        self.db = VMDatabase(str(Path(self.tmp.name) / 'test.db'))
        Handler.db = self.db
        self.server = GatewayHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.origin = f'http://127.0.0.1:{self.server.server_port}'
        self.slow = None

    def tearDown(self):
        if self.slow:
            # Complete the held request and drain its response before teardown.
            self.slow.sendall(self.remaining)
            while self.slow.recv(4096):
                pass
            self.slow.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
        self.tmp.cleanup()

    def http(self, path, body=None, token=None):
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        request = Request(self.origin + path, headers=headers,
                          data=json.dumps(body).encode() if body is not None else None)
        with urlopen(request, timeout=2) as response:
            return json.loads(response.read())

    def hold_client(self, request):
        self.remaining = b'}' + b' ' * 98 if request.endswith(b'{') else b'\r\n'
        self.slow = socket.create_connection(self.server.server_address, timeout=2)
        self.slow.sendall(request)
        self.assertTrue(self.accepted.wait(1), 'Slow connection was not accepted')

    def test_partial_headers_do_not_block_other_clients(self):
        self.hold_client(b'GET /healthz HTTP/1.1\r\nHost: localhost\r\n')
        start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.http('/healthz'), range(16)))
        elapsed = time.perf_counter() - start
        self.assertTrue(all(r['status'] == 'ONLINE' for r in results))
        self.assertLess(elapsed, 2)
        print(f'16 health requests with stalled headers: {elapsed * 1000:.1f} ms')

    def test_partial_body_does_not_block_and_command_delivered_once(self):
        self.hold_client(b'POST /agent/poll HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\n{')
        token = secrets.token_hex(24)
        now = time.time()
        with self.db.get_conn() as conn:
            conn.execute('INSERT INTO devices (device_id, computer_name, public_key_hex, device_secret_hash, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)',
                         ('test_pc', 'test', '00' * 32, hashlib.sha256(token.encode()).hexdigest(), now, now))
            conn.execute("INSERT INTO commands (command_id, device_id, action, status, created_at) VALUES ('test_cmd', 'test_pc', 'mock', 'pending', ?)", (now,))
        start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.http('/agent/poll', {'device_id': 'test_pc'}, token), range(8)))
        elapsed = time.perf_counter() - start
        delivered = [r['command'] for r in results if r['command'] is not None]
        self.assertEqual([r['id'] for r in delivered], ['test_cmd'])
        self.assertLess(elapsed, 2)
        print(f'8 authenticated polls with stalled body, exactly one delivery: {elapsed * 1000:.1f} ms')


if __name__ == '__main__':
    unittest.main()
