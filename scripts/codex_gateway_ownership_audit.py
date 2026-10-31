"""Isolated ownership regression; never executes desktop commands."""
import gc
import io
import json
import sys
import tempfile
import time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from deploy.gateway_production_server import GatewayHandler, ProductionDatabase


def main():
    root = Path(__file__).resolve().parents[1] / 'plan/reports/codex'
    with tempfile.TemporaryDirectory(dir=root, prefix='ownership_') as folder:
        db = ProductionDatabase(str(Path(folder) / 'audit.db'))
        def post(path, payload):
            handler = object.__new__(GatewayHandler)
            body = json.dumps(payload).encode()
            handler.path, handler.db = path, db
            handler.headers = {'Content-Length': str(len(body))}
            handler.rfile = io.BytesIO(body)
            output = []
            handler._send_json = lambda status, data: output.append((status, data))
            handler.do_POST()
            return output[0]

        pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
        payload = {'device_id': 'isolated-device', 'public_key_hex': pub}
        first_status, first = post('/agent/register', payload)
        second_status, second = post('/agent/register', payload)
        results = [
            ('REGISTRATION_WITHOUT_PROOF', first_status == 200),
            ('PUBLIC_KEY_ONLY_SECRET_ROTATION', second_status == 200 and first.get('device_secret') != second.get('device_secret')),
        ]
        conn = db.get_conn()
        conn.execute("INSERT INTO pairing_requests VALUES (?, ?, ?, ?, ?, ?)",
                     ('rejected-fixture', 'isolated-device', 'fixture', 'REJECTED', time.time()+60, time.time()))
        conn.commit()
        conn.close()
        status, response = post('/pair', {'pair_code': 'rejected-fixture'})
        results.append(('REJECTED_PAIR_GRANTS_SESSION', status == 200 and bool(response.get('session_token'))))
        for name, found in results:
            print(f"{'REPRODUCED' if found else 'NOT_REPRODUCED'}: {name}")
        gc.collect()
        return int(any(found for _, found in results))


if __name__ == '__main__':
    raise SystemExit(main())
