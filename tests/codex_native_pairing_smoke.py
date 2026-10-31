"""Actual native desktop register/QR -> actual gateway claim; no screen input."""
import gc
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from deploy.gateway_production_server import run_server

def main():
    with tempfile.TemporaryDirectory(dir=ROOT / 'plan/reports/codex', prefix='native_pair_') as folder:
        server = run_server(0, str(Path(folder) / 'gateway.db'))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = f'http://127.0.0.1:{server.server_port}'
        try:
            for attempt in range(2):
                result = subprocess.run([
                    str(ROOT / 'apps/desktop_tauri/src-tauri/target/debug/winkey_desktop.exe'),
                    '--register-and-qr', '--origin', origin, '--data-dir', str(Path(folder) / 'client')
                ], capture_output=True, text=True, errors='replace', timeout=20)
                assert result.returncode == 0, result.stderr
                payload = json.loads(result.stdout.strip().splitlines()[-1])
                req = urllib.request.Request(origin + '/pair',
                    data=json.dumps({'pair_code': payload['pair_code']}).encode(),
                    headers={'Content-Type': 'application/json'})
                with urllib.request.urlopen(req, timeout=4) as response:
                    claim = json.load(response)
                assert claim.get('session_token') and claim['device_id'] == payload['device_id']
                print(f'PASS native register/QR -> phone claim, attempt {attempt+1} (secrets redacted)')
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
            gc.collect()

if __name__ == '__main__':
    main()
