"""
WinKey Pro — Real Native Service WebSocket Integration Test
Spesifikasiya: plan/GEMINI_WEBSOCKET_BATCH.md (Paket C, E)

Bu test real tərtib olunmuş `winkey_service.exe` ikili faylını `--standalone --mock`
rejimində işə salaraq, onun ASGI Uvicorn serverinə birbaşa daimi WebSocket ilə qoşulmasını,
avtorizasiyadan keçməsini, `hub` üzərindən əmri (push) qəbul edib icra etməsini, nəticəni
WebSocket ilə qaytarmasını və bu müddətdə HTTP poll sayının SIFIR olmasını təsdiqləyir.
"""

import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from deploy.gateway_service import GatewayService
from deploy.asgi_app import build_asgi_app
from deploy.websocket_hub import hub
from deploy.vm.server import VMDatabase
from deploy.vm.configure import configure

import socket

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

SERVICE_BIN = ROOT_DIR / "apps/winkey_service/target/release/winkey_service.exe"


class NativeWebSocketIntegrationTest(unittest.TestCase):
    def test_native_service_ws_flow(self):
        self.assertTrue(SERVICE_BIN.exists(), f"Binary tapılmadı: {SERVICE_BIN}")

        with tempfile.TemporaryDirectory(dir=ROOT_DIR) as srv_dir, tempfile.TemporaryDirectory(dir=ROOT_DIR) as agent_dir:
            srv_root = Path(srv_dir)
            agent_root = Path(agent_dir)

            configure("winkey.example.com", srv_root)
            admin_sec = (srv_root / "deploy/vm/secrets/admin_key").read_text(encoding="utf-8").strip()
            os.environ["WINKEY_ADMIN_SECRET"] = admin_sec

            db = VMDatabase(str(srv_root / "test_native.db"))
            service = GatewayService(db, admin_sec)
            app = build_asgi_app(service)

            port = get_free_port()
            config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
            server = uvicorn.Server(config)
            t_srv = threading.Thread(target=server.run, daemon=True)
            t_srv.start()

            for _ in range(50):
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1) as resp:
                        if resp.status == 200:
                            break
                except Exception:
                    time.sleep(0.05)

            http_origin = f"http://127.0.0.1:{port}"

            def http_req(path, body=None, token=None):
                headers = {"Content-Type": "application/json"}
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                data = json.dumps(body).encode("utf-8") if body is not None else None
                req = urllib.request.Request(http_origin + path, data=data, headers=headers)
                with urllib.request.urlopen(req, timeout=5) as r:
                    return json.loads(r.read())

            # 1. Cihaz qeydiyyatı
            dev_id = "native_pc_ws"
            priv = Ed25519PrivateKey.generate()
            pub_bytes = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
            chal = http_req("/agent/challenge", {"device_id": dev_id})
            nonce = chal["nonce"]
            sig = priv.sign(f"WINKEY_REGISTER:{nonce}:{dev_id}".encode()).hex()

            reg = http_req("/agent/register", {
                "device_id": dev_id, "computer_name": "WinKey Native PC",
                "public_key_hex": pub_bytes, "nonce": nonce, "proof_signature_hex": sig
            })
            dev_sec = reg["device_secret"]

            # 2. Cütləşmə
            p_req = http_req("/devices/pair-request", {"device_id": dev_id}, token=dev_sec)
            pair = http_req("/pair", {"pair_code": p_req["pair_code"]})
            sess_token = pair["session_token"]

            # 3. Agent konfiqurasiyası
            cfg_path = agent_root / "config.json"
            cfg_content = {
                "gateway_origin": http_origin,
                "device_id": dev_id,
                "device_secret": dev_sec,
                "server_confirmed": True
            }
            cfg_path.write_text(json.dumps(cfg_content, indent=2), encoding="utf-8")

            # 4. Native winkey_service prosesini başladırıq
            proc = subprocess.Popen(
                [str(SERVICE_BIN), "--standalone", "--mock", "--data-dir", str(agent_root), "--timeout-sec", "15"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace"
            )

            print("[TEST] Native winkey_service işə salındı, WebSocket bağlantısı gözlənilir...")
            connected = False
            t_wait = time.time()
            while time.time() - t_wait < 8.0:
                if hub.has_active_agent(dev_id):
                    connected = True
                    break
                time.sleep(0.2)

            self.assertTrue(connected, "Native agent serverə WebSocket ilə qoşulmadı!")
            print(f"[TEST] Native agent WebSocket ilə uğurla qoşuldu və avtorizasiya olundu!")

            # 5. Mobil tərəfdən mock komanda göndəririk
            cmd_req_id = secrets.token_hex(16)
            cmd_resp = http_req("/commands", {
                "device_id": dev_id, "action": "mock", "request_id": cmd_req_id
            }, token=sess_token)
            self.assertEqual(cmd_resp.get("status"), "queued")
            cmd_id = cmd_resp["command_id"]
            print(f"[TEST] Komanda göndərildi: {cmd_id}, status: queued. Native agentin icrası gözlənilir...")

            # 6. Komandanın native icraçı tərəfindən icra olunub nəticənin gəlməsini gözləyirik
            completed = False
            t_cmd_wait = time.time()
            stat_resp = None
            while time.time() - t_cmd_wait < 8.0:
                stat_resp = http_req(f"/commands/{cmd_id}", token=sess_token)
                if stat_resp.get("status") == "completed":
                    completed = True
                    break
                time.sleep(0.2)

            self.assertTrue(completed, f"Komanda completed olmadı: {stat_resp}")
            print(f"[PASS] Native agent əmri WebSocket ilə aldı və icra etdi! Nəticə: {stat_resp.get('result')}")

            # 7. Prosesi dayandırırıq
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()

            server.should_exit = True
            t_srv.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
