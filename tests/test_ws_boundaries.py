"""
WinKey Pro — WebSocket Boundary, Origin Policy & Rate Limit Tests (R2-04)
Spesifikasiya: plan/GEMINI_WEBSOCKET_REVISION_2.md (R2-04)

Bu test süiti:
1. Wrong-Origin sorğularının 4003 ilə bloklanmasını;
2. İcazə verilmiş LAN / localhost Origin-lərinin qəbul edilməsini;
3. Native agent üçün Origin headersiz bağlantının qəbul edilməsini;
4. Flood hücumlarında sürət həddinin (Rate Limit 4029) tətbiqini;
5. 64 KB-dan böyük həcmli freymlərin bloklanmasını;
6. Cihaz ləğv edildikdə (Revoke) aktiv WebSocket-in bağlanmasını
avtomatlaşdırılmış şəkildə yoxlayır.
"""

import asyncio
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
import uvicorn
import websockets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from deploy.gateway_service import GatewayService
from deploy.asgi_app import build_asgi_app
from deploy.websocket_hub import hub
from deploy.vm.server import VMDatabase
from deploy.vm.configure import configure

def get_free_port():
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class WebSocketBoundaryTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(dir=ROOT_DIR)
        self.root = Path(self.temp_dir.name)
        configure("winkey.example.com", self.root)
        self.admin_secret = (self.root / "deploy/vm/secrets/admin_key").read_text(encoding="utf-8").strip()
        os.environ["WINKEY_ADMIN_SECRET"] = self.admin_secret

        db_path = str(self.root / "test_boundaries.db")
        self.db = VMDatabase(db_path)
        self.service = GatewayService(self.db, self.admin_secret)
        self.app = build_asgi_app(self.service)

        self.port = get_free_port()
        config = uvicorn.Config(self.app, host="127.0.0.1", port=self.port, log_level="error", ws_max_size=65536)
        self.server = uvicorn.Server(config)
        self.server_thread = threading.Thread(target=self.server.run, daemon=True)
        self.server_thread.start()

        for _ in range(50):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/healthz", timeout=1) as resp:
                    if resp.status == 200:
                        break
            except Exception:
                await asyncio.sleep(0.05)

        self.http_origin = f"http://127.0.0.1:{self.port}"
        self.ws_origin = f"ws://127.0.0.1:{self.port}"

    async def asyncTearDown(self):
        self.server.should_exit = True
        self.server_thread.join(timeout=3)
        self.temp_dir.cleanup()

    def _http_req(self, path, body=None, token=None):
        url = self.http_origin + path
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())

    def _setup_device(self, prefix):
        dev_id = f"{prefix}_{secrets.token_hex(4)}"
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        _, chal = self._http_req("/agent/challenge", {"device_id": dev_id})
        nonce = chal["nonce"]
        sig = priv.sign(f"WINKEY_REGISTER:{nonce}:{dev_id}".encode()).hex()

        _, reg = self._http_req("/agent/register", {
            "device_id": dev_id, "computer_name": f"Boundary PC {prefix}",
            "public_key_hex": pub, "nonce": nonce, "proof_signature_hex": sig
        })
        dev_sec = reg["device_secret"]

        _, p_req = self._http_req("/devices/pair-request", {"device_id": dev_id}, token=dev_sec)
        _, pair = self._http_req("/pair", {"pair_code": p_req["pair_code"]})
        sess_token = pair["session_token"]

        return dev_id, dev_sec, sess_token

    # 1. Wrong-Origin rədd edilməsi (R2-04)
    async def test_01_wrong_origin_rejected(self):
        ws_url = f"{self.ws_origin}/ws"
        headers = [("Origin", "http://malicious-attacker-site.com")]
        async with websockets.connect(ws_url, additional_headers=headers) as ws:
            try:
                await ws.recv()
                self.fail("Server kənar / icazəsiz Origin-li bağlantını bağlamalıdır.")
            except websockets.exceptions.ConnectionClosed as exc:
                self.assertEqual(exc.rcvd.code, 4003)

    # 2. İcazə verilmiş LAN / Localhost Origin-lərinin qəbul edilməsi (R2-04)
    async def test_02_allowed_origin_accepted(self):
        dev_id, dev_sec, _ = self._setup_device("origin_ok")
        ws_url = f"{self.ws_origin}/ws"
        headers = [("Origin", "http://localhost:3000")]
        async with websockets.connect(ws_url, additional_headers=headers) as ws:
            await ws.send(json.dumps({"type": "auth", "role": "agent", "device_id": dev_id, "token": dev_sec}))
            ack = json.loads(await ws.recv())
            self.assertEqual(ack.get("type"), "auth_ok")

    # 3. Native Agent üçün Origin headersiz bağlantı (R2-04)
    async def test_03_native_agent_without_origin_accepted(self):
        dev_id, dev_sec, _ = self._setup_device("native_no_origin")
        ws_url = f"{self.ws_origin}/ws"
        # Standard native client: no Origin header sent
        async with websockets.connect(ws_url) as ws:
            await ws.send(json.dumps({"type": "auth", "role": "agent", "device_id": dev_id, "token": dev_sec}))
            ack = json.loads(await ws.recv())
            self.assertEqual(ack.get("type"), "auth_ok")

    # 4. Message Rate Limit / Flood mühafizəsi (R2-04)
    async def test_04_rate_limit_flood_rejected(self):
        dev_id, dev_sec, _ = self._setup_device("flood_test")
        ws_url = f"{self.ws_origin}/ws"
        async with websockets.connect(ws_url) as ws:
            await ws.send(json.dumps({"type": "auth", "role": "agent", "device_id": dev_id, "token": dev_sec}))
            ack = json.loads(await ws.recv())
            self.assertEqual(ack.get("type"), "auth_ok")

            # 1 saniyədən az müddətdə 60 ədəd mesaj göndəririk (limit 50/san-dir)
            try:
                for i in range(65):
                    await ws.send(json.dumps({"type": "heartbeat", "locked": True, "pin_ready": True}))
                # Server bağlantını 4029 ilə bağlamalıdır
                await asyncio.wait_for(ws.recv(), timeout=2.0)
            except websockets.exceptions.ConnectionClosed as exc:
                self.assertEqual(exc.rcvd.code, 4029)

    # 5. Oversized Frame (>64 KB) Bloklanması (R2-04)
    async def test_05_oversized_frame_rejected(self):
        ws_url = f"{self.ws_origin}/ws"
        async with websockets.connect(ws_url) as ws:
            oversize_payload = "X" * (70 * 1024)
            await ws.send(oversize_payload)
            try:
                await ws.recv()
                self.fail("Server 64KB-dan böyük mesajı bloklamalıdır.")
            except websockets.exceptions.ConnectionClosed:
                pass

    # 6. Revoke zamanı aktiv WebSocket-in kəsilməsi (R2-04)
    async def test_06_revocation_disconnects_active_ws(self):
        dev_id, dev_sec, _ = self._setup_device("revoke_test")
        ws_url = f"{self.ws_origin}/ws"
        ws = await websockets.connect(ws_url)
        await ws.send(json.dumps({"type": "auth", "role": "agent", "device_id": dev_id, "token": dev_sec}))
        ack = json.loads(await ws.recv())
        self.assertEqual(ack.get("type"), "auth_ok")
        self.assertTrue(hub.has_active_agent(dev_id))

        # Admin vasitəsilə cihazı revoke edirik (event loop-u bloklamamaq üçün asyncio.to_thread ilə)
        def _do_revoke():
            admin_req = urllib.request.Request(
                f"{self.http_origin}/admin/revoke",
                data=json.dumps({"device_id": dev_id}).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-Owner-Admin-Secret": self.admin_secret}
            )
            with urllib.request.urlopen(admin_req, timeout=5) as r:
                return r.status
        status = await asyncio.to_thread(_do_revoke)
        self.assertEqual(status, 200)

        # Agent WebSocket-i bağlanmalıdır
        try:
            await asyncio.wait_for(ws.recv(), timeout=2.0)
        except websockets.exceptions.ConnectionClosed:
            pass
        self.assertFalse(hub.has_active_agent(dev_id))


if __name__ == "__main__":
    unittest.main()
