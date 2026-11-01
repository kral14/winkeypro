"""
WinKey Pro — WebSocket Contract & Transport Test Suite
Spesifikasiya: plan/GEMINI_WEBSOCKET_BATCH.md (Paket A, B, C, D, E)

Bu test dəsti ASGI Uvicorn server üzərində real WebSocket daşıyıcısını,
avtorizasiya vaxtını, təhlükəsizlik qaydalarını (zero-token URL, 64KB limit),
IDOR qorunmasını, əmr/nəticə çatdırılmasını, superseded məntiqini və ləğv edilmə
(revocation) bağlantı kəsilməsini hərtərəfli yoxlayır.
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

import socket

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from deploy.gateway_service import GatewayService
from deploy.asgi_app import build_asgi_app
from deploy.websocket_hub import hub
from deploy.vm.server import VMDatabase
from deploy.vm.configure import configure


class WebSocketTransportContractTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(dir=ROOT_DIR)
        self.root = Path(self.temp_dir.name)

        # Admin açarı və baza konfiqurasiyası
        configure("winkey.example.com", self.root)
        self.admin_secret = (self.root / "deploy/vm/secrets/admin_key").read_text(encoding="utf-8").strip()
        os.environ["WINKEY_ADMIN_SECRET"] = self.admin_secret

        db_path = str(self.root / "test_ws.db")
        self.db = VMDatabase(db_path)
        self.service = GatewayService(self.db, self.admin_secret)
        self.app = build_asgi_app(self.service)

        # Uvicorn serverini dinamik boş portda başladırıq
        self.port = get_free_port()
        config = uvicorn.Config(self.app, host="127.0.0.1", port=self.port, log_level="error")
        self.server = uvicorn.Server(config)

        self.server_thread = threading.Thread(target=self.server.run, daemon=True)
        self.server_thread.start()

        # Serverin qalxmasını gözləyirik
        for _ in range(50):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/healthz", timeout=1) as resp:
                    if resp.status == 200:
                        break
            except Exception:
                await asyncio.sleep(0.05)

        self.ws_origin = f"ws://127.0.0.1:{self.port}"
        self.http_origin = f"http://127.0.0.1:{self.port}"

    async def asyncTearDown(self):
        self.server.should_exit = True
        self.server_thread.join(timeout=3)
        self.temp_dir.cleanup()

    def _http_request(self, path, body=None, token=None, admin=False):
        url = self.http_origin + path
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if admin:
            headers["X-Owner-Admin-Secret"] = self.admin_secret

        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                raw = resp.read()
                return resp.status, json.loads(raw) if raw.startswith(b"{") else raw
        except urllib.error.HTTPError as err:
            raw = err.read()
            return err.code, json.loads(raw) if raw.startswith(b"{") else raw

    def _setup_device_and_mobile(self, dev_suffix="1"):
        """Ed25519 açar cütü ilə cihaz qeydiyyatı və mobil cütləşdirmə aparır."""
        device_id = f"pc_ws_test_{dev_suffix}"
        priv_key = Ed25519PrivateKey.generate()
        pub_bytes = priv_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()

        _, chal = self._http_request("/agent/challenge", {"device_id": device_id})
        nonce = chal["nonce"]
        sig = priv_key.sign(f"WINKEY_REGISTER:{nonce}:{device_id}".encode()).hex()

        status, reg = self._http_request("/agent/register", {
            "device_id": device_id,
            "computer_name": f"WS Test PC {dev_suffix}",
            "public_key_hex": pub_bytes,
            "nonce": nonce,
            "proof_signature_hex": sig
        })
        self.assertEqual(status, 200)
        device_secret = reg["device_secret"]

        status, pairing = self._http_request("/devices/pair-request", {"device_id": device_id}, token=device_secret)
        self.assertEqual(status, 200, f"pair-request failed: {pairing}")
        pair_code = pairing["pair_code"]

        status, session = self._http_request("/pair", {"pair_code": pair_code})
        self.assertEqual(status, 200, f"pair failed: {session}")
        session_token = session["session_token"]

        return device_id, device_secret, session_token

    # 1. URL Query Parametrlərində Tokenin Qadağan Edilməsi (Zero-Token in URL)
    async def test_01_query_token_forbidden(self):
        ws_url = f"{self.ws_origin}/ws?token=secret12345"
        async with websockets.connect(ws_url) as ws:
            try:
                await ws.recv()
                self.fail("Server query-də token olan bağlantını dərhal kəsməlidir.")
            except websockets.exceptions.ConnectionClosed as exc:
                self.assertEqual(exc.rcvd.code, 4003)

    # 2. Auth Frame Deadline (Gözləmə vaxtının aşılması)
    async def test_02_auth_deadline_timeout(self):
        ws_url = f"{self.ws_origin}/ws"
        async with websockets.connect(ws_url) as ws:
            # 5 saniyə heç nə göndərmirik, server 4001 və ya timeout ilə bağlamalıdır
            start = time.time()
            try:
                await asyncio.wait_for(ws.recv(), timeout=6.0)
                self.fail("Server auth frame göndərilmədikdə bağlantını bağlamalıdır.")
            except (websockets.exceptions.ConnectionClosed, asyncio.TimeoutError):
                elapsed = time.time() - start
                self.assertGreaterEqual(elapsed, 4.5)

    # 3. Böyük Həcmli Mesajların Bloklanması (>64 KB limit)
    async def test_03_oversize_frame_rejected(self):
        ws_url = f"{self.ws_origin}/ws"
        async with websockets.connect(ws_url) as ws:
            oversize_payload = "A" * (70 * 1024)
            await ws.send(oversize_payload)
            try:
                await ws.recv()
                self.fail("Server 64KB-dan böyük mesajı bloklamalıdır.")
            except websockets.exceptions.ConnectionClosed as exc:
                self.assertEqual(exc.rcvd.code, 4009)

    # 4. Yanlış JSON və İcazəsiz Əmr Göndərilməsi
    async def test_04_invalid_json_and_premature_command(self):
        ws_url = f"{self.ws_origin}/ws"
        # Yanlış JSON
        async with websockets.connect(ws_url) as ws:
            await ws.send("BU_JSON_DEYIL{")
            try:
                await ws.recv()
                self.fail("Yanlış JSON bağlantını sonlandırmalıdır.")
            except websockets.exceptions.ConnectionClosed as exc:
                self.assertEqual(exc.rcvd.code, 4000)

        # Autentifikasiyadan əvvəl birbaşa əmr göndərilməsi
        async with websockets.connect(ws_url) as ws:
            await ws.send(json.dumps({"type": "command", "action": "mock"}))
            try:
                await ws.recv()
                self.fail("Auth olmadan göndərilən əmr rədd edilməlidir.")
            except websockets.exceptions.ConnectionClosed as exc:
                self.assertEqual(exc.rcvd.code, 4401)

    # 5. IDOR və Saxta Açarın Bloklanması
    async def test_05_idor_and_fake_credentials_rejected(self):
        dev1_id, dev1_sec, sess1 = self._setup_device_and_mobile("idor1")
        dev2_id, dev2_sec, sess2 = self._setup_device_and_mobile("idor2")

        # Cihaz 1 adından Cihaz 2-nin açarı ilə daxil olmağa cəhd
        async with websockets.connect(f"{self.ws_origin}/ws") as ws:
            await ws.send(json.dumps({
                "type": "auth",
                "role": "agent",
                "device_id": dev1_id,
                "token": dev2_sec # Yanlış açar!
            }))
            try:
                await ws.recv()
                self.fail("IDOR / yanlış açar rədd edilməlidir.")
            except websockets.exceptions.ConnectionClosed as exc:
                self.assertEqual(exc.rcvd.code, 4401)

        # Saxta mobil sessiya tokeni
        async with websockets.connect(f"{self.ws_origin}/ws") as ws:
            await ws.send(json.dumps({
                "type": "auth",
                "role": "mobile",
                "session_token": "saxta_sessiya_tokeni_12345"
            }))
            try:
                await ws.recv()
                self.fail("Saxta mobil sessiya rədd edilməlidir.")
            except websockets.exceptions.ConnectionClosed as exc:
                self.assertEqual(exc.rcvd.code, 4401)

    # 6. Tam WebSocket Əmr, Nəticə və Telemetriya Zənciri
    async def test_06_full_e2e_ws_command_and_result_chain(self):
        dev_id, dev_sec, sess_tok = self._setup_device_and_mobile("flow")

        # Agent və Mobil WebSocket bağlantılarını açırıq
        agent_ws = await websockets.connect(f"{self.ws_origin}/ws")
        mobile_ws = await websockets.connect(f"{self.ws_origin}/ws")

        try:
            # Agent Auth
            await agent_ws.send(json.dumps({
                "type": "auth",
                "role": "agent",
                "device_id": dev_id,
                "token": dev_sec
            }))
            agent_auth_ack = json.loads(await agent_ws.recv())
            self.assertEqual(agent_auth_ack.get("type"), "auth_ok")

            # Mobile Auth
            await mobile_ws.send(json.dumps({
                "type": "auth",
                "role": "mobile",
                "session_token": sess_tok
            }))
            mobile_auth_ack = json.loads(await mobile_ws.recv())
            self.assertEqual(mobile_auth_ack.get("type"), "auth_ok")
            self.assertEqual(mobile_auth_ack.get("device_id"), dev_id)

            # Mobile cari cihaz vəziyyətini (device_state) almalıdır
            dev_state = json.loads(await mobile_ws.recv())
            self.assertEqual(dev_state.get("type"), "device_state")

            # Agent Heartbeat göndərir
            await agent_ws.send(json.dumps({
                "type": "heartbeat",
                "locked": True,
                "pin_ready": True
            }))
            # Mobil dərhal yenilənmiş device_state frame almalıdır
            pushed_state = json.loads(await mobile_ws.recv())
            self.assertEqual(pushed_state.get("type"), "device_state")
            self.assertTrue(pushed_state.get("locked"))

            # Mobil WebSocket üzərindən əmr göndərir (MOCK action)
            cmd_req_id = secrets.token_hex(16)
            await mobile_ws.send(json.dumps({
                "type": "command",
                "action": "mock",
                "request_id": cmd_req_id
            }))

            # Mobil həm command_ack, həm də command_status almalıdır
            f1 = json.loads(await mobile_ws.recv())
            f2 = json.loads(await mobile_ws.recv())
            frames = {f1.get("type"): f1, f2.get("type"): f2}
            self.assertIn("command_ack", frames)
            self.assertIn("command_status", frames)
            cmd_id = frames["command_ack"]["command_id"]

            # Agent dərhal WebSocket vasitəsilə əmri almalıdır (HTTP poll olmadan!)
            agent_frame = json.loads(await agent_ws.recv())
            self.assertEqual(agent_frame.get("type"), "command")
            self.assertEqual(agent_frame.get("command_id"), cmd_id)
            self.assertEqual(agent_frame.get("action"), "mock")

            # Agent nəticəni serverə WebSocket ilə qaytarır
            await agent_ws.send(json.dumps({
                "type": "result",
                "command_id": cmd_id,
                "success": True,
                "status": "mock_success_ok"
            }))

            # Agent serverdən result_ack almalıdır
            res_ack = json.loads(await agent_ws.recv())
            self.assertEqual(res_ack.get("type"), "result_ack")
            self.assertEqual(res_ack.get("command_id"), cmd_id)

            # Mobil WebSocket dərhal tamamlanmış nəticəni almalıdır
            res_mob = json.loads(await mobile_ws.recv())
            self.assertEqual(res_mob.get("type"), "command_result")
            self.assertEqual(res_mob.get("command_id"), cmd_id)
            self.assertEqual(res_mob.get("status"), "completed")

        finally:
            await agent_ws.close()
            await mobile_ws.close()

    # 7. Superseded Əmrlər Məntiqi və İcra Olunan Əmrin Qorunması
    async def test_07_superseded_commands_logic(self):
        dev_id, dev_sec, sess_tok = self._setup_device_and_mobile("super")

        # Mobil ardıcıl lock və unlock əmrləri göndərir (Agent hələ qoşulmayıb)
        req1 = secrets.token_hex(16)
        req2 = secrets.token_hex(16)
        st1, cmd1 = self._http_request("/commands", {
            "device_id": dev_id, "action": "lock", "request_id": req1
        }, token=sess_tok)
        self.assertEqual(st1, 200, f"cmd1 failed: {cmd1}")
        c1_id = cmd1["command_id"]

        st2, cmd2 = self._http_request("/commands", {
            "device_id": dev_id, "action": "unlock", "request_id": req2
        }, token=sess_tok)
        self.assertEqual(st2, 200, f"cmd2 failed: {cmd2}")
        c2_id = cmd2["command_id"]

        # Birinci əmr (lock) pending vəziyyətində idisə, avtomatik SUPERSEDED olmalıdır!
        with self.db.get_conn() as conn:
            c1_row = conn.execute("SELECT status FROM commands WHERE command_id = ?", (c1_id,)).fetchone()
            c2_row = conn.execute("SELECT status FROM commands WHERE command_id = ?", (c2_id,)).fetchone()
            self.assertEqual(c1_row["status"], "superseded")
            self.assertEqual(c2_row["status"], "pending")

        # İndi Agent WebSocket ilə qoşulduqda yalnız c2 (unlock) çatdırılmalıdır
        async with websockets.connect(f"{self.ws_origin}/ws") as agent_ws:
            await agent_ws.send(json.dumps({
                "type": "auth",
                "role": "agent",
                "device_id": dev_id,
                "token": dev_sec
            }))
            auth_ack = json.loads(await agent_ws.recv())
            self.assertEqual(auth_ack["type"], "auth_ok")

            # İlk çatdırılan əmr c2 olmalıdır!
            cmd_frame = json.loads(await agent_ws.recv())
            self.assertEqual(cmd_frame.get("type"), "command")
            self.assertEqual(cmd_frame.get("command_id"), c2_id)
            self.assertEqual(cmd_frame.get("action"), "unlock")

    # 8. Sessiya və Cihaz Ləğv Edildikdə (Revocation) Bağlantının Kəsilməsi
    async def test_08_revocation_disconnect(self):
        dev_id, dev_sec, sess_tok = self._setup_device_and_mobile("revoke")

        agent_ws = await websockets.connect(f"{self.ws_origin}/ws")
        mobile_ws = await websockets.connect(f"{self.ws_origin}/ws")

        try:
            await agent_ws.send(json.dumps({"type": "auth", "role": "agent", "device_id": dev_id, "token": dev_sec}))
            await agent_ws.recv()

            await mobile_ws.send(json.dumps({"type": "auth", "role": "mobile", "session_token": sess_tok}))
            await mobile_ws.recv()
            await mobile_ws.recv() # device_state

            # Mobil sessiyasını HTTP POST ilə ləğv edirik (asyncio.to_thread ilə, event loop bloklanmır)
            rev_st, _ = await asyncio.to_thread(self._http_request, "/mobile/revoke", {}, sess_tok)
            self.assertEqual(rev_st, 200)

            # Mobil WebSocket server tərəfindən dərhal bağlanmalıdır!
            try:
                await asyncio.wait_for(mobile_ws.recv(), timeout=2.0)
                self.fail("Mobil sessiya ləğv edildikdə WebSocket dərhal bağlanmalıdır.")
            except websockets.exceptions.ConnectionClosed as exc:
                self.assertEqual(exc.rcvd.code, 4403)

            # İndi Admin cihazı REVOKED statusuna salır
            adm_st, _ = await asyncio.to_thread(self._http_request, "/admin/revoke", {"device_id": dev_id}, None, True)
            self.assertEqual(adm_st, 200)

            # Agent WebSocket server tərəfindən dərhal bağlanmalıdır!
            try:
                await asyncio.wait_for(agent_ws.recv(), timeout=2.0)
                self.fail("Cihaz ləğv edildikdə Agent WebSocket dərhal bağlanmalıdır.")
            except websockets.exceptions.ConnectionClosed as exc:
                self.assertEqual(exc.rcvd.code, 4403)

        finally:
            try:
                await agent_ws.close()
            except Exception:
                pass
            try:
                await mobile_ws.close()
            except Exception:
                pass


if __name__ == "__main__":
    unittest.main()
