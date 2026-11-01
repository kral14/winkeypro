"""
WinKey Pro — Durable DB Claim / Lease Protocol & Race Condition Tests (R2-01)
Spesifikasiya: plan/GEMINI_WEBSOCKET_REVISION_2.md (R2-01)

Bu test süiti idarə olunan gate (dispatch_gate_hook) vasitəsilə:
1. HTTP poll və WebSocket push arasında paralel yarış sınağını;
2. Paralel reconnect edən iki agent arasında yarış sınağını;
3. Çatdırılma uğursuz olduqda claim-in buraxılıb bərpa edilməsini
həm izolyasiya edilmiş SQLite, həm də PostgreSQL üzərində deterministik şəkildə yoxlayır.
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


class ClaimRaceMixin:
    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(dir=ROOT_DIR)
        self.root = Path(self.temp_dir.name)
        configure("winkey.example.com", self.root)
        self.admin_secret = (self.root / "deploy/vm/secrets/admin_key").read_text(encoding="utf-8").strip()
        os.environ["WINKEY_ADMIN_SECRET"] = self.admin_secret

        self.db = self._create_db()
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
        if hasattr(self.db, "pool") and self.db.pool:
            self.db.pool.close()
        self.temp_dir.cleanup()

    def _create_db(self):
        db_path = str(self.root / "test_race.db")
        return VMDatabase(db_path)

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
            "device_id": dev_id, "computer_name": f"Race PC {prefix}",
            "public_key_hex": pub, "nonce": nonce, "proof_signature_hex": sig
        })
        dev_sec = reg["device_secret"]

        _, p_req = self._http_req("/devices/pair-request", {"device_id": dev_id}, token=dev_sec)
        _, pair = self._http_req("/pair", {"pair_code": p_req["pair_code"]})
        sess_token = pair["session_token"]

        return dev_id, dev_sec, sess_token

    # SINAQ 1: HTTP poll və WS push arasında idarə olunan gate yarışı (R2-01)
    async def test_01_http_poll_vs_ws_push_race(self):
        dev_id, dev_sec, sess_tok = self._setup_device("race_hp_ws")

        # Agent WebSocket açırıq
        agent_ws = await websockets.connect(f"{self.ws_origin}/ws")
        await agent_ws.send(json.dumps({"type": "auth", "role": "agent", "device_id": dev_id, "token": dev_sec}))
        auth_ack = json.loads(await agent_ws.recv())
        self.assertEqual(auth_ack.get("type"), "auth_ok")

        gate_entered = threading.Event()
        gate_release = threading.Event()

        def controlled_gate(cmd_id):
            gate_entered.set()
            gate_release.wait(timeout=5.0)

        # Gate hook-u aktivləşdiririk
        self.service.dispatch_gate_hook = controlled_gate

        # Mobil tərəfdən asinxron komanda göndəririk
        req_id = secrets.token_hex(16)
        cmd_task = asyncio.create_task(asyncio.to_thread(
            self._http_req, "/commands", {"device_id": dev_id, "action": "mock", "request_id": req_id}, sess_tok
        ))

        # Gate-ə daxil olmağı gözləyirik (əmr DB-də enqueue olunub, lakin WS push hələ gözləyir)
        await asyncio.to_thread(gate_entered.wait, 3.0)

        # Bu dəqiq aralıqda paralel olaraq HTTP poll (/agent/poll) çağırırıq!
        poll_status, poll_data = await asyncio.to_thread(
            self._http_req, "/agent/poll", {"device_id": dev_id, "locked": True, "pin_ready": True}, dev_sec
        )

        # Gate-i açırıq ki, WS push davam etsin
        gate_release.set()
        cmd_status, cmd_resp = await cmd_task
        self.assertEqual(cmd_status, 200)
        cmd_id = cmd_resp["command_id"]

        # İndi iki tərəfin nəticəsini yoxlayırıq:
        # Əgər WS claim edibsə, poll_data["command"] = None olmalıdır və WS agent əmri almalıdır.
        # Əgər poll claim edibsə, poll_data["command"] = cmd_id olmalıdır və WS agent heç bir əmr almamalıdır.
        # Heç bir halda HƏR İKİSİ əmri götürə BİLMƏZ (Dəqiq 1 Çatdırılma)!
        deliveries = 0
        if poll_data.get("command") is not None:
            self.assertEqual(poll_data["command"]["id"], cmd_id)
            deliveries += 1

        try:
            ws_frame = json.loads(await asyncio.wait_for(agent_ws.recv(), timeout=0.8))
            if ws_frame.get("type") == "command":
                self.assertEqual(ws_frame["command_id"], cmd_id)
                deliveries += 1
        except asyncio.TimeoutError:
            pass

        # İNVARYANT: Eyni əmr üçün çatdırılma sayı DƏQİQ BİRDİR (0 deyil, 2 deyil, DƏQİQ 1)!
        self.assertEqual(deliveries, 1, f"Yarış zamanı çatdırılma sayı {deliveries} oldu! 1 olmalıdır.")

        # Nəticəni təqdim edirik və terminal statusu yoxlayırıq
        self.service.dispatch_gate_hook = None
        await agent_ws.close()

    # SINAQ 2: Paralel Reconnect Yarışı (R2-01)
    async def test_02_parallel_reconnect_race(self):
        dev_id, dev_sec, sess_tok = self._setup_device("race_reconn")

        # Əvvəlcə agent qoşulmadan əmri növbəyə salırıq
        req_id = secrets.token_hex(16)
        c_stat, c_data = self._http_req("/commands", {"device_id": dev_id, "action": "mock", "request_id": req_id}, sess_tok)
        self.assertEqual(c_stat, 200)
        cmd_id = c_data["command_id"]

        # Eyni anda İKİ fərqli agent bağlantısı reconnect edir və auth göndərir
        ws1 = await websockets.connect(f"{self.ws_origin}/ws")
        ws2 = await websockets.connect(f"{self.ws_origin}/ws")

        # Hər ikisinə paralel auth göndəririk
        await asyncio.gather(
            ws1.send(json.dumps({"type": "auth", "role": "agent", "device_id": dev_id, "token": dev_sec})),
            ws2.send(json.dumps({"type": "auth", "role": "agent", "device_id": dev_id, "token": dev_sec}))
        )

        ack1 = json.loads(await ws1.recv())
        ack2 = json.loads(await ws2.recv())
        self.assertEqual(ack1.get("type"), "auth_ok")
        self.assertEqual(ack2.get("type"), "auth_ok")

        # İki agent soketindən hansının əmri aldığını sayırıq
        command_frames_received = 0
        for ws in (ws1, ws2):
            try:
                frame = json.loads(await asyncio.wait_for(ws.recv(), timeout=0.8))
                if frame.get("type") == "command" and frame.get("command_id") == cmd_id:
                    command_frames_received += 1
            except asyncio.TimeoutError:
                pass

        await ws1.close()
        await ws2.close()

        # İNVARYANT: Reconnect zamanı pending əmr DƏQİQ BİR agent soketinə çatdırılmalıdır!
        self.assertEqual(command_frames_received, 1, f"Paralel reconnect zamanı {command_frames_received} agent əmr aldı! Dəqiq 1 olmalıdır.")

    # SINAQ 3: Çatdırılma Uğursuzluğu və Claim Bərpası (R2-01)
    async def test_03_failed_delivery_releases_claim_for_recovery(self):
        dev_id, dev_sec, sess_tok = self._setup_device("fail_recover")

        # 1. Agent qoşulur
        ws = await websockets.connect(f"{self.ws_origin}/ws")
        await ws.send(json.dumps({"type": "auth", "role": "agent", "device_id": dev_id, "token": dev_sec}))
        _ = await ws.recv()

        # Soketi zorla bağlayırıq (agent şəbəkədən qopur)
        await ws.close()

        # İndi komanda göndəririk
        req_id = secrets.token_hex(16)
        c_stat, c_data = self._http_req("/commands", {"device_id": dev_id, "action": "mock", "request_id": req_id}, sess_tok)
        self.assertEqual(c_stat, 200)
        cmd_id = c_data["command_id"]

        # Çünki agent qopmuşdu, push uğursuz oldu və claim dərhal 'pending' vəziyyətinə buraxılmalıdır!
        # Sonrakı HTTP poll və ya reconnect əmri dərhal bərpa edə bilməlidir:
        poll_stat, poll_resp = self._http_req("/agent/poll", {"device_id": dev_id, "locked": True, "pin_ready": True}, dev_sec)
        self.assertEqual(poll_stat, 200)
        self.assertIsNotNone(poll_resp.get("command"), "Uğursuz göndərişdən sonra əmr bərpa olunmadı!")
        self.assertEqual(poll_resp["command"]["id"], cmd_id)


class ClaimRaceSQLite(ClaimRaceMixin, unittest.IsolatedAsyncioTestCase):
    pass


@unittest.skipUnless(os.environ.get('WINKEY_TEST_DATABASE_URL'), 'Disposable PostgreSQL URL required')
class ClaimRacePostgres(ClaimRaceMixin, unittest.IsolatedAsyncioTestCase):
    def _create_db(self):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        from deploy.postgres_database import PostgresDatabase

        self.schema = 'winkey_race_' + secrets.token_hex(8)
        with psycopg.connect(os.environ['WINKEY_TEST_DATABASE_URL'], autocommit=True) as conn:
            conn.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(self.schema)))

        return PostgresDatabase(make_conninfo(os.environ['WINKEY_TEST_DATABASE_URL'],
                                options='-c search_path=' + self.schema))

    async def asyncTearDown(self):
        try:
            await super().asyncTearDown()
        finally:
            if hasattr(self, 'schema') and os.environ.get('WINKEY_TEST_DATABASE_URL'):
                import psycopg
                from psycopg import sql
                with psycopg.connect(os.environ['WINKEY_TEST_DATABASE_URL'], autocommit=True) as conn:
                    conn.execute(sql.SQL('DROP SCHEMA IF EXISTS {} CASCADE').format(sql.Identifier(self.schema)))


if __name__ == "__main__":
    unittest.main()
