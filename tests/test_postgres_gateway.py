"""Run only against an explicitly supplied DISPOSABLE PostgreSQL database."""
import os
import unittest
from pathlib import Path
import sys
import secrets
import asyncio
import json
import socket
import threading
import time
import urllib.request
import uvicorn
import websockets
import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_vm_gateway as contracts
import test_gateway_concurrency as concurrency
from deploy.postgres_database import PostgresDatabase
from deploy.gateway_service import GatewayService
from deploy.asgi_app import build_asgi_app
from deploy.websocket_hub import hub

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class IsolatedSchema:
    def setUp(self):
        self.schema = 'winkey_test_' + secrets.token_hex(8)
        with psycopg.connect(os.environ['WINKEY_TEST_DATABASE_URL'], autocommit=True) as conn:
            conn.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(self.schema)))
        super().setUp()

    def database_factory(self, _):
        return PostgresDatabase(make_conninfo(os.environ['WINKEY_TEST_DATABASE_URL'],
                                options='-c search_path=' + self.schema))

    def tearDown(self):
        try:
            super().tearDown()
        finally:
            with psycopg.connect(os.environ['WINKEY_TEST_DATABASE_URL'], autocommit=True) as conn:
                conn.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(self.schema)))


@unittest.skipUnless(os.environ.get('WINKEY_TEST_DATABASE_URL'), 'Disposable PostgreSQL URL required')
class PostgresContract(IsolatedSchema, contracts.VMContract):
    pass


@unittest.skipUnless(os.environ.get('WINKEY_TEST_DATABASE_URL'), 'Disposable PostgreSQL URL required')
class PostgresConcurrency(IsolatedSchema, concurrency.Concurrency):
    pass


@unittest.skipUnless(os.environ.get('WINKEY_TEST_DATABASE_URL'), 'Disposable PostgreSQL URL required')
class PostgresWebSocketContract(IsolatedSchema, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.db = self.database_factory(None)
        self.admin_secret = secrets.token_hex(32)
        os.environ["WINKEY_ADMIN_SECRET"] = self.admin_secret
        self.service = GatewayService(self.db, self.admin_secret)
        self.app = build_asgi_app(self.service)

        self.port = get_free_port()
        config = uvicorn.Config(self.app, host="127.0.0.1", port=self.port, log_level="error")
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
        if hasattr(self.db, "pool"):
            self.db.pool.close()

    def _http_request(self, path, body=None, token=None):
        url = self.http_origin + path
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())

    async def test_postgres_real_ws_agent_and_command_e2e(self):
        dev_id = "pg_ws_device_" + secrets.token_hex(4)
        priv = Ed25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        chal = self._http_request("/agent/challenge", {"device_id": dev_id})
        nonce = chal["nonce"]
        sig = priv.sign(f"WINKEY_REGISTER:{nonce}:{dev_id}".encode()).hex()

        reg = self._http_request("/agent/register", {
            "device_id": dev_id, "computer_name": "PG Test PC",
            "public_key_hex": pub_bytes, "nonce": nonce, "proof_signature_hex": sig
        })
        dev_sec = reg["device_secret"]

        p_req = self._http_request("/devices/pair-request", {"device_id": dev_id}, token=dev_sec)
        pair = self._http_request("/pair", {"pair_code": p_req["pair_code"]})
        sess_token = pair["session_token"]

        # Connect Agent WebSocket
        async with websockets.connect(f"{self.ws_origin}/ws") as agent_ws, \
                   websockets.connect(f"{self.ws_origin}/ws") as mobile_ws:

            # 1. Auth agent
            await agent_ws.send(json.dumps({"type": "auth", "role": "agent", "device_id": dev_id, "token": dev_sec}))
            agent_auth = json.loads(await agent_ws.recv())
            self.assertEqual(agent_auth.get("type"), "auth_ok")

            # 2. Auth mobile
            await mobile_ws.send(json.dumps({"type": "auth", "role": "mobile", "session_token": sess_token}))
            mobile_auth = json.loads(await mobile_ws.recv())
            self.assertEqual(mobile_auth.get("type"), "auth_ok")

            # Mobile receives initial device_state
            dev_state = json.loads(await mobile_ws.recv())
            self.assertEqual(dev_state.get("type"), "device_state")

            # 3. Mobile sends command via WS
            req_id = secrets.token_hex(16)
            await mobile_ws.send(json.dumps({"type": "command", "action": "mock", "request_id": req_id}))

            # Mobile receives ack and status
            f1 = json.loads(await mobile_ws.recv())
            f2 = json.loads(await mobile_ws.recv())
            frames = {f1.get("type"): f1, f2.get("type"): f2}
            self.assertIn("command_ack", frames)
            cmd_id = frames["command_ack"]["command_id"]

            # 4. Agent receives command via WS
            agent_frame = json.loads(await asyncio.wait_for(agent_ws.recv(), timeout=3.0))
            self.assertEqual(agent_frame.get("type"), "command")
            self.assertEqual(agent_frame.get("action"), "mock")
            self.assertEqual(agent_frame.get("command_id"), cmd_id)

            # 5. Agent sends execution result via WS
            await agent_ws.send(json.dumps({
                "type": "result", "command_id": cmd_id, "device_id": dev_id,
                "success": True, "status": "SUCCESS_PG_MOCK"
            }))

            # 6. Agent receives ACK via WS
            agent_ack = json.loads(await asyncio.wait_for(agent_ws.recv(), timeout=3.0))
            self.assertEqual(agent_ack.get("type"), "result_ack")
            self.assertEqual(agent_ack.get("command_id"), cmd_id)

            # 7. Mobile receives command_result via WS
            mob_res = json.loads(await asyncio.wait_for(mobile_ws.recv(), timeout=3.0))
            self.assertEqual(mob_res.get("type"), "command_result")
            self.assertEqual(mob_res.get("command_id"), cmd_id)
            self.assertEqual(mob_res.get("status"), "completed")

        # 8. Verify DB row in PostgreSQL directly
        with self.db.get_conn() as conn:
            dev_row = conn.execute("SELECT device_id, computer_name FROM devices WHERE device_id = ?", (dev_id,)).fetchone()
            self.assertIsNotNone(dev_row)
            cmd_row = conn.execute("SELECT command_id, status, result_status FROM commands WHERE command_id = ?", (cmd_id,)).fetchone()
            self.assertIsNotNone(cmd_row)
            self.assertEqual(cmd_row["status"], "completed")
            self.assertEqual(cmd_row["result_status"], "SUCCESS_PG_MOCK")


if __name__ == '__main__':
    unittest.main()
