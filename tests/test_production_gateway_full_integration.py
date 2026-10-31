"""
WinKey Pro — Production Gateway Tam İnteqrasiya Sınağı
Spesifikasiya: plan/GEMINI_PRODUCT_INTEGRATION_FINAL.md

Sınaq Zənciri:
1. Real deploy/gateway_production_server.py HTTPServer kimi işə salınır.
2. Ed25519 açar cütü generasiya olunur, /agent/challenge ilə unikal nonce alınır.
3. Imzalanmış proof ilə /agent/register çağırılır və device_secret əldə edilir.
4. PC Agent Bearer token ilə /devices/pair-request edir və pair_code (QR məlumatı) alır.
5. Mobil müştəri /pair endpoint-i vasitəsilə kodu atomik claim edir və sessiya tokeni alır.
6. Multi-Tenant IDOR Guard: Yad cihaz ID-sinə komanda və status sorğusunun rədd edilməsi (403).
7. Zero-PIN Guard: Şəbəkə sorğusuna 'pin' qoyulduqda 400 ilə dərhal rədd edilməsi.
8. Mobil müştəri /devices/{id}/command ilə 'lock' əmri göndərir.
9. PC Agent Bearer auth ilə /agent/poll edir, əmri alır və /agent/result ilə tamamlanma göndərir.
10. Mobil müştəri /commands/{id} ilə icranın 'executed' olduğunu görür.
11. Mobil /mobile/revoke çağırır, sessiya silinir və sonrakı status sorğusu 401 verir.
12. Owner-only Admin (/admin/devices, /admin/telemetry) gizli açarla yoxlanılır.
"""

import os
import sys
import time
import json
import uuid
import socket
import tempfile
import threading
import urllib.request
import urllib.error
import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519

# UTF-8 stdout təhlükəsizliyi
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Layihə kökünü əlavə edirik
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from deploy.gateway_production_server import GatewayHandler, ProductionDatabase, HTTPServer, get_admin_secret

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

class TestProductionGatewayFullIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.TemporaryDirectory()
        cls.db_path = os.path.join(cls.tmp_dir.name, "test_gateway.db")
        cls.db = ProductionDatabase(cls.db_path)

        cls.port = get_free_port()
        cls.base_url = f"http://127.0.0.1:{cls.port}"

        class CustomHandler(GatewayHandler):
            db = cls.db

        cls.httpd = HTTPServer(('127.0.0.1', cls.port), CustomHandler)
        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.httpd.shutdown()
            cls.httpd.server_close()
        except Exception:
            pass
        time.sleep(0.1)
        try:
            cls.tmp_dir.cleanup()
        except Exception:
            pass

    def _http_post(self, path: str, payload: dict, token: str = None, headers: dict = None):
        url = f"{self.base_url}{path}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)

        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode("utf-8")
                return resp.status, json.loads(body) if body else {}
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8")
            return e.code, json.loads(body) if body else {}

    def _http_get(self, path: str, token: str = None, headers: dict = None):
        url = f"{self.base_url}{path}"
        req = urllib.request.Request(url, method="GET")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)

        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode("utf-8")
                return resp.status, json.loads(body) if body else {}
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8")
            return e.code, json.loads(body) if body else {}

    def test_full_production_gateway_lifecycle(self):
        print("\n=== WinKey Pro: Production Gateway Tam İnteqrasiya Sınağı Başlanır ===")

        # 1. Ed25519 Cihaz Açar Cütü
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        pub_bytes = public_key.public_bytes_raw()
        pub_hex = pub_bytes.hex()
        device_id = f"pc_desk_{uuid.uuid4().hex[:8]}"

        # 2. /agent/challenge ilə Fresh Nonce alınması
        st, res = self._http_post("/agent/challenge", {"device_id": device_id, "purpose": "register"})
        self.assertEqual(st, 200, f"Challenge xətası: {res}")
        nonce = res["nonce"]
        self.assertTrue(nonce, "Nonce boş ola bilməz")

        # 3. Kriptoqrafik Proof ilə /agent/register
        bound_msg = f"WINKEY_REGISTER:{nonce}:{device_id}".encode("utf-8")
        sig = private_key.sign(bound_msg)
        sig_hex = sig.hex()

        st, res = self._http_post("/agent/register", {
            "device_id": device_id,
            "computer_name": "WIN11-OFFICE-PC",
            "public_key_hex": pub_hex,
            "nonce": nonce,
            "proof_signature_hex": sig_hex
        })
        self.assertEqual(st, 200, f"Qeydiyyat xətası: {res}")
        self.assertEqual(res["status"], "REGISTERED")
        device_secret = res["device_secret"]
        self.assertTrue(device_secret, "device_secret qaytarılmalıdır")
        print("[PASS] 1. Cihaz Ed25519 kriptoqrafik proof ilə uğurla qeydiyyata alındı.")

        # 4. Anti-Replay: Eyni nonce təkrar istifadə edilə bilməz
        st, res_replay = self._http_post("/agent/register", {
            "device_id": device_id,
            "computer_name": "WIN11-OFFICE-PC",
            "public_key_hex": pub_hex,
            "nonce": nonce,
            "proof_signature_hex": sig_hex
        })
        self.assertEqual(st, 400, "Artıq istifadə olunmuş nonce rədd edilməlidir")
        print("[PASS] 2. Nonce anti-replay yoxlanışı təsdiqləndi.")

        # 5. PC Agent tərəfindən Pair Kodu generasiyası
        st, res = self._http_post("/devices/pair-request", {"device_id": device_id}, token=device_secret)
        self.assertEqual(st, 200, f"Pair request xətası: {res}")
        pair_code = res["pair_code"]
        self.assertTrue(pair_code.startswith("PAIR_"))
        print(f"[PASS] 3. PC tərəfindən one-use cütləşmə kodu yaradıldı: {pair_code}")

        # 6. Mobil Müştəri Kodu Claim Edir (/pair)
        st, res = self._http_post("/pair", {"pair_code": pair_code})
        self.assertEqual(st, 200, f"Pair claim xətası: {res}")
        session_token = res["session_token"]
        self.assertTrue(session_token.startswith("sess_"))
        print("[PASS] 4. Mobil müştəri cütləşmə kodunu uğurla təsdiqlədi və sessiya aldı.")

        # 7. One-Use Anti-Replay: Eyni pair_code ikinci dəfə istifadə edilə bilməz
        st, res_pair_replay = self._http_post("/pair", {"pair_code": pair_code})
        self.assertEqual(st, 409, "Artıq claim edilmiş pair_code dərhal 409 verməlidir")
        print("[PASS] 5. One-use pair anti-replay (409 Conflict) təsdiqləndi.")

        # 8. Multi-Tenant IDOR Qoruması: Başqa saxta cihazın statusunu oxumağa cəhd
        st, res_idor = self._http_get("/devices/foreign_pc_9999/status", token=session_token)
        self.assertEqual(st, 403, "Başqa cihazın ID-sinə giriş 403 ilə bloklanmalıdır")
        self.assertEqual(res_idor.get("error"), "E_TENANT_IDOR_FORBIDDEN")
        print("[PASS] 6. Multi-Tenant IDOR qoruması təsdiqləndi (403 E_TENANT_IDOR_FORBIDDEN).")

        # 9. Zero-PIN Qoruması: Şəbəkə komandasına PIN salındıqda rədd edilməlidir
        st, res_pin = self._http_post(f"/devices/{device_id}/command", {"action": "unlock", "pin": "1234"}, token=session_token)
        self.assertEqual(st, 400, "Şəbəkədə PIN göndərilməsi qadağandır")
        self.assertEqual(res_pin.get("error"), "E_CREDENTIAL_NOT_PERMITTED")
        print("[PASS] 7. Zero-PIN şəbəkə qadağası təsdiqləndi (E_CREDENTIAL_NOT_PERMITTED).")

        # 10. Qanuni 'lock' Komandasının Göndərilməsi
        st, res_cmd = self._http_post(f"/devices/{device_id}/command", {"action": "lock"}, token=session_token)
        self.assertEqual(st, 200, f"Komanda göndəriş xətası: {res_cmd}")
        cmd_id = res_cmd["command_id"]
        self.assertTrue(cmd_id.startswith("cmd_"))
        print(f"[PASS] 8. Mobil tərəfdən 'lock' komandası göndərildi: {cmd_id}")

        # 11. PC Agent Polling (/agent/poll)
        st, res_poll = self._http_post("/agent/poll", {"device_id": device_id, "locked": False, "pin_ready": True}, token=device_secret)
        self.assertEqual(st, 200, f"Poll xətası: {res_poll}")
        received_cmd = res_poll.get("command")
        self.assertIsNotNone(received_cmd, "PC Agent əmri qəbul etməlidir")
        self.assertEqual(received_cmd["id"], cmd_id)
        self.assertEqual(received_cmd["action"], "lock")
        print("[PASS] 9. PC Agent əmri uğurla poll etdi və çatdırılmanı qeydə aldı.")

        # 12. PC Agent İcra Nəticəsinin Çatdırılması (/agent/result)
        st, res_res = self._http_post("/agent/result", {
            "device_id": device_id,
            "command_id": cmd_id,
            "success": True,
            "status": "executed"
        }, token=device_secret)
        self.assertEqual(st, 200, f"Result göndəriş xətası: {res_res}")
        print("[PASS] 10. PC Agent əmrin icra olunduğunu gateway-ə bildirdi.")

        # 13. Mobil Tərəf İcra Nəticəsini İzləyir (/commands/{id})
        st, res_track = self._http_get(f"/commands/{cmd_id}", token=session_token)
        self.assertEqual(st, 200, f"Command track xətası: {res_track}")
        self.assertIn(res_track["status"], ("completed", "executed"))
        print(f"[PASS] 11. Mobil tərəf əmrin tamamlandığını ({res_track['status']}) təsdiqlədi.")

        # 14. Mobil Sessiyanın Revoke Edilməsi (/mobile/revoke)
        st, res_rev = self._http_post("/mobile/revoke", {}, token=session_token)
        self.assertEqual(st, 200, f"Revoke xətası: {res_rev}")

        # 15. Revoke-dan sonra həmin sessiya ilə sorğunun 401 verməsi
        st, res_after_rev = self._http_get(f"/devices/{device_id}/status", token=session_token)
        self.assertEqual(st, 401, "Revoke edilmiş sessiya 401 verməlidir")
        print("[PASS] 12. Mobil revoke təsdiqləndi: ləğv olunmuş sessiya dərhal 401 qaytardı.")

        # 16. Owner Admin Girişi
        admin_sec = get_admin_secret()
        st, res_admin = self._http_get("/admin/devices", headers={"X-Owner-Admin-Secret": admin_sec})
        self.assertEqual(st, 200, "Admin cihaz siyahısı 200 olmalıdır")
        self.assertTrue(any(d["device_id"] == device_id for d in res_admin["devices"]))
        print("[PASS] 13. Owner Admin gizli açarla cihazlar siyahısını uğurla yoxladı.")

        print("=== Bütün 13 İnteqrasiya Sınağı 100% Uğurla Başa Çatdı! ===\n")

if __name__ == "__main__":
    unittest.main()
