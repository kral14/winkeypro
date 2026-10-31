"""
WinKey Pro — Native Worker -> Production Gateway Real Komanda və Nəticə İnteqrasiya Sınağı
Spesifikasiya: plan/GEMINI_WORKER_TRUST_FINAL.md (Gateway İnteqrasiya Bölməsi)

Yoxlayır:
1. Production Gateway Server (deploy/gateway_production_server.py) işə salınır.
2. Faktiki Ed25519 qeydiyyatı və mobil cütləşmə yaradılır (One-Use Pair Claim).
3. Real native binar prosesi (winkey_service.exe --worker) işə salınır.
4. Mobil token vasitəsilə təhlükəsiz nonphysical mock komandası növbəyə qoyulur.
5. Heç bir kənar HTTP injection OLMADAN, məhz native worker prosesinin özü
   /agent/poll ilə komandanı qəbul edir, icra edir və /agent/result ilə çatdırır.
6. Mobil tərəf /commands/<cmd_id> vasitəsilə native worker-in çatdırdığı nəticəni oxuyur
   (status == "completed", result == "DEMO_MOCK_ACTION").
7. Mobil revoke axını ilə token serverdə ləğv edilir (401 E_INVALID_SESSION).
8. Sınaq heç vaxt canlı ekranı kilidləmir və ya unlock inputu göndərmir.
"""

import os
import sys
import json
import time
import socket
import shutil
import tempfile
import subprocess
import threading
import unittest
from http.server import HTTPServer

import urllib.request
import urllib.error
from cryptography.hazmat.primitives.asymmetric import ed25519

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_PY = os.path.join(ROOT_DIR, "deploy", "gateway_production_server.py")
SERVICE_BIN = os.path.join(ROOT_DIR, "apps", "winkey_service", "target", "release", "winkey_service.exe")

def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def http_req(url: str, method: str = "GET", data: dict = None, headers: dict = None):
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            code = resp.getcode()
            res_body = json.loads(resp.read().decode("utf-8"))
            return code, res_body
    except urllib.error.HTTPError as e:
        err_body = {}
        try:
            err_body = json.loads(e.read().decode("utf-8"))
        except Exception:
            pass
        return e.code, err_body

def send_pipe_msg(msg: str, timeout_sec: float = 3.0) -> str:
    import ctypes
    from ctypes import wintypes
    k = ctypes.WinDLL('kernel32', use_last_error=True)
    H = ctypes.c_void_p
    k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, H, wintypes.DWORD, wintypes.DWORD, H]
    k.CreateFileW.restype = H
    k.WriteFile.argtypes = [H, wintypes.LPCVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), H]
    k.WriteFile.restype = wintypes.BOOL
    k.ReadFile.argtypes = [H, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), H]
    k.ReadFile.restype = wintypes.BOOL
    k.CloseHandle.argtypes = [H]

    t0 = time.time()
    while time.time() - t0 < timeout_sec:
        handle = k.CreateFileW(
            r"\\.\pipe\WinKey_Service_IPC",
            0x0012008B,  # PIPE_MIN_USER_CHANNEL_MASK
            0,
            None,
            3,  # OPEN_EXISTING
            0x00110000,  # SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION
            None
        )
        if handle and handle != H(-1).value:
            data = msg.encode("utf-8")
            n = wintypes.DWORD()
            k.WriteFile(handle, data, len(data), ctypes.byref(n), None)
            buf = ctypes.create_string_buffer(4096)
            k.ReadFile(handle, buf, len(buf), ctypes.byref(n), None)
            k.CloseHandle(handle)
            return buf.raw[:n.value].decode("utf-8", errors="replace")
        time.sleep(0.1)
    raise TimeoutError(f"Named Pipe əlçatan olmadı ({timeout_sec}s)")

class TestNativeWorkerGatewayAction(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="winkey_worker_gw_")
        self.data_dir = os.path.join(self.tmp_dir, "WinKeyData")
        os.makedirs(self.data_dir, exist_ok=True)

        # Cari istifadəçinin SID-sini owner.sid olaraq yazırıq
        import win32security, win32api
        user_sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(
            win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY),
            win32security.TokenUser
        )[0])
        with open(os.path.join(self.data_dir, "owner.sid"), "w", encoding="utf-8") as f:
            f.write(user_sid)

        self.port = get_free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.db_path = os.path.join(self.tmp_dir, "gateway_test.db")

        # Gateway serverini başladırıq
        self.gw_proc = subprocess.Popen(
            [sys.executable, GATEWAY_PY, str(self.port), self.db_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        time.sleep(1.0)
        self.assertIsNone(self.gw_proc.poll(), "Gateway serveri başlamadı")

    def tearDown(self):
        if hasattr(self, "gw_proc") and self.gw_proc.poll() is None:
            self.gw_proc.terminate()
            self.gw_proc.wait()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_native_worker_polls_and_executes_mock_action(self):
        """Native worker-in Gateway-dən komanda qəbul edib real icra nəticəsi göndərməsi."""
        
        # 1. Cihaz üçün Ed25519 açar cütü generasiya edirik
        priv_key = ed25519.Ed25519PrivateKey.generate()
        pub_bytes = priv_key.public_key().public_bytes_raw()
        pub_hex = pub_bytes.hex()
        device_id = f"pc_native_{pub_hex[:8]}"

        # 2. Challenge alırıq
        code, chal_resp = http_req(f"{self.base_url}/agent/challenge", "POST", {"device_id": device_id})
        self.assertEqual(code, 200)
        nonce = chal_resp["nonce"]

        # 3. İmzalı qeydiyyat
        bound_msg = f"WINKEY_REGISTER:{nonce}:{device_id}".encode("utf-8")
        proof_sig = priv_key.sign(bound_msg).hex()

        reg_data = {
            "device_id": device_id,
            "computer_name": "TEST-NATIVE-PC",
            "public_key_hex": pub_hex,
            "nonce": nonce,
            "proof_signature_hex": proof_sig
        }
        code, reg_resp = http_req(f"{self.base_url}/agent/register", "POST", reg_data)
        self.assertEqual(code, 200)
        device_secret = reg_resp["device_secret"]

        # 4. Cütləşmə kodu yaradırıq (Pair Request)
        code, pair_req = http_req(
            f"{self.base_url}/devices/pair-request",
            "POST",
            {"device_id": device_id},
            {"Authorization": f"Bearer {device_secret}"}
        )
        self.assertEqual(code, 200)
        pair_code = pair_req["pair_code"]

        # 5. Mobil cütləşmə (One-Use Pair Claim)
        code, pair_resp = http_req(f"{self.base_url}/pair", "POST", {"pair_code": pair_code})
        self.assertEqual(code, 200)
        mobile_session = pair_resp["session_token"]
        self.assertTrue(mobile_session.startswith("sess_"))

        # 6. İlkin konfiqurasiya (Python secret yazmır, yalnız origin təyin edilir)
        config = {
            "gateway_origin": self.base_url
        }
        with open(os.path.join(self.data_dir, "config.json"), "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

        # 7. Native Worker prosesini işə salırıq!
        worker_proc = subprocess.Popen(
            [SERVICE_BIN, "--worker", "--data-dir", self.data_dir, "--version-marker", "v0.1.0-gw-test"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        time.sleep(1.0)
        self.assertIsNone(worker_proc.poll(), "Worker prosesi çökməməlidir")

        try:
            # 7b. IPC üzərindən Desktop Onboarding Provisioning (REM-024 / REM-027):
            # Python config.json-a plain secret yazmır! Worker IPC Named Pipe ilə device_id və secret təmin edilir:
            prov_cmd = json.dumps({
                "ProvisionDevice": {
                    "device_id": device_id,
                    "device_secret": device_secret
                }
            })
            prov_resp = send_pipe_msg(f"{prov_cmd}\n", timeout_sec=3.0)
            self.assertIn("Ack", prov_resp, f"Provisioning Ack alınmadı: {prov_resp}")
            print(f"[PASS] IPC ProvisionDevice icra olundu və DPAPI vault təhlükəsiz yazıldı: {prov_resp.strip()}")

            # DPAPI vault faylının yaradıldığını təsdiqləyirik
            dpapi_path = os.path.join(self.data_dir, "device_secret.dpapi")
            self.assertTrue(os.path.exists(dpapi_path), "device_secret.dpapi faylı yaranmalıdır")

            # 8. Mobil tərəf nonphysical mock komandası göndərir
            code, cmd_resp = http_req(
                f"{self.base_url}/devices/{device_id}/command",
                "POST",
                {"action": "mock"},
                {"Authorization": f"Bearer {mobile_session}"}
            )
            self.assertEqual(code, 200)
            self.assertTrue(cmd_resp["success"])
            cmd_id = cmd_resp["command_id"]
            print(f"[TEST_ACTION] Komanda növbəyə qoyuldu: {cmd_id}")

            # 9. Native worker-in komandanı poll edib nəticəni qaytarmasını gözləyirik
            completed = False
            result_val = None
            t0 = time.time()
            while time.time() - t0 < 8.0:
                time.sleep(0.5)
                code, stat_resp = http_req(
                    f"{self.base_url}/commands/{cmd_id}",
                    "GET",
                    headers={"Authorization": f"Bearer {mobile_session}"}
                )
                if code == 200 and stat_resp.get("status") == "completed":
                    completed = True
                    result_val = stat_resp.get("result")
                    break

            self.assertTrue(completed, "Native worker komandanı qəbul edib nəticəni serverə çatdırmalı idi!")
            self.assertIn("MOCK", str(result_val), f"Gözlənilən mock nəticə alınmadı: {result_val}")
            print(f"[PASS] Native worker komandanı uğurla icra etdi və nəticə çatdırıldı: {result_val}")

            # 10. Mobil Revoke Sınağı
            code, rev_resp = http_req(
                f"{self.base_url}/mobile/revoke",
                "POST",
                headers={"Authorization": f"Bearer {mobile_session}"}
            )
            self.assertEqual(code, 200)
            self.assertTrue(rev_resp["success"])

            # Revoke edilmiş tokenlə təkrar sorğu rədd edilməlidir (401)
            code, reject_resp = http_req(
                f"{self.base_url}/commands/{cmd_id}",
                "GET",
                headers={"Authorization": f"Bearer {mobile_session}"}
            )
            self.assertEqual(code, 401, "Revoke edilmiş mobil token 401 ilə rədd edilməlidir")
            print("[PASS] Mobil revoke serverdə dərhal qüvvəyə mindi (401 təsdiqləndi).")

        finally:
            if worker_proc.poll() is None:
                worker_proc.kill()
                worker_proc.wait()

if __name__ == "__main__":
    unittest.main()
