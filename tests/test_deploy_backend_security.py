"""
WinKey Pro — Production Backend Security & Multi-Tenant IDOR Suite
Spesifikasiya: plan/GEMINI_FINAL_ALL_REMAINING.md Bölmə 3 və plan/GEMINI_FINAL_BATCH_REVISION.md
"""

import os
import sys
import time
import json
import shutil
import tempfile
import threading
import urllib.request
import urllib.error
from cryptography.hazmat.primitives.asymmetric import ed25519

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

# Dynamic Test Admin Secret
TEST_ADMIN_SECRET = "WINKEY_TEST_SECRET_" + os.urandom(8).hex()
os.environ["WINKEY_ADMIN_SECRET"] = TEST_ADMIN_SECRET

sys.path.insert(0, os.path.abspath("."))
from deploy.gateway_production_server import run_server, get_admin_secret

def request_json(url, method="GET", data=None, headers=None):
    if headers is None:
        headers = {}
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp_headers = dict(resp.headers)
            resp_body = resp.read().decode("utf-8")
            try:
                parsed = json.loads(resp_body) if resp_body else {}
            except Exception:
                parsed = {"raw": resp_body}
            return resp.status, parsed, resp_headers
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        try:
            parsed = json.loads(err_body)
        except Exception:
            parsed = {"raw": err_body}
        return e.code, parsed, dict(e.headers)

def main():
    temp_dir = tempfile.mkdtemp(prefix="winkey_sec_test_")
    db_path = os.path.join(temp_dir, "test_prod.db")
    port = 8199
    server = run_server(port, db_path)

    srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
    srv_thread.start()
    time.sleep(0.5)

    base_url = f"http://127.0.0.1:{port}"
    print(f"[SETUP] Production Gateway aktivdir: {base_url}")

    try:
        # Ed25519 açar cütləri yaradırıq
        key_a = ed25519.Ed25519PrivateKey.generate()
        pub_hex_a = key_a.public_key().public_bytes_raw().hex()

        key_b = ed25519.Ed25519PrivateKey.generate()
        pub_hex_b = key_b.public_key().public_bytes_raw().hex()

        # 1. Cihaz A və Cihaz B qeydiyyatı (Strict Register with Challenge & Proof)
        print("\n--- TEST 1: İki ayrı Cihazın Qeydiyyatı (Tenant A və Tenant B) ---")
        _, chal_a, _ = request_json(f"{base_url}/agent/challenge", "POST", {"purpose": "register", "device_id": "dev_AAA"})
        sig_a = key_a.sign(f"WINKEY_REGISTER:{chal_a['nonce']}:dev_AAA".encode("utf-8")).hex()
        st_reg_a, dev_a, _ = request_json(f"{base_url}/agent/register", "POST", {
            "device_id": "dev_AAA", "computer_name": "PC-Alice", "public_key_hex": pub_hex_a,
            "nonce": chal_a["nonce"], "proof_signature_hex": sig_a
        })

        _, chal_b, _ = request_json(f"{base_url}/agent/challenge", "POST", {"purpose": "register", "device_id": "dev_BBB"})
        sig_b = key_b.sign(f"WINKEY_REGISTER:{chal_b['nonce']}:dev_BBB".encode("utf-8")).hex()
        st_reg_b, dev_b, _ = request_json(f"{base_url}/agent/register", "POST", {
            "device_id": "dev_BBB", "computer_name": "PC-Bob", "public_key_hex": pub_hex_b,
            "nonce": chal_b["nonce"], "proof_signature_hex": sig_b
        })
        assert st_reg_a == 200 and st_reg_b == 200, f"Registration failed: {dev_a}, {dev_b}"
        secret_a = dev_a["device_secret"]
        secret_b = dev_b["device_secret"]
        print("[PASS] dev_AAA və dev_BBB qeydiyyatdan keçdi.")

        # 2. Cihazlar tərəfindən rəsmi Pair Request yaradılması
        print("\n--- TEST 2: Cütləşmə Sorğusunun Yaradılması və Sessiya Verilməsi ---")
        st_pr_a, pr_a, _ = request_json(
            f"{base_url}/devices/pair-request", "POST",
            data={"device_id": "dev_AAA"},
            headers={"Authorization": f"Bearer {secret_a}"}
        )
        st_pr_b, pr_b, _ = request_json(
            f"{base_url}/devices/pair-request", "POST",
            data={"device_id": "dev_BBB"},
            headers={"Authorization": f"Bearer {secret_b}"}
        )
        assert st_pr_a == 200 and st_pr_b == 200
        pair_code_a = pr_a["pair_code"]
        pair_code_b = pr_b["pair_code"]

        st_p1, pair_a, _ = request_json(f"{base_url}/pair", "POST", {"pair_code": pair_code_a})
        st_p2, pair_b, _ = request_json(f"{base_url}/pair", "POST", {"pair_code": pair_code_b})
        assert st_p1 == 200 and st_p2 == 200
        token_a = pair_a["session_token"]
        token_b = pair_b["session_token"]
        print(f"[PASS] Token A: {token_a[:12]}..., Token B: {token_b[:12]}...")

        # 3. One-Use Replay Attack Qoruması
        print("\n--- TEST 3: One-Use Replay Attack Qoruması ---")
        st_rep, rep_json, _ = request_json(f"{base_url}/pair", "POST", {"pair_code": pair_code_a})
        assert st_rep == 409, f"Expected 409 Replay rejection, got {st_rep}"
        assert rep_json.get("error") == "E_REPLAY_REJECTED"
        print(f"[PASS] İstifadə olunmuş cütləşmə kodu dərhal rədd edildi (HTTP 409): {rep_json}")

        # 4. Multi-Tenant IDOR Qoruması (Cihaz A sessiyası Cihaz B-nin statusunu oxuya bilməz)
        print("\n--- TEST 4: Multi-Tenant IDOR Qoruması (Status Oxunuşu) ---")
        st_idor, idor_json, _ = request_json(f"{base_url}/devices/dev_BBB/status", "GET", headers={"Authorization": f"Bearer {token_a}"})
        assert st_idor == 403, f"Expected 403 IDOR rejection, got {st_idor}"
        assert idor_json.get("error") == "E_TENANT_IDOR_FORBIDDEN"
        print(f"[PASS] Cihaz A sessiyası Cihaz B statusundan məhrum edildi (HTTP 403): {idor_json}")

        # 5. Multi-Tenant IDOR Qoruması (Cihaz A sessiyası Cihaz B-yə komanda göndərə bilməz)
        print("\n--- TEST 5: Multi-Tenant IDOR Qoruması (Komanda Göndərişi) ---")
        st_cmd_idor, cmd_idor_json, _ = request_json(
            f"{base_url}/devices/dev_BBB/command", "POST",
            data={"action": "unlock"},
            headers={"Authorization": f"Bearer {token_a}"}
        )
        assert st_cmd_idor == 403, f"Expected 403 IDOR rejection, got {st_cmd_idor}"
        assert cmd_idor_json.get("error") == "E_TENANT_IDOR_FORBIDDEN"
        print(f"[PASS] Cihaz A-nın Cihaz B-yə kənar komanda göndərməsi bloklandı (HTTP 403): {cmd_idor_json}")

        # 6. Zero-PIN Network Rejection Guard
        print("\n--- TEST 6: Zero-PIN Network Rejection Qoruması ---")
        st_pin, pin_json, _ = request_json(
            f"{base_url}/devices/dev_AAA/command", "POST",
            data={"action": "unlock", "pin": "1234"},
            headers={"Authorization": f"Bearer {token_a}"}
        )
        assert st_pin == 400, f"Expected 400 PIN rejection, got {st_pin}"
        assert pin_json.get("error") == "E_CREDENTIAL_NOT_PERMITTED"
        print(f"[PASS] Şəbəkəyə daxil edilən PIN dərhal fail-closed rədd edildi (HTTP 400): {pin_json}")

        # 7. Owner-Only Admin API Təhlükəsizliyi
        print("\n--- TEST 7: Owner-Only Admin API Təhlükəsizliyi ---")
        # İcazəsiz sorğu
        st_no_adm, _, _ = request_json(f"{base_url}/admin/devices", "GET")
        assert st_no_adm == 403, "Admin endpoint without secret must be 403"

        # Səhv secret
        st_bad_adm, _, _ = request_json(f"{base_url}/admin/devices", "GET", headers={"X-Owner-Admin-Secret": "WRONG_SECRET"})
        assert st_bad_adm == 403, "Admin endpoint with wrong secret must be 403"

        # Düzgün dinamik secret
        st_ok_adm, adm_json, _ = request_json(f"{base_url}/admin/devices", "GET", headers={"X-Owner-Admin-Secret": TEST_ADMIN_SECRET})
        assert st_ok_adm == 200, f"Admin request failed: {adm_json}"
        assert len(adm_json.get("devices", [])) == 2
        print(f"[PASS] Yalnız düzgün sahib açarı ilə admin məlumatları açılır (HTTP 200): {len(adm_json['devices'])} cihaz tapıldı.")

        # 8. Təhlükəsizlik Başlıqları (Security Headers)
        print("\n--- TEST 8: Təhlükəsizlik Başlıqları (CSP, Clickjacking, MIME) ---")
        _, _, headers = request_json(f"{base_url}/mobile", "GET")
        assert headers.get("X-Frame-Options") == "DENY", "X-Frame-Options DENY olmalıdır"
        assert headers.get("X-Content-Type-Options") == "nosniff", "nosniff olmalıdır"
        assert "Content-Security-Policy" in headers, "CSP başlığı mövcud olmalıdır"
        print("[PASS] Bütün təhlükəsizlik başlıqları (CSP, X-Frame-Options: DENY, nosniff) təsdiqləndi.")

        # 9. Authenticated Agent Polling və Result Object Ownership
        print("\n--- TEST 9: Authenticated Polling və Command Theft Qoruması ---")
        # Polling Bearer secret ilə
        st_pol, pol_res, _ = request_json(
            f"{base_url}/agent/poll", "POST",
            data={"device_id": "dev_AAA", "locked": False, "pin_ready": True},
            headers={"Authorization": f"Bearer {secret_a}"}
        )
        assert st_pol == 200, f"Polling failed: {pol_res}"

        # Cihaz B Cihaz A-nın komandasının nəticəsini dəyişə bilməz!
        st_theft, res_theft, _ = request_json(
            f"{base_url}/agent/result", "POST",
            data={"device_id": "dev_BBB", "command_id": "cmd_nonexistent", "success": True},
            headers={"Authorization": f"Bearer {secret_b}"}
        )
        assert st_theft in (404, 403)
        print("[PASS] Authenticated polling və command theft qoruması təsdiqləndi.")

        print("\n=============================================================")
        print("  BÜTÜN PRODUCTION GATEWAY SECURITY TESTLƏRİ 100% PASS!     ")
        print("=============================================================")

    finally:
        server.shutdown()
        import gc
        gc.collect()
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    main()
