import sys
import os
import time
import json
import tempfile
import shutil
import subprocess
import urllib.request
import urllib.error

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

PORT = 8794
BASE_URL = f"http://127.0.0.1:{PORT}"
GATEWAY_SCRIPT = os.path.abspath(os.path.join(os.path.dirname(__file__), "gateway_http_suite", "gateway_server.py"))
DESKTOP_EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "apps", "desktop_tauri", "src-tauri", "target", "release", "winkey_desktop.exe"))

def parse_json(text):
    for line in text.strip().splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try: return json.loads(line)
            except: pass
    return json.loads(text.strip())

def http_req(path, method="GET", body=None, headers=None):
    if headers is None: headers = {}
    url = f"{BASE_URL}/{path.lstrip('/')}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            raw = resp.read().decode("utf-8")
            try: return resp.status, json.loads(raw)
            except: return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try: return e.code, json.loads(raw)
        except: return e.code, {"error": raw}

def test_mobile_flow():
    print("=================================================================")
    print("  WinKey Pro — Mobile /remote UI & Full Backend Integration Test ")
    print("  Classification: MOBILE_UI_BACKEND | ZERO_PIN_LEAK | REVOKE     ")
    print("=================================================================")

    test_data_dir = tempfile.mkdtemp(prefix="winkey_mob_test_")
    proc_gw = subprocess.Popen([sys.executable, GATEWAY_SCRIPT, str(PORT), "--reset-db"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1.2)

    try:
        # 1. Test /remote & /mobile HTML routes
        print("\n--- TEST 1: Mobile UI HTML Render (/remote & /mobile) ---")
        for route in ["remote", "mobile"]:
            req = urllib.request.Request(f"{BASE_URL}/{route}?device=dev_test")
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                assert resp.status == 200
                html = resp.read().decode("utf-8")
                assert "WinKey Pro — Mobil İdarəetmə" in html
                assert "btn-unlock" in html and "btn-lock" in html and "btn-revoke" in html
                assert "Qorunan Zəncir" in html
                print(f"[PASS] Route /{route} rendered full responsive Avant-Garde mobile interface ({len(html)} bytes)")

        # 2. Register Device via Desktop CLI
        print("\n--- TEST 2: Native Device Registration via Desktop CLI ---")
        res_reg = subprocess.run([
            DESKTOP_EXE, "--register-and-qr",
            "--origin", BASE_URL,
            "--data-dir", test_data_dir
        ], capture_output=True, text=True, timeout=10)
        assert res_reg.returncode == 0
        reg_payload = parse_json(res_reg.stdout)
        device_id = reg_payload["device_id"]
        pair_code = reg_payload["pair_code"]
        print(f"[PASS] Device registered: ID={device_id}, PairCode={pair_code[:4]}****")

        # 3. Mobile Owner Login
        print("\n--- TEST 3: Mobile Owner Authentication ---")
        st_log, res_log = http_req("auth/login", "POST", {"username": "alice", "password": "AlicePass#2026!"})
        assert st_log == 200
        token = res_log["token"]
        auth_hdr = {"Authorization": f"Bearer {token}"}
        print(f"[PASS] Mobile session obtained: Token={token[:12]}...")

        # 4. QR Pair Execution
        print("\n--- TEST 4: Mobile Pairing Handshake ---")
        st_p, res_p = http_req("pair", "POST", {"code": pair_code}, headers=auth_hdr)
        assert st_p == 200 and res_p["device_id"] == device_id
        assert res_p["approval_status"] == "PENDING_PC_APPROVAL"
        print(f"[PASS] Device claimed via mobile QR code: Status={res_p['approval_status']}")

        # 5. One-Use Code Replay Protection
        st_replay, _ = http_req("pair", "POST", {"code": pair_code}, headers=auth_hdr)
        assert st_replay == 409
        print("[PASS] Expired/claimed QR code replay strictly rejected with HTTP 409")

        # 6. Reject Remote Approval Bypass
        st_appr_bypass, _ = http_req("devices/approve", "POST", {"device_id": device_id}, headers=auth_hdr)
        assert st_appr_bypass == 403
        print("[PASS] Mobile user remote approval bypass rejected (Local PC cryptographic proof required)")

        # 7. Local PC-Authenticated Ed25519 Approval
        print("\n--- TEST 5: Local PC Ed25519 Approval ---")
        res_appr = subprocess.run([
            DESKTOP_EXE, "--approve-device", device_id,
            "--origin", BASE_URL,
            "--data-dir", test_data_dir
        ], capture_output=True, text=True, timeout=10)
        assert res_appr.returncode == 0
        appr_payload = parse_json(res_appr.stdout)
        assert appr_payload.get("status") == "APPROVED"
        print("[PASS] Device cryptographically approved on PC: Status=APPROVED")

        # 8. Mobile Dispatches Lock Command
        print("\n--- TEST 6: Mobile Lock Dispatch ---")
        st_cmd, res_cmd = http_req("commands", "POST", {"device_id": device_id, "action": "lock"}, headers=auth_hdr)
        assert st_cmd == 200
        cmd_id = res_cmd["command_id"]
        print(f"[PASS] Mobile dispatched lock command: ID={cmd_id}")

        # 9. Strict Zero-PIN Policy Verification
        print("\n--- TEST 7: Zero PIN Leakage Enforcement ---")
        for bad_field in ["pin", "password", "credential", "secret"]:
            st_leak, res_leak = http_req("commands", "POST", {"device_id": device_id, "action": "unlock", bad_field: "123456"}, headers=auth_hdr)
            assert st_leak == 400
            assert "E_CREDENTIAL_NOT_PERMITTED" in str(res_leak)
            print(f"[PASS] Network rejected credential payload with field '{bad_field}': HTTP 400")

        # 10. Device Revocation Lifecycle
        print("\n--- TEST 8: Mobile Device Revocation ---")
        st_rev, res_rev = http_req("devices/revoke", "POST", {"device_id": device_id}, headers=auth_hdr)
        assert st_rev == 200 and res_rev.get("status") == "REVOKED"
        print("[PASS] Device successfully revoked from mobile")

        st_post_rev, _ = http_req("commands", "POST", {"device_id": device_id, "action": "lock"}, headers=auth_hdr)
        assert st_post_rev in (401, 403, 404)
        print("[PASS] Subsequent commands on revoked device rejected cleanly")

        print("\n=================================================================")
        print("  ALL MOBILE /remote UI & BACKEND FLOW TESTS PASSED (8/8 PASS)   ")
        print("=================================================================")

    finally:
        try:
            proc_gw.terminate()
            proc_gw.wait(timeout=2.0)
        except:
            proc_gw.kill()
        if os.path.exists(test_data_dir):
            shutil.rmtree(test_data_dir, ignore_errors=True)

if __name__ == "__main__":
    test_mobile_flow()
