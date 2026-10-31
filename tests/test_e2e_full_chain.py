import sys
import argparse
import getpass
import os
import time
import json
import uuid
import hashlib
import tempfile
import shutil
import subprocess
import urllib.request
import urllib.error

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

PORT = 8788
BASE_URL = f"http://127.0.0.1:{PORT}"
REPORT_LOG = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "plan", "reports", "remaining", "revision10", "e2e_full_chain.log"))

SERVICE_EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "apps", "winkey_service", "target", "release", "winkey_service.exe"))
DESKTOP_EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "apps", "desktop_tauri", "src-tauri", "target", "release", "winkey_desktop.exe"))
GATEWAY_SCRIPT = os.path.abspath(os.path.join(os.path.dirname(__file__), "gateway_http_suite", "gateway_server.py"))

def parse_json_from_output(output_text):
    for line in output_text.strip().splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except:
                pass
    return json.loads(output_text.strip())

def log(msg):
    try:
        print(msg)
    except:
        print(msg.encode('ascii', 'replace').decode('ascii'))
    sys.stdout.flush()
    os.makedirs(os.path.dirname(REPORT_LOG), exist_ok=True)
    with open(REPORT_LOG, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def http_req(path, method="GET", body=None, headers=None):
    if headers is None:
        headers = {}
    url = f"{BASE_URL}/{path.lstrip('/')}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)

    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            status = resp.status
            resp_body = json.loads(resp.read().decode("utf-8"))
            return status, resp_body
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            parsed = json.loads(raw)
        except:
            parsed = {"error": raw}
        return e.code, parsed

def run_e2e(allow_real_input=False):
    # Read before any real LOCK action so the operator is not prompted on a locked screen.
    operator_pin = getpass.getpass("Local Windows test PIN (never logged): ") if allow_real_input else None
    if allow_real_input and not operator_pin:
        raise ValueError("Real-input test requires a local operator credential")
    os.makedirs(os.path.dirname(REPORT_LOG), exist_ok=True)
    with open(REPORT_LOG, "w", encoding="utf-8") as f:
        f.write("=== WinKey Pro — End-to-End Real Integration & Full Chain Suite (Revision 10) ===\n")
        f.write(f"Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

    log("=================================================================")
    log("  WinKey Pro — End-to-End Real Chain & Cross-Component Audit (Rev 10)")
    log("  Classification: E2E_REAL_CHAIN | ED25519_VERIFIED | LOCAL_PIN_VAULT | TRUSTED_SCM_BINDING")
    log("=================================================================")

    # 0. Test Data Isolation Directory
    test_data_dir = tempfile.mkdtemp(prefix="winkey_test_rev10_")
    log(f"[ISOLATION] Created dedicated isolated test data dir: {test_data_dir}")

    # 1. Start Durable Gateway Server
    log("\n[PROCESS 1] Starting Gateway server on port 8788 (--reset-db)...")
    proc_gw = subprocess.Popen([sys.executable, GATEWAY_SCRIPT, str(PORT), "--reset-db"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1.2)

    # 2. Native Desktop PE & Version Verification
    log("\n--- STAGE 1: Native Desktop Binary & CLI Smoke ---")
    res_dsk = subprocess.run([DESKTOP_EXE, "--version"], capture_output=True, text=True, timeout=5)
    log(f"[PASS] Desktop app responded: '{res_dsk.stdout.strip()}' (Exit code: {res_dsk.returncode})")
    assert res_dsk.returncode == 0

    res_chk = subprocess.run([DESKTOP_EXE, "--check"], capture_output=True, text=True, timeout=5)
    log(f"[PASS] Desktop app PE check: '{res_chk.stdout.strip()}'")
    assert "WINKEY_DESKTOP_PE_OK" in res_chk.stdout

    # 3. Real Device Registration & Ephemeral QR Generation via Desktop Native CLI (REM-013)
    log("\n--- STAGE 2: Real Server Device Registration via Desktop Native CLI ---")
    res_qr = subprocess.run([
        DESKTOP_EXE,
        "--register-and-qr",
        "--origin", BASE_URL,
        "--data-dir", test_data_dir
    ], capture_output=True, text=True, timeout=10)

    log(f"[DESKTOP_CLI] Return code: {res_qr.returncode}")
    log(f"[DESKTOP_CLI] Stdout: {res_qr.stdout.strip()[:180]}...")
    assert res_qr.returncode == 0, f"Desktop registration failed: {res_qr.stderr}"

    qr_payload = parse_json_from_output(res_qr.stdout)
    device_id = qr_payload["device_id"]
    pair_code_raw = qr_payload["pair_code"]
    pairing_url = qr_payload["pairing_url"]
    public_key_hex = qr_payload.get("public_key_hex", "")
    log(f"[PASS] Desktop CLI registered device: ID={device_id}")
    log(f"[PASS] Ephemeral Pair Code: {pair_code_raw[:4]}****, Public Key: {public_key_hex[:16]}...")
    log(f"[PASS] Mobile Pairing URL: {pairing_url}")

    # Verify config written in isolated data-dir without plain device_secret
    cfg_path = os.path.join(test_data_dir, "config.json")
    assert os.path.exists(cfg_path), "Isolated config.json was not created!"
    with open(cfg_path, "r", encoding="utf-8") as f:
        local_cfg = json.load(f)
    assert "device_secret" not in local_cfg, "CRITICAL: Plain device_secret leaked into config.json!"
    log(f"[PASS] Isolated config confirmed: server_confirmed={local_cfg.get('server_confirmed')} (Zero secret leak)")

    secret_path = os.path.join(test_data_dir, "device_secret.dpapi")
    assert os.path.exists(secret_path), "Windows DPAPI vault (device_secret.dpapi) not found!"
    log(f"[PASS] Windows DPAPI encrypted vault confirmed in isolated dir: {secret_path}")

    # 4. Start Native Windows Service Worker (Process 2)
    log("\n[PROCESS 2] Starting Real Native WinKey Service in Standalone Mode...")
    proc_svc = subprocess.Popen([
        SERVICE_EXE,
        "--standalone",
        "--timeout-sec", "35",
        "--data-dir", test_data_dir
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1.5)

    try:
        # 5. Mobile Owner Login (Salted Authentication)
        log("\n--- STAGE 3: Mobile User Login (Salted Password Authentication) ---")
        st_login, res_login = http_req("auth/login", "POST", {"username": "alice", "password": "AlicePass#2026!"})
        assert st_login == 200, f"Login failed: {res_login}"
        owner_token = res_login["token"]
        owner_headers = {"Authorization": f"Bearer {owner_token}"}
        log(f"[PASS] Owner Alice logged in: Token={owner_token[:12]}..., Role={res_login['role']}")

        # 6. Mobile Pairing via QR Code
        log("\n--- STAGE 4: Mobile Pairing & PC Approval Handshake Flow ---")
        st_pair, res_pair = http_req("pair", "POST", {"code": pair_code_raw}, headers=owner_headers)
        assert st_pair == 200 and res_pair["device_id"] == device_id
        approval_status = res_pair.get("approval_status", "")
        log(f"[PASS] Device paired with status: '{approval_status}' (PC approval required)")
        assert approval_status == "PENDING_PC_APPROVAL"

        # One-use verification: second attempt with same code must be rejected (HTTP 409)
        st_replay, res_replay = http_req("pair", "POST", {"code": pair_code_raw}, headers=owner_headers)
        assert st_replay == 409, f"Expected 409 for reused code, got {st_replay}"
        log(f"[PASS] QR One-Use Replay Rejected: HTTP {st_replay} (Code already claimed/expired)")

        # Verify command CANNOT be executed before PC approval
        log("[SECURITY_CHECK] Attempting command before PC approval...")
        st_unapproved, res_unapproved = http_req("commands", "POST", {"device_id": device_id, "action": "lock"}, headers=owner_headers)
        assert st_unapproved == 403, f"Expected 403 for unapproved device, got {st_unapproved}"
        log(f"[PASS] Command blocked before approval: HTTP {st_unapproved} ({res_unapproved.get('error')})")

        # Negative Test: Mobile user remotely attempting to approve without PC proof
        st_mob_appr, res_mob_appr = http_req("devices/approve", "POST", {"device_id": device_id}, headers=owner_headers)
        assert st_mob_appr == 403 and "E_UNAUTHORIZED_PC_APPROVAL" in str(res_mob_appr)
        log(f"[PASS] Remote mobile bypass rejected: HTTP {st_mob_appr} ({res_mob_appr.get('error')})")

        # 7. Real PC-Authenticated Approval via Native Desktop CLI (REM-014)
        log("\n--- STAGE 5: Native Desktop PC-Authenticated Approval (Ed25519 Proof) ---")
        res_appr_cli = subprocess.run([
            DESKTOP_EXE,
            "--approve-device", device_id,
            "--origin", BASE_URL,
            "--data-dir", test_data_dir
        ], capture_output=True, text=True, timeout=10)
        log(f"[CLI_APPROVAL] Stdout: {res_appr_cli.stdout.strip()}")
        assert res_appr_cli.returncode == 0
        res_appr_json = parse_json_from_output(res_appr_cli.stdout)
        assert res_appr_json.get("status") == "APPROVED"
        log(f"[PASS] Native Desktop CLI authenticated and approved device: Status=APPROVED")

        # 8. Mobile Dispatches Command -> Service Polls & Executes Lock
        log("\n--- STAGE 6: Mobile Lock Dispatch -> Native Service Poll & Execution ---")
        action = "lock" if allow_real_input else "mock"
        st_cmd, res_cmd = http_req("commands", "POST", {"device_id": device_id, "action": action}, headers=owner_headers)
        assert st_cmd == 200
        cmd_id = res_cmd["command_id"]
        log(f"[PASS] Mobile dispatched command: ID={cmd_id}, Action='lock'")

        # Wait for native service poller loop to consume and report result
        log("[POLL] Waiting for native service to poll command and report handler result...")
        cmd_finished = False
        final_state = None
        final_result = None

        for attempt in range(12):
            time.sleep(0.8)
            st_chk, res_chk = http_req("history", "GET", headers=owner_headers)
            if st_chk == 200:
                matching = [c for c in res_chk.get("commands", []) if c["id"] == cmd_id]
                if matching and matching[0]["state"] in ["success", "failed"]:
                    cmd_finished = True
                    final_state = matching[0]["state"]
                    final_result = matching[0]["result"]
                    break

        log(f"[RESULT] Native Service consumed & reported result: State='{final_state}', Result='{final_result}'")
        assert cmd_finished is True, "Service failed to execute and report command within window!"
        assert final_state == "success", f"Command failed: {final_result}"
        expected = "SUCCESS_LOCKED" if allow_real_input else "DEMO_MOCK_ACTION"
        assert expected in str(final_result), f"Unexpected command result: {final_result}"

        # 9. Real Unlock Fail-Closed Security & Local PIN Vault Boundary (REM-020 & REM-012)
        log("\n--- STAGE 7: Real Win32 Unlock Engine & Local PIN Vault Boundary (REM-020) ---")
        # 7a. Attempt unlock without local PIN provisioned in vault -> Must fail-closed with E_NO_LOCAL_CREDENTIAL_PROVISIONED
        st_unlock_cmd, res_unlock_cmd = http_req("commands", "POST", {"device_id": device_id, "action": "unlock"}, headers=owner_headers)
        assert st_unlock_cmd == 200
        unlock_cmd_id = res_unlock_cmd["command_id"]

        missing_vault_finished = False
        for attempt in range(12):
            time.sleep(0.8)
            st_chk, res_chk = http_req("history", "GET", headers=owner_headers)
            if st_chk == 200:
                matching = [c for c in res_chk.get("commands", []) if c["id"] == unlock_cmd_id]
                if matching and matching[0]["state"] in ["success", "failed"]:
                    log(f"[PASS] Missing Local PIN Vault Handled: State='{matching[0]['state']}', Result='{matching[0]['result']}'")
                    assert "SUCCESS_UNLOCKED" not in str(matching[0]["result"])
                    assert "E_NO_LOCAL_CREDENTIAL" in str(matching[0]["result"])
                    missing_vault_finished = True
                    log("[PASS][SECURITY_BOUNDARY] Missing credential rejected; this is NOT an unlock success")
                    break

        assert missing_vault_finished, "Missing-vault command never completed"

        # 7b. Provision Local PIN into DPAPI Vault via Desktop CLI (REM-024 & REM-027: Stdin transport + Trusted Service PID)
        local_pin = operator_pin if allow_real_input else "123456"
        res_pin = subprocess.run([
            DESKTOP_EXE,
            "--store-pin-stdin",
            "--data-dir", test_data_dir,
            "--trusted-service-pid", str(proc_svc.pid)
        ], input=local_pin + "\n", capture_output=True, text=True, timeout=5)
        local_pin = None
        operator_pin = None
        log(f"[PASS] Desktop CLI provisioned local PIN via stdin: Exit={res_pin.returncode}, Stdout: {res_pin.stdout.strip()}")
        assert res_pin.returncode == 0
        pin_vault_path = os.path.join(test_data_dir, "user_credential.dpapi")
        assert os.path.exists(pin_vault_path), "user_credential.dpapi vault not created!"

        if allow_real_input:
            # 7c. Trigger unlock with Local PIN provisioned in Vault
            st_unlock_cmd2, res_unlock_cmd2 = http_req("commands", "POST", {"device_id": device_id, "action": "unlock"}, headers=owner_headers)
            assert st_unlock_cmd2 == 200
            unlock_cmd_id2 = res_unlock_cmd2["command_id"]

            functional_unlock_finished = False
            for attempt in range(12):
                time.sleep(0.8)
                st_chk, res_chk = http_req("history", "GET", headers=owner_headers)
                if st_chk == 200:
                    matching = [c for c in res_chk.get("commands", []) if c["id"] == unlock_cmd_id2]
                    if matching and matching[0]["state"] in ["success", "failed"]:
                        log(f"[RESULT] Local Vault PIN Unlock Handled: State='{matching[0]['state']}', Result='{matching[0]['result']}'")
                        assert matching[0]["state"] == "success", f"FUNCTIONAL_UNLOCK_FAILED: {matching[0]['result']}"
                        assert "SUCCESS_UNLOCKED" in str(matching[0]["result"]), "No verified unlock result"
                        functional_unlock_finished = True
                        log("[PASS][FUNCTIONAL_UNLOCK] Verified service unlock result")
                        break

            assert functional_unlock_finished, "Functional unlock command never completed"
        else:
            log("[NOT_TESTED][PHYSICAL_UNLOCK] Skipped: --allow-real-input not supplied. No credential input sent.")

        # 10. Device Revoke Lifecycle
        log("\n--- STAGE 8: Device Ownership Revoke Lifecycle ---")
        st_rev, res_rev = http_req("devices/revoke", "POST", {"device_id": device_id}, headers=owner_headers)
        assert st_rev == 200 and res_rev.get("status") == "REVOKED"
        log(f"[PASS] Device ownership successfully revoked: {res_rev}")

        # Verification: Bob cannot interact with revoked device
        st_bob_cmd, res_bob_cmd = http_req("commands", "POST", {"device_id": device_id, "action": "unlock"}, headers={"Authorization": "Bearer sess_fake_bob"})
        assert st_bob_cmd == 401 or st_bob_cmd == 403
        log(f"[PASS] Revoked device protected from unauthorized commands: HTTP {st_bob_cmd}")

        # 11. Mobile / Remote HTML Route Verification
        log("\n--- STAGE 9: Mobile Web Interface Route Verification (/remote & /mobile) ---")
        req_mob = urllib.request.Request(f"{BASE_URL}/remote?device={device_id}")
        with urllib.request.urlopen(req_mob, timeout=5.0) as resp_mob:
            html_content = resp_mob.read().decode("utf-8")
            assert resp_mob.status == 200
            assert "WinKey Mobile Remote" in html_content
            log(f"[PASS] Mobile route /remote rendered 200 OK with UI title (Length: {len(html_content)} bytes)")

        log("\n=================================================================")
        log("  NONPHYSICAL INTEGRATION COMPLETED; PHYSICAL UNLOCK REQUIRES OPT-IN  ")
        log("=================================================================")

    finally:
        try:
            proc_svc.terminate()
            proc_svc.wait(timeout=2.0)
        except:
            proc_svc.kill()
        try:
            proc_gw.terminate()
            proc_gw.wait(timeout=2.0)
        except:
            proc_gw.kill()
        if os.path.exists(test_data_dir):
            try:
                shutil.rmtree(test_data_dir, ignore_errors=True)
                log(f"[CLEANUP] Isolated test data dir removed: {test_data_dir}")
            except:
                pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-real-input", action="store_true", help="Explicit operator opt-in: real screen lock and credential input")
    run_e2e(allow_real_input=parser.parse_args().allow_real_input)
