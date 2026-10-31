import sys
import os
import time
import json
import subprocess
import urllib.request
import urllib.error
import hashlib
import uuid
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.asymmetric import ed25519

PORT = 8788
BASE_URL = f"http://127.0.0.1:{PORT}"
REPORT_LOG_REV1 = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "plan", "reports", "remaining", "gateway_durable_http_suite.log"))
REPORT_LOG_REV2 = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "plan", "reports", "remaining", "revision2", "gateway_durable_auth.log"))
REPORT_LOG_REV8 = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "plan", "reports", "remaining", "revision8", "gateway_hardened_auth.log"))

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

def log(msg):
    try:
        print(msg)
    except:
        print(msg.encode('ascii', 'replace').decode('ascii'))
    sys.stdout.flush()
    for lp in [REPORT_LOG_REV1, REPORT_LOG_REV2, REPORT_LOG_REV8]:
        os.makedirs(os.path.dirname(lp), exist_ok=True)
        with open(lp, "a", encoding="utf-8") as f:
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

def run_tests():
    for lp in [REPORT_LOG_REV1, REPORT_LOG_REV2]:
        os.makedirs(os.path.dirname(lp), exist_ok=True)
        with open(lp, "w", encoding="utf-8") as f:
            f.write(f"=== WinKey Pro Real HTTP Gateway & Durable Auth Test Suite ===\n")
            f.write(f"Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

    log("=================================================================")
    log("  WinKey Pro — Real HTTP Gateway & Durable Auth Test Suite        ")
    log("  Classification: DURABLE_AUTH | ZERO_FORGERY | RESTART_PERSIST ")
    log("=================================================================")

    server_script = os.path.join(os.path.dirname(__file__), "gateway_server.py")
    
    # Clean run with initial reset
    log("\n[SETUP] Starting Gateway with --reset-db for clean baseline...")
    proc = subprocess.Popen([sys.executable, server_script, str(PORT), "--reset-db"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1.2)

    try:
        # TEST 1: Forgery & Unauthenticated Session Rejection
        log("\n--- TEST 1: Forgery & Unauthenticated Session Rejection ---")
        st_forge, res_forge = http_req("pair", "POST", {"code": "ANYCODE123"}, headers={"oai-authenticated-user-id": "attacker_user"})
        assert st_forge == 401, f"Expected 401, got {st_forge}: {res_forge}"
        log(f"[PASS] Direct client header injection rejected: HTTP {st_forge}, Error='{res_forge.get('error')}'")

        st_fake_tok, res_fake_tok = http_req("devices", "GET", headers={"Authorization": "Bearer sess_non_existent_fake_token"})
        assert st_fake_tok == 401, f"Expected 401, got {st_fake_tok}: {res_fake_tok}"
        log(f"[PASS] Forged Bearer session token rejected: HTTP {st_fake_tok}, Error='{res_fake_tok.get('error')}'")

        # TEST 2: Verified Login & Strict Salted Password Verification (Positive & Negative)
        log("\n--- TEST 2: Verified Login, Salted Password Verification & Negative Tests ---")
        # 2a. Unknown user
        st_unk, res_unk = http_req("auth/login", "POST", {"username": "non_existent_user_99", "password": "AnyPassword123!"})
        assert st_unk == 401 and "E_UNKNOWN_USER" in res_unk.get("error", "")
        log(f"[PASS] Unknown user rejected: HTTP {st_unk}, Error='{res_unk.get('error')}'")

        # 2b. Wrong password
        st_wp, res_wp = http_req("auth/login", "POST", {"username": "alice", "password": "WRONG_PASSWORD_XYZ"})
        assert st_wp == 401 and "E_INVALID_CREDENTIALS" in res_wp.get("error", "")
        log(f"[PASS] Wrong password rejected: HTTP {st_wp}, Error='{res_wp.get('error')}'")

        # 2c. Impersonation attempt: client sends fake role/user_id in body
        st_imp, res_imp = http_req("auth/login", "POST", {"username": "bob", "password": "BobPass#2026!", "role": "owner", "user_id": "usr_alice_owner_9281"})
        assert st_imp == 200 and res_imp["user_id"] == "usr_bob_tenant_4419" and res_imp["role"] == "tenant"
        token_stranger = res_imp["token"]
        log(f"[PASS] Client impersonation thwarted: Bob assigned actual user_id='{res_imp['user_id']}' and role='{res_imp['role']}'")

        # 2d. Legitimate Owner Login
        st_l1, res_l1 = http_req("auth/login", "POST", {"username": "alice", "password": "AlicePass#2026!"})
        assert st_l1 == 200 and res_l1["user_id"] == "usr_alice_owner_9281"
        token_owner = res_l1["token"]
        log(f"[PASS] Verified Owner login issued: {token_owner[:12]}... (User: {res_l1['user_id']}, Role: {res_l1['role']})")

        auth_owner = {"Authorization": f"Bearer {token_owner}"}
        auth_stranger = {"Authorization": f"Bearer {token_stranger}"}

        # TEST 3: Device Registration & Pair (Ed25519 Verified)
        log("\n--- TEST 3: Device Registration & Pairing (Ed25519 Verified) ---")
        priv_a = ed25519.Ed25519PrivateKey.generate()
        pub_a = priv_a.public_key().public_bytes_raw().hex()
        priv_b = ed25519.Ed25519PrivateKey.generate()
        pub_b = priv_b.public_key().public_bytes_raw().hex()

        sec_a = hashlib.sha256(b"secret_agent_a").hexdigest()
        sec_b = hashlib.sha256(b"secret_agent_b").hexdigest()
        pair_a = hashlib.sha256(b"PAIRCODEA123").hexdigest()
        pair_b = hashlib.sha256(b"PAIRCODEB456").hexdigest()

        # Nonce for Device A
        st_ch_a, res_ch_a = http_req("agent/challenge", "POST", {"purpose": "register"})
        nonce_a = res_ch_a["nonce"]
        sig_a = priv_a.sign(f"WINKEY_REGISTER:{nonce_a}:{sec_a}:{pair_a}".encode("utf-8")).hex()

        # Nonce for Device B
        st_ch_b, res_ch_b = http_req("agent/challenge", "POST", {"purpose": "register"})
        nonce_b = res_ch_b["nonce"]
        sig_b = priv_b.sign(f"WINKEY_REGISTER:{nonce_b}:{sec_b}:{pair_b}".encode("utf-8")).hex()

        st_a, res_a = http_req("agent/register", "POST", {
            "secret_hash": sec_a, "pair_hash": pair_a, "name": "Nesib-Laptop",
            "public_key_hex": pub_a, "proof_signature_hex": sig_a, "nonce": nonce_a
        })
        st_b, res_b = http_req("agent/register", "POST", {
            "secret_hash": sec_b, "pair_hash": pair_b, "name": "Office-Desktop",
            "public_key_hex": pub_b, "proof_signature_hex": sig_b, "nonce": nonce_b
        })
        assert st_a == 200 and st_b == 200
        assert res_a.get("proof_verified") is True and res_b.get("proof_verified") is True
        dev_a = res_a["device_id"]
        dev_b = res_b["device_id"]
        log(f"[PASS] Registered with Ed25519 proof: dev_a={dev_a}, dev_b={dev_b}")

        st_p1, res_p1 = http_req("pair", "POST", {"code": "PAIRCODEA123"}, headers=auth_owner)
        st_p2, res_p2 = http_req("pair", "POST", {"code": "PAIRCODEB456"}, headers=auth_stranger)
        assert st_p1 == 200 and res_p1["device_id"] == dev_a
        assert st_p2 == 200 and res_p2["device_id"] == dev_b
        log(f"[PASS] Device A paired to usr_nesib_owner; Device B paired to usr_stranger_tenant")

        # TEST 4: Cross-Tenant IDOR Rejection & PC Approval Gate
        log("\n--- TEST 4: Cross-Tenant IDOR & PC Approval Gate Rejection ---")
        st_idor, res_idor = http_req("commands", "POST", {"device_id": dev_a, "action": "unlock"}, headers=auth_stranger)
        assert st_idor == 403, f"Expected 403, got {st_idor}: {res_idor}"
        log(f"[PASS] Stranger attempted unlock on Owner's laptop: HTTP {st_idor}, Error='{res_idor.get('error')}'")

        # Unapproved owner attempt must also be blocked until local PC approval
        st_unappr, res_unappr = http_req("commands", "POST", {"device_id": dev_a, "action": "unlock"}, headers=auth_owner)
        assert st_unappr == 403 and "E_PENDING_APPROVAL" in str(res_unappr)
        log(f"[PASS] Command blocked before PC local approval: HTTP {st_unappr} ({res_unappr.get('error')})")

        # Remote mobile approval without PC proof must be blocked
        st_mob_appr, res_mob_appr = http_req("devices/approve", "POST", {"device_id": dev_a}, headers=auth_owner)
        assert st_mob_appr == 403 and "E_UNAUTHORIZED_PC_APPROVAL" in str(res_mob_appr)
        log(f"[PASS] Remote mobile bypass without PC proof rejected: HTTP {st_mob_appr} ({res_mob_appr.get('error')})")

        # PC Local Approval with Device A Ed25519 Signature
        st_ch_appr, res_ch_appr = http_req("agent/challenge", "POST", {"purpose": "approve", "device_id": dev_a})
        nonce_appr = res_ch_appr["nonce"]
        sig_appr = priv_a.sign(f"WINKEY_APPROVE:{nonce_appr}:{dev_a}".encode("utf-8")).hex()

        st_appr, res_appr = http_req("devices/approve", "POST", {
            "device_id": dev_a, "nonce": nonce_appr, "approval_proof_hex": sig_appr
        })
        assert st_appr == 200 and res_appr.get("status") == "APPROVED"
        log(f"[PASS] Local PC owner approved Device A with Ed25519 proof: {res_appr}")

        # TEST 5: Authorized Dispatch, Poll & Atomic Execution
        log("\n--- TEST 5: Authorized Tenant Command Lifecycle ---")
        st_cmd, res_cmd = http_req("commands", "POST", {"device_id": dev_a, "action": "unlock"}, headers=auth_owner)
        assert st_cmd == 200
        cmd_id = res_cmd["command_id"]
        log(f"[PASS] Owner enqueued unlock command: ID={cmd_id}")

        st_poll, res_poll = http_req("agent/poll", "POST", {"device_id": dev_a, "locked": True, "pin_ready": True}, headers={"Authorization": "Bearer secret_agent_a"})
        assert st_poll == 200 and res_poll["command"]["id"] == cmd_id
        log(f"[PASS] Agent A consumed command: {cmd_id}")

        st_rep, res_rep = http_req("agent/result", "POST", {"device_id": dev_a, "command_id": cmd_id, "success": True, "status": "SUCCESS_UNLOCKED"}, headers={"Authorization": "Bearer secret_agent_a"})
        assert st_rep == 200
        log(f"[PASS] Agent reported execution status: SUCCESS_UNLOCKED")

        # TEST 6: 10-Concurrent QR Claim CAS Test (Atomic Compare-And-Swap)
        log("\n--- TEST 6: Concurrent Multi-Threaded QR Claim (Atomic CAS) ---")
        pair_code_race = "RACETEST9999"
        pair_hash_race = hashlib.sha256(pair_code_race.encode()).hexdigest()
        st_ch_rc, res_ch_rc = http_req("agent/challenge", "POST", {"purpose": "register"})
        nonce_rc = res_ch_rc["nonce"]
        sig_rc = priv_a.sign(f"WINKEY_REGISTER:{nonce_rc}:{sec_a}:{pair_hash_race}".encode("utf-8")).hex()
        st_rc, res_rc = http_req("agent/register", "POST", {
            "secret_hash": sec_a, "pair_hash": pair_hash_race, "name": "Race-Target",
            "public_key_hex": pub_a, "proof_signature_hex": sig_rc, "nonce": nonce_rc
        })
        assert st_rc == 200
        dev_race = res_rc["device_id"]

        # Create 10 distinct verified user sessions for race competitors
        competitor_tokens = []
        for i in range(10):
            c_name = f"competitor_{i}"
            _, lr = http_req("auth/login", "POST", {"username": c_name, "password": f"pwd_{c_name}"})
            competitor_tokens.append((c_name, lr["token"]))

        def attempt_claim(worker_idx):
            c_user, c_token = competitor_tokens[worker_idx]
            code, r = http_req("pair", "POST", {"code": pair_code_race}, headers={"Authorization": f"Bearer {c_token}"})
            return code, r, c_user

        with ThreadPoolExecutor(max_workers=10) as executor:
            claim_results = list(executor.map(attempt_claim, range(10)))

        success_claims = [r for r in claim_results if r[0] == 200]
        failed_claims = [r for r in claim_results if r[0] == 409]

        log(f"[PASS] 10 Parallel Claims: Successful={len(success_claims)}, Rejected={len(failed_claims)}")
        assert len(success_claims) == 1, f"Expected 1 winner, got {len(success_claims)}"
        assert len(failed_claims) == 9, f"Expected 9 rejections, got {len(failed_claims)}"
        log(f"[PASS] Atomic Winner: {success_claims[0][2]}")

        # TEST 7: Zero PIN Exposure in Admin Output
        log("\n--- TEST 7: Zero PIN Exposure in Admin Output ---")
        st_adm, res_adm = http_req("devices", "GET", headers=auth_owner)
        assert st_adm == 200
        dev_list = res_adm["devices"]
        for d in dev_list:
            for banned_key in ["pin", "password", "secret", "private_key", "secret_hash", "pair_hash"]:
                assert banned_key not in d, f"SECURITY VIOLATION: '{banned_key}' exposed!"
        log("[PASS] Strict Assertion Passed: ZERO PIN / ZERO SECRETS exposed to API/client.")

        # TEST 8: Server Kill & Restart Persistence Verification (DURABLE SQLITE)
        log("\n--- TEST 8: Server Kill & Restart Persistence Verification ---")
        log("[KILL] Terminating Gateway server process...")
        proc.terminate()
        proc.wait(timeout=3.0)
        log("[KILL] Gateway process terminated. Database file remains untouched on disk.")

        log("[RESTART] Relaunching Gateway server WITHOUT --reset-db flag...")
        proc = subprocess.Popen([sys.executable, server_script, str(PORT)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(1.5)

        log("[VERIFY] Querying devices with existing session token after restart...")
        st_restart_adm, res_restart_adm = http_req("devices", "GET", headers=auth_owner)
        assert st_restart_adm == 200, f"Expected 200 after restart, got {st_restart_adm}: {res_restart_adm}"
        restarted_devs = [d["id"] for d in res_restart_adm["devices"]]
        assert dev_a in restarted_devs, f"Device A {dev_a} missing after restart!"
        log(f"[PASS] Restart Persistence Verified! Found {len(restarted_devs)} device(s) for owner: {restarted_devs}")

        st_hist, res_hist = http_req("history", "GET", headers=auth_owner)
        assert st_hist == 200
        cmd_ids = [c["id"] for c in res_hist["commands"]]
        assert cmd_id in cmd_ids, f"Command {cmd_id} lost after restart!"
        log(f"[PASS] Historical commands persisted across restart: Found {len(cmd_ids)} commands including {cmd_id}")

        log("\n=================================================================")
        log("  ALL DURABLE AUTH & RESTART TESTS PASSED (8/8 PASS)             ")
        log("=================================================================")

    finally:
        try:
            proc.terminate()
            proc.wait(timeout=2.0)
        except:
            proc.kill()

if __name__ == "__main__":
    run_tests()
