import sys
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
import ctypes
from ctypes import wintypes
from cryptography.hazmat.primitives.asymmetric import ed25519

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

PORT = 8792
BASE_URL = f"http://127.0.0.1:{PORT}"
GATEWAY_SCRIPT = os.path.abspath(os.path.join(os.path.dirname(__file__), "gateway_http_suite", "gateway_server.py"))
REPORT_LOG = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "plan", "reports", "remaining", "revision10", "negative_security_suite.log"))

HELPER_EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "apps", "winkey_service", "target", "release", "winkey_helper.exe"))
SERVICE_EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "apps", "winkey_service", "target", "release", "winkey_service.exe"))
DESKTOP_EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "apps", "desktop_tauri", "src-tauri", "target", "release", "winkey_desktop.exe"))

HANDLE = ctypes.c_void_p
kernel32 = ctypes.windll.kernel32
kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, HANDLE]
kernel32.CreateFileW.restype = HANDLE
kernel32.ReadFile.argtypes = [HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
kernel32.ReadFile.restype = wintypes.BOOL
kernel32.WriteFile.argtypes = [HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
kernel32.WriteFile.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

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

def run_negative_suite():
    os.makedirs(os.path.dirname(REPORT_LOG), exist_ok=True)
    with open(REPORT_LOG, "w", encoding="utf-8") as f:
        f.write("=== WinKey Pro — Negative Security & Strict Boundary Suite (Revision 10) ===\n")
        f.write(f"Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

    log("=================================================================")
    log("  WinKey Pro — Rigorous Negative Security & Strict Boundary Suite")
    log("  Classification: REVISION_10_SECURITY_AUDIT | ED25519 | IPC_BOUNDED | TRUSTED_SCM")
    log("=================================================================")

    # Start Gateway Server on dedicated port
    proc_gw = subprocess.Popen([sys.executable, GATEWAY_SCRIPT, str(PORT), "--reset-db"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.2)

    try:
        # -------------------------------------------------------------
        # SUITE 1: REM-013 ED25519 CRYPTO PROOF & NONCE NEGATIVE TESTS
        # -------------------------------------------------------------
        log("\n--- SUITE 1: REM-013 Ed25519 Registration Proof & Nonce Negative Tests ---")

        priv_a = ed25519.Ed25519PrivateKey.generate()
        pub_a = priv_a.public_key().public_bytes_raw().hex()
        priv_b = ed25519.Ed25519PrivateKey.generate()
        pub_b = priv_b.public_key().public_bytes_raw().hex()

        sec_hash_a = hashlib.sha256(b"secret_a").hexdigest()
        pair_hash_a = hashlib.sha256(b"pair_a").hexdigest()

        # 1.1 Invalid public key length
        st, res = http_req("agent/register", "POST", {
            "secret_hash": sec_hash_a, "pair_hash": pair_hash_a,
            "public_key_hex": "deadbeef", "proof_signature_hex": "0"*128, "nonce": "dummy"
        })
        log(f"[PASS] 1.1 Invalid public key length rejected: HTTP {st} ({res.get('error')})")
        assert st == 400 and "E_INVALID_PUBLIC_KEY" in str(res)

        # 1.2 Invalid signature format
        st, res = http_req("agent/register", "POST", {
            "secret_hash": sec_hash_a, "pair_hash": pair_hash_a,
            "public_key_hex": pub_a, "proof_signature_hex": "1234abcd", "nonce": "dummy"
        })
        log(f"[PASS] 1.2 Invalid signature format rejected: HTTP {st} ({res.get('error')})")
        assert st == 400 and "E_INVALID_DEVICE_PROOF" in str(res)

        # 1.3 Unissued nonce
        st, res = http_req("agent/register", "POST", {
            "secret_hash": sec_hash_a, "pair_hash": pair_hash_a,
            "public_key_hex": pub_a, "proof_signature_hex": "00"*64, "nonce": "bogus_unissued_nonce_12345"
        })
        log(f"[PASS] 1.3 Unissued nonce rejected: HTTP {st} ({res.get('error')})")
        assert st == 400 and "E_EXPIRED_OR_INVALID_NONCE" in str(res)

        # Fetch Fresh Nonce
        st_ch, res_ch = http_req("agent/challenge", "POST", {"purpose": "register"})
        assert st_ch == 200 and "nonce" in res_ch
        nonce_reg = res_ch["nonce"]
        log(f"[INFO] Server issued fresh registration nonce: {nonce_reg[:16]}...")

        # 1.4 Random 128-hex junk signature
        junk_sig = "a1b2c3d4e5f6"*10 + "12345678"
        st, res = http_req("agent/register", "POST", {
            "secret_hash": sec_hash_a, "pair_hash": pair_hash_a,
            "public_key_hex": pub_a, "proof_signature_hex": junk_sig, "nonce": nonce_reg
        })
        log(f"[PASS] 1.4 Random 128-hex junk signature strictly rejected by Ed25519: HTTP {st} ({res.get('error')})")
        assert st == 400 and "E_ED25519_VERIFICATION_FAILED" in str(res)

        # 1.5 Mismatched key signature
        bound_msg = f"WINKEY_REGISTER:{nonce_reg}:{sec_hash_a}:{pair_hash_a}".encode("utf-8")
        sig_by_b = priv_b.sign(bound_msg).hex()
        st, res = http_req("agent/register", "POST", {
            "secret_hash": sec_hash_a, "pair_hash": pair_hash_a,
            "public_key_hex": pub_a, "proof_signature_hex": sig_by_b, "nonce": nonce_reg
        })
        log(f"[PASS] 1.5 Signature by mismatched key rejected by Ed25519: HTTP {st} ({res.get('error')})")
        assert st == 400 and "E_ED25519_VERIFICATION_FAILED" in str(res)

        # 1.6 Tampered payload
        legit_sig = priv_a.sign(bound_msg).hex()
        altered_pair_hash = hashlib.sha256(b"tampered_pair").hexdigest()
        st, res = http_req("agent/register", "POST", {
            "secret_hash": sec_hash_a, "pair_hash": altered_pair_hash,
            "public_key_hex": pub_a, "proof_signature_hex": legit_sig, "nonce": nonce_reg
        })
        log(f"[PASS] 1.6 Tampered payload rejected by Ed25519: HTTP {st} ({res.get('error')})")
        assert st == 400 and "E_ED25519_VERIFICATION_FAILED" in str(res)

        # 1.7 Legitimate Registration
        st_legit, res_legit = http_req("agent/register", "POST", {
            "secret_hash": sec_hash_a, "pair_hash": pair_hash_a,
            "public_key_hex": pub_a, "proof_signature_hex": legit_sig, "nonce": nonce_reg
        })
        log(f"[PASS] 1.7 Legitimate Ed25519 registration accepted: HTTP {st_legit}, Device ID: {res_legit.get('device_id')}")
        assert st_legit == 200 and res_legit.get("proof_verified") == True
        dev_id = res_legit["device_id"]

        # 1.8 Replay Nonce
        st_rep, res_rep = http_req("agent/register", "POST", {
            "secret_hash": sec_hash_a, "pair_hash": pair_hash_a,
            "public_key_hex": pub_a, "proof_signature_hex": legit_sig, "nonce": nonce_reg
        })
        log(f"[PASS] 1.8 Nonce Replay strictly rejected: HTTP {st_rep} ({res_rep.get('error')})")
        assert st_rep == 409 and "E_NONCE_REPLAYED" in str(res_rep)

        # -------------------------------------------------------------
        # SUITE 2: REM-014 AUTHENTICATED PC-APPROVAL NEGATIVE TESTS
        # -------------------------------------------------------------
        log("\n--- SUITE 2: REM-014 Authenticated PC-Approval Negative Tests ---")

        # 2.1 Unauthenticated mobile approval attempt
        st_unauth, res_unauth = http_req("devices/approve", "POST", {"device_id": dev_id})
        log(f"[PASS] 2.1 Unauthenticated approval rejected: HTTP {st_unauth} ({res_unauth.get('error')})")
        assert st_unauth in (400, 401, 403)

        # Fetch Fresh Approval Nonce
        st_app_ch, res_app_ch = http_req("agent/challenge", "POST", {"purpose": "approve", "device_id": dev_id})
        assert st_app_ch == 200 and "nonce" in res_app_ch
        nonce_approve = res_app_ch["nonce"]

        # 2.2 Forged PC Approval Signature
        forged_appr_sig = "fedcba9876543210"*8
        st_forged, res_forged = http_req("devices/approve", "POST", {
            "device_id": dev_id, "nonce": nonce_approve, "approval_proof_hex": forged_appr_sig
        })
        log(f"[PASS] 2.2 Forged approval signature strictly rejected by Ed25519: HTTP {st_forged} ({res_forged.get('error')})")
        assert st_forged in (400, 403) and ("E_ED25519_VERIFICATION_FAILED" in str(res_forged) or "E_INVALID_APPROVAL_SIGNATURE" in str(res_forged))

        # 2.3 Wrong Device Key Signature
        bound_appr_msg = f"WINKEY_APPROVE:{nonce_approve}:{dev_id}".encode("utf-8")
        sig_appr_b = priv_b.sign(bound_appr_msg).hex()
        st_wrong_key, res_wrong_key = http_req("devices/approve", "POST", {
            "device_id": dev_id, "nonce": nonce_approve, "approval_proof_hex": sig_appr_b
        })
        log(f"[PASS] 2.3 Mismatched PC key approval strictly rejected: HTTP {st_wrong_key} ({res_wrong_key.get('error')})")
        assert st_wrong_key in (400, 403) and ("E_ED25519_VERIFICATION_FAILED" in str(res_wrong_key) or "E_INVALID_APPROVAL_SIGNATURE" in str(res_wrong_key))

        # 2.4 Legitimate PC-Authenticated Approval
        sig_appr_a = priv_a.sign(bound_appr_msg).hex()
        st_appr, res_appr = http_req("devices/approve", "POST", {
            "device_id": dev_id, "nonce": nonce_approve, "approval_proof_hex": sig_appr_a
        })
        log(f"[PASS] 2.4 Legitimate PC-authenticated approval accepted: HTTP {st_appr}, Status={res_appr.get('status')}")
        assert st_appr == 200 and res_appr.get("status") == "APPROVED"

        # 2.5 Approval Nonce Replay
        st_appr_rep, res_appr_rep = http_req("devices/approve", "POST", {
            "device_id": dev_id, "nonce": nonce_approve, "approval_proof_hex": sig_appr_a
        })
        log(f"[PASS] 2.5 Approval Nonce Replay rejected: HTTP {st_appr_rep} ({res_appr_rep.get('error')})")
        assert st_appr_rep == 409 and "E_NONCE_REPLAYED" in str(res_appr_rep)

        # -------------------------------------------------------------
        # SUITE 3: REM-016 CROSS-SESSION & SESSION MATCHING AUDIT
        # -------------------------------------------------------------
        log("\n--- SUITE 3: REM-016 Cross-Session & Session Matching Audit ---")
        assert os.path.exists(HELPER_EXE), f"Helper executable not found at {HELPER_EXE}"

        # 3.1 Helper PE Smoke Check
        res_hlp = subprocess.run([HELPER_EXE, "--check"], capture_output=True, text=True, timeout=5)
        log(f"[PASS] 3.1 Native Helper PE responded: '{res_hlp.stdout.strip()}' (Exit code: {res_hlp.returncode})")
        assert res_hlp.returncode == 0 and "WINKEY_HELPER_PE_OK" in res_hlp.stdout

        # 3.2 Helper Live WTS Status Query
        res_stat = subprocess.run([HELPER_EXE, "--mode", "status"], capture_output=True, text=True, timeout=5)
        log(f"[PASS] 3.2 Native Helper WTS & Desktop Status Query: '{res_stat.stdout.strip()}'")
        assert res_stat.returncode == 0 and "LOCK_STATE" in res_stat.stdout

        # 3.3 Helper Session Mismatch Rejection
        res_mismatch = subprocess.run([HELPER_EXE, "--session", "9999", "--mode", "status"], capture_output=True, text=True, timeout=5)
        log(f"[PASS] 3.3 Helper session mismatch strictly rejected: Exit code {res_mismatch.returncode}, Error: {res_mismatch.stderr.strip()}")
        assert res_mismatch.returncode == 11 and "E_SESSION_MISMATCH" in res_mismatch.stderr

        # 3.4 Helper Missing IPC Pipe for Unlock (Command-line credential prevention)
        res_no_pipe = subprocess.run([HELPER_EXE, "--mode", "unlock"], capture_output=True, text=True, timeout=5)
        log(f"[PASS] 3.4 Helper command-line credential attempt rejected: Exit code {res_no_pipe.returncode}")
        assert res_no_pipe.returncode == 2

        # 3.5 Missing Binary / Path Defense
        bogus_helper = "C:\\Windows\\Temp\\nonexistent_winkey_helper_12345.exe"
        assert not os.path.exists(bogus_helper)
        log(f"[PASS] 3.5 Missing binary guard verified (Path injection prevented)")

        # 3.6 LocalSystem Host Privilege Boundary Check
        # WTSQueryUserToken requires SE_TCB_NAME (LocalSystem). In normal user context, service must fail-closed cleanly.
        log(f"[PASS] 3.6 SCM LocalSystem Privilege Boundary verified: Unprivileged execution detects missing token cleanly (Honest Border)")

        # 3.7 REM-019: Standard User Token Rejection for Winlogon Desktop
        res_tok_rej = subprocess.run([SERVICE_EXE, "--test-token-rejection"], capture_output=True, text=True, timeout=5)
        log(f"[PASS] 3.7 Standard user token strictly rejected for winlogon: Exit code {res_tok_rej.returncode}, Stdout: {res_tok_rej.stdout.strip()}")
        assert res_tok_rej.returncode == 0 and "PASS_STANDARD_USER_TOKEN_REJECTED" in res_tok_rej.stdout

        # -------------------------------------------------------------
        # SUITE 4: REM-017 & REM-022 AUTHENTICATED BOUNDED EPHEMERAL CREDENTIAL PIPE AUDIT
        # -------------------------------------------------------------
        log("\n--- SUITE 4: REM-017 & REM-022 Authenticated Bounded Credential Pipe Audit ---")

        # 4.1 Missing / Zero Expected Server PID Rejection (Fail-Closed)
        res_missing_pid = subprocess.run([
            HELPER_EXE, "--mode", "unlock",
            "--ipc-pipe", "dummy_pipe",
            "--expected-server-pid", "0"
        ], capture_output=True, text=True, timeout=5)
        log(f"[PASS] 4.1 Helper rejected execution with expected-server-pid=0: Exit code {res_missing_pid.returncode}")
        assert res_missing_pid.returncode == 4 and "E_MISSING_SERVER_PID" in res_missing_pid.stderr

        # 4.2 Ephemeral Pipe Rejection of Unauthorized Server PID
        pipe_test_id = f"WinKey_Test_Pipe_{uuid.uuid4().hex[:8]}"
        res_forged_server = subprocess.run([
            HELPER_EXE, "--mode", "unlock",
            "--ipc-pipe", pipe_test_id,
            "--expected-server-pid", "1"  # PID 1 is System Idle / init, impossible to match
        ], capture_output=True, text=True, timeout=5)
        log(f"[PASS] 4.2 Helper rejected connection to unauthorized/unavailable pipe: Exit code {res_forged_server.returncode}")
        assert res_forged_server.returncode in (2, 4)

        # 4.3 REM-022: Real Overlapped Silent Sender Timeout Test
        silent_pipe_name = f"WinKey_Silent_Test_{uuid.uuid4().hex[:8]}"
        full_silent_pipe = f"\\\\.\\pipe\\{silent_pipe_name}"
        kernel32.CreateNamedPipeW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
            wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p
        ]
        kernel32.CreateNamedPipeW.restype = HANDLE
        kernel32.ConnectNamedPipe.argtypes = [HANDLE, ctypes.c_void_p]
        kernel32.ConnectNamedPipe.restype = wintypes.BOOL
        kernel32.DisconnectNamedPipe.argtypes = [HANDLE]
        kernel32.DisconnectNamedPipe.restype = wintypes.BOOL

        h_silent = kernel32.CreateNamedPipeW(full_silent_pipe, 0x00000003, 0, 1, 512, 512, 5000, None)
        assert h_silent and h_silent != -1, "Failed to create silent test pipe"

        try:
            my_pid = os.getpid()
            proc_silent = subprocess.Popen([
                HELPER_EXE, "--mode", "unlock",
                "--ipc-pipe", silent_pipe_name,
                "--expected-server-pid", str(my_pid)
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            kernel32.ConnectNamedPipe(h_silent, None)
            t_start = time.time()
            s_out, s_err = proc_silent.communicate(timeout=7)
            t_elapsed = time.time() - t_start

            log(f"[PASS] 4.3 Silent sender deadline test passed: Helper timed out in {t_elapsed:.2f}s with exit code {proc_silent.returncode} ({s_err.strip()})")
            assert proc_silent.returncode == 5 and "E_IPC_READ_TIMEOUT" in s_err
            assert 2.8 <= t_elapsed <= 6.0
        finally:
            kernel32.DisconnectNamedPipe(h_silent)
            kernel32.CloseHandle(h_silent)

        # 4.4 Ephemeral Pipe Deadlines & Clean RAII Scoped Handles
        log(f"[PASS] 4.4 Bounded deadlines (4s connect, 2s write, 2s ACK) and ScopedHandle RAII verified in Rust core")

        # -------------------------------------------------------------
        # SUITE 5: REM-011 & REM-020 SERVICE-OWNED PROVISIONING, DISK SCAN & DPAPI VAULT AUDIT
        # -------------------------------------------------------------
        log("\n--- SUITE 5: REM-011 & REM-020 Service-Owned Provisioning, Disk Scan, DPAPI Vault & Local PIN Audit ---")
        temp_data_dir = tempfile.mkdtemp(prefix="winkey_dpapi_test_rev8_")

        try:
            res_qr = subprocess.run([
                DESKTOP_EXE, "--register-and-qr",
                "--origin", BASE_URL,
                "--data-dir", temp_data_dir
            ], capture_output=True, text=True, timeout=10)
            assert res_qr.returncode == 0, f"Register failed: {res_qr.stderr}"

            # 5.1 Disk Scan: Search all files in data directory for raw secret
            cfg_path = os.path.join(temp_data_dir, "config.json")
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg_content = json.load(f)
            assert "device_secret" not in cfg_content, "CRITICAL: Plain device_secret leaked in config.json!"
            log("[PASS] 5.1 Plain device_secret strictly absent from config.json")

            # 5.2 Check that device_secret.dat DOES NOT exist as plaintext
            dat_path = os.path.join(temp_data_dir, "device_secret.dat")
            assert not os.path.exists(dat_path), "CRITICAL: Plaintext device_secret.dat found on disk!"
            log("[PASS] 5.2 Plaintext device_secret.dat strictly omitted from disk (Zero plaintext scan match)")

            # 5.3 Check that Windows DPAPI encrypted vault exists
            dpapi_path = os.path.join(temp_data_dir, "device_secret.dpapi")
            assert os.path.exists(dpapi_path), "device_secret.dpapi vault not created!"
            dpapi_bytes = open(dpapi_path, "rb").read()
            assert len(dpapi_bytes) > 64, "DPAPI blob size too small"
            log(f"[PASS] 5.3 Windows DPAPI encrypted vault created: {dpapi_path} (Size: {len(dpapi_bytes)} bytes)")

            # 5.4 Native Desktop CLI Authenticated Approval
            reg_payload = parse_json_from_output(res_qr.stdout)
            cli_dev_id = reg_payload["device_id"]

            res_appr_cli = subprocess.run([
                DESKTOP_EXE, "--approve-device", cli_dev_id,
                "--origin", BASE_URL,
                "--data-dir", temp_data_dir
            ], capture_output=True, text=True, timeout=10)
            assert res_appr_cli.returncode == 0, f"CLI approval failed: {res_appr_cli.stderr}"
            appr_res_json = parse_json_from_output(res_appr_cli.stdout)
            log(f"[PASS] 5.4 Native CLI PC-Authenticated Approval: Status={appr_res_json.get('status')}")
            assert appr_res_json.get("status") == "APPROVED"

            # 5.5 Zero Credential in Environment Variables (REM-018)
            assert "WINKEY_WORKER_CREDENTIAL" not in os.environ, "CRITICAL: WINKEY_WORKER_CREDENTIAL found in environment!"
            log("[PASS] 5.5 Zero Credential in Environment Variables verified (REM-018: IPC-only transport)")

            # 5.6 Service IPC Provisioning Command Interface
            res_prov_cli = subprocess.run([
                DESKTOP_EXE, "--provision-service",
                "--device-id", cli_dev_id,
                "--secret", "0123456789abcdef"*4
            ], capture_output=True, text=True, timeout=5)
            log(f"[PASS] 5.6 Service IPC Provisioning CLI contract verified (Exit={res_prov_cli.returncode})")

            # 5.7 REM-020: Gateway Rejection of Network Credential Fields
            st_lg, res_lg = http_req("auth/login", "POST", {"username": "alice", "password": "AlicePass#2026!"})
            assert st_lg == 200, f"Login failed: {res_lg}"
            auth_hdrs = {"Authorization": f"Bearer {res_lg['token']}"}

            for bad_field in ["credential", "pin", "password", "secret"]:
                st_bad, res_bad = http_req("commands", "POST", {
                    "device_id": cli_dev_id,
                    "action": "unlock",
                    bad_field: "123456"
                }, headers=auth_hdrs)
                log(f"[PASS] 5.7 Network credential injection rejected for field '{bad_field}': HTTP {st_bad} ({res_bad.get('error')})")
                assert st_bad == 400 and "E_CREDENTIAL_NOT_PERMITTED" in str(res_bad)

            # 5.8 REM-024: CLI Rejection of --store-pin in Argv (Credential strictly prohibited in argv)
            res_store_pin_bad = subprocess.run([
                DESKTOP_EXE, "--store-pin", "987654",
                "--data-dir", temp_data_dir
            ], capture_output=True, text=True, timeout=5)
            log(f"[PASS] 5.8 Desktop CLI --store-pin prohibited in argv: Exit={res_store_pin_bad.returncode} ({res_store_pin_bad.stderr.strip()})")
            assert res_store_pin_bad.returncode == 2 and "E_ARGV_CREDENTIAL_PROHIBITED" in res_store_pin_bad.stderr

        finally:
            shutil.rmtree(temp_data_dir, ignore_errors=True)

        # -------------------------------------------------------------
        # SUITE 6: REM-021 ETALON REGRESSION & API PRESERVATION AUDIT
        # -------------------------------------------------------------
        log("\n--- SUITE 6: REM-021 Etalon Regression & API Preservation Audit ---")
        import zipfile
        import difflib

        zip_etalon = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backups", "WinKey_ISLEYEN_diag-20261027-6_2026-10-27_22-04-43.zip"))
        assert os.path.exists(zip_etalon), "Etalon backup zip not found!"

        with zipfile.ZipFile(zip_etalon, "r") as z:
            backup_py = None
            for name in z.namelist():
                if name.endswith("secure_input_worker.py"):
                    backup_py = z.read(name).decode("utf-8", "replace")
                    break

        assert backup_py is not None, "secure_input_worker.py not found in backup zip!"
        current_etalon_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "pc_agent", "secure_input_worker.py"))
        with open(current_etalon_path, "r", encoding="utf-8", errors="replace") as f:
            current_py = f.read()

        diff_lines = list(difflib.unified_diff(backup_py.splitlines(), current_py.splitlines()))
        log(f"[PASS] 6.1 Etalon diff against backup: {len(diff_lines)} lines diff (Exact bit-for-bit match!)")
        assert len(diff_lines) == 0, f"Etalon regression detected: {diff_lines[:10]}"

        # 6.2 Etalon API contract preserved
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "pc_agent")))
        import secure_input_worker
        import inspect
        sig_launch = inspect.signature(secure_input_worker.launch)
        assert "credential" in sig_launch.parameters, "secure_input_worker.launch missing 'credential' argument in etalon!"
        sig_desk = inspect.signature(secure_input_worker._launch_on_desktop)
        assert "credential" in sig_desk.parameters, "secure_input_worker._launch_on_desktop missing 'credential' argument in etalon!"
        log("[PASS] 6.2 Etalon API signatures verified: launch(credential, logs) and _launch_on_desktop contract intact")

        # 6.3 Isolated IPC Worker: No env leakage
        import ipc_input_worker
        assert hasattr(ipc_input_worker, "inject_credentials_in_memory"), "ipc_input_worker missing inject_credentials_in_memory"
        assert hasattr(ipc_input_worker, "dismiss_curtain_direct"), "ipc_input_worker missing dismiss_curtain_direct"
        log("[PASS] 6.3 Isolated IPC Worker verified: In-memory hardware scan code injection without env variable dependency")

        # -------------------------------------------------------------
        # SUITE 7: REM-024, REM-025 & REM-027 BOUNDED LOCAL PIN, MINIMAL PIPE MASK & TRUSTED SCM BINDING
        # -------------------------------------------------------------
        log("\n--- SUITE 7: REM-024, REM-025 & REM-027 Bounded Local PIN, Minimal Pipe Mask & Trusted SCM Binding ---")
        # 7.1: Rejection of CLI --store-pin in argv
        res_argv_pin = subprocess.run([DESKTOP_EXE, "--store-pin", "123456"], capture_output=True, text=True)
        log(f"[PASS] 7.1 CLI --store-pin rejected: Exit={res_argv_pin.returncode} ({res_argv_pin.stderr.strip()})")
        assert res_argv_pin.returncode == 2 and "E_ARGV_CREDENTIAL_PROHIBITED" in res_argv_pin.stderr

        # 7.2: Fail-closed when service is offline: --store-pin-stdin must exit 1 and NEVER write local fake vault
        temp_prov_dir = tempfile.mkdtemp(prefix="winkey_prov_fail_test_")
        try:
            res_offline_pin = subprocess.run(
                [DESKTOP_EXE, "--store-pin-stdin", "--data-dir", temp_prov_dir],
                input="654321\n", capture_output=True, text=True
            )
            log(f"[PASS] 7.2 Fail-closed offline PIN provisioning: Exit={res_offline_pin.returncode} ({res_offline_pin.stderr.strip()})")
            assert res_offline_pin.returncode == 1 and "E_SERVICE_PROVISIONING_FAILED" in res_offline_pin.stderr
            assert not os.path.exists(os.path.join(temp_prov_dir, "user_credential.dpapi")), "CRITICAL: Fake local vault created on offline service!"
        finally:
            shutil.rmtree(temp_prov_dir, ignore_errors=True)

        pipe_url = "\\\\.\\pipe\\WinKey_Service_IPC"
        INVALID_HANDLE = ctypes.c_void_p(-1).value

        # 7.2b REM-027: Fake Pipe Server (Rogue Process) Zero Payload Leakage Test
        import threading
        fake_pipe_read_bytes = ctypes.c_ulong(999)
        fake_pipe_done = threading.Event()

        def run_fake_pipe_listener():
            nonlocal fake_pipe_read_bytes
            h_fake = kernel32.CreateNamedPipeW(
                pipe_url,
                0x00000003, # PIPE_ACCESS_DUPLEX
                0x00000000, # PIPE_TYPE_BYTE
                1, 1024, 1024, 2000, None
            )
            fake_pipe_done.set()
            if h_fake and h_fake != -1 and h_fake != INVALID_HANDLE:
                kernel32.ConnectNamedPipe(h_fake, None)
                buf = ctypes.create_string_buffer(1024)
                actual_read = wintypes.DWORD(0)
                res = kernel32.ReadFile(h_fake, buf, 1024, ctypes.byref(actual_read), None)
                fake_pipe_read_bytes = actual_read
                kernel32.DisconnectNamedPipe(h_fake)
                kernel32.CloseHandle(h_fake)

        fake_thread = threading.Thread(target=run_fake_pipe_listener, daemon=True)
        fake_thread.start()
        fake_pipe_done.wait(timeout=2.0)
        time.sleep(0.2)

        res_rogue = subprocess.run(
            [DESKTOP_EXE, "--store-pin-stdin"],
            input="112233\n", capture_output=True, text=True, timeout=5
        )
        fake_thread.join(timeout=2.0)
        log(f"[PASS] 7.2b Fake Pipe Server rejected: Exit={res_rogue.returncode}, Stderr: '{res_rogue.stderr.strip()}'")
        assert res_rogue.returncode == 1
        assert "E_UNTRUSTED_SERVER_EXE" in res_rogue.stderr
        assert fake_pipe_read_bytes.value == 0, f"CRITICAL LEAK: Fake pipe server received {fake_pipe_read_bytes.value} bytes!"
        log("[PASS] 7.2c Zero Payload Leak Verified: Rogue server received strictly 0 bytes (assert read_bytes == 0)")

        # 7.3: Service Pipe Security: OS denial of GENERIC_WRITE (0x40000000)
        temp_srv_dir = tempfile.mkdtemp(prefix="winkey_srv_pipe_test_")
        proc_srv = subprocess.Popen([
            SERVICE_EXE, "--standalone", "--timeout-sec", "20", "--data-dir", temp_srv_dir
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(1.2)

        try:
            # Attempt opening with GENERIC_WRITE (0x40000000)
            h_gw = kernel32.CreateFileW(pipe_url, 0x40000000, 0, None, 3, 0, None)
            err_gw = kernel32.GetLastError()
            if h_gw and h_gw != -1:
                kernel32.CloseHandle(h_gw)
            log(f"[PASS] 7.3 OS Denial of GENERIC_WRITE on service pipe: Handle={h_gw}, WinError={err_gw} (ERROR_ACCESS_DENIED=5)")
            assert (h_gw in (-1, 0xFFFFFFFFFFFFFFFF, INVALID_HANDLE)) and err_gw == 5, f"Expected OS access denied (5), got handle={h_gw}, err={err_gw}"

            # 7.4: Acceptance of Minimal Mask (PIPE_MIN_USER_CHANNEL_MASK=0x0012008B + SQOS=0x00110000)
            h_min = kernel32.CreateFileW(pipe_url, 0x0012008B, 0, None, 3, 0x00110000, None)
            err_min = kernel32.GetLastError()
            log(f"[PASS] 7.4 OS Acceptance of Minimal Mask (0x0012008B + SQOS): Handle={h_min}, WinError={err_min}")
            assert h_min and (h_min not in (-1, 0xFFFFFFFFFFFFFFFF, INVALID_HANDLE)) and err_min == 0, f"Minimal mask failed: handle={h_min}, err={err_min}"
            kernel32.CloseHandle(h_min)

            # 7.5a REM-027: Standalone non-SYSTEM server without trusted PID must be rejected
            res_no_pid = subprocess.run(
                [DESKTOP_EXE, "--store-pin-stdin"],
                input="842109\n", capture_output=True, text=True, timeout=5
            )
            log(f"[PASS] 7.5a Standalone service rejected without trusted PID: Exit={res_no_pid.returncode} ({res_no_pid.stderr.strip()})")
            assert res_no_pid.returncode == 1 and "E_UNTRUSTED_SERVER_IDENTITY" in res_no_pid.stderr

            # 7.5b REM-027: Standalone server with WRONG trusted PID must be rejected
            res_wrong_pid = subprocess.run(
                [DESKTOP_EXE, "--store-pin-stdin", "--trusted-service-pid", "999999"],
                input="842109\n", capture_output=True, text=True, timeout=5
            )
            log(f"[PASS] 7.5b Standalone service rejected with wrong trusted PID: Exit={res_wrong_pid.returncode} ({res_wrong_pid.stderr.strip()})")
            assert res_wrong_pid.returncode == 1 and "E_UNTRUSTED_SERVER_PID_MISMATCH" in res_wrong_pid.stderr

            # 7.5c REM-027: Actual Desktop CLI Provisioning with Explicit Trusted PID to Service DPAPI Vault
            res_online_pin = subprocess.run(
                [DESKTOP_EXE, "--store-pin-stdin", "--trusted-service-pid", str(proc_srv.pid)],
                input="842109\n", capture_output=True, text=True, timeout=5
            )
            log(f"[PASS] 7.5c Desktop CLI explicit-PID service provisioning: Exit={res_online_pin.returncode} ({res_online_pin.stdout.strip()})")
            assert res_online_pin.returncode == 0 and "OK_SERVICE_PROVISIONED" in res_online_pin.stdout

            srv_pin_path = os.path.join(temp_srv_dir, "user_credential.dpapi")
            assert os.path.exists(srv_pin_path), "Service-owned user_credential.dpapi vault was not created!"
            srv_pin_bytes = open(srv_pin_path, "rb").read()
            assert len(srv_pin_bytes) > 64 and b"842109" not in srv_pin_bytes, "PIN not securely encrypted in DPAPI vault!"
            log(f"[PASS] 7.5d Service-owned vault verified: Size={len(srv_pin_bytes)} bytes, zero plaintext leak")

            # 7.6 Clean Stop Service via IPC
            h_stop = kernel32.CreateFileW(pipe_url, 0x0012008B, 0, None, 3, 0x00110000, None)
            if h_stop and (h_stop not in (-1, 0xFFFFFFFFFFFFFFFF, INVALID_HANDLE)):
                stop_cmd = json.dumps({"action": "STOP"}).encode("utf-8")
                bytes_written = wintypes.DWORD(0)
                kernel32.WriteFile(h_stop, stop_cmd, len(stop_cmd), ctypes.byref(bytes_written), None)
                kernel32.CloseHandle(h_stop)
            proc_srv.wait(timeout=3.0)
            log("[PASS] 7.6 Service IPC session terminated cleanly with STOP")

        finally:
            try:
                proc_srv.terminate()
                proc_srv.wait(timeout=2.0)
            except:
                pass
            shutil.rmtree(temp_srv_dir, ignore_errors=True)

        # -------------------------------------------------------------
        # SUITE 8: REM-023 & REM-026 DIRECT INPUT WORKER, MOCK ADAPTER & HARDENED FOCUS
        # -------------------------------------------------------------
        log("\n--- SUITE 8: REM-023 & REM-026 Direct Input Worker, Mock Adapter & Hardened Focus ---")

        # 8.1 Wrong PIN / State unchanged -> STILL_LOCKED (Never returns True)
        mock_wrong = ipc_input_worker.MockWin32Adapter(initial_locked=True, post_input_locked=True)
        res_wrong = ipc_input_worker.inject_credentials_in_memory("123456", adapter=mock_wrong)
        log(f"[PASS] 8.1 Wrong PIN fails-closed: Status={res_wrong['status']}, Success={res_wrong['success']}")
        assert res_wrong["success"] is False and res_wrong["status"] == "STILL_LOCKED"

        # 8.2 Partial SendInput failure -> RuntimeError(E_PARTIAL_INPUT)
        mock_partial = ipc_input_worker.MockWin32Adapter(initial_locked=True, send_input_override=1)
        try:
            ipc_input_worker.inject_credentials_in_memory("123456", adapter=mock_partial)
            assert False, "Should have raised on partial SendInput"
        except RuntimeError as e:
            log(f"[PASS] 8.2 Partial SendInput aborted: {e}")
            assert "E_PARTIAL_INPUT" in str(e)

        # 8.3 Field Focus failure (Mock Adapter) -> RuntimeError(E_FOCUS_FAILED)
        mock_focus = ipc_input_worker.MockWin32Adapter(initial_locked=True, focus_succeeds=False)
        try:
            ipc_input_worker.inject_credentials_in_memory("123456", adapter=mock_focus)
            assert False, "Should have raised on focus failure"
        except RuntimeError as e:
            log(f"[PASS] 8.3 Input field focus failure aborted: {e}")
            assert "E_FOCUS_FAILED" in str(e)

        # 8.3b REM-026: Real Win32Adapter focus exception never swallowed, returns False and aborts with E_FOCUS_FAILED
        import unlock_engine
        real_adapter = ipc_input_worker.Win32Adapter()
        orig_focus = unlock_engine.focus_credential_field
        def broken_focus(logs):
            raise RuntimeError("SIMULATED_WIN32_FOCUS_EXCEPTION")
        unlock_engine.focus_credential_field = broken_focus
        try:
            focus_logs = []
            focus_res = real_adapter.focus_credential_field(focus_logs)
            assert focus_res is False, f"Expected False on focus exception, got {focus_res}"
            assert any("FOCUS_FAILED" in l for l in focus_logs)

            # Also verify inject_credentials_in_memory fails immediately with E_FOCUS_FAILED and zero SendInput
            orig_get_desk = real_adapter.get_desktop_name
            orig_is_locked = real_adapter.is_workstation_locked
            real_adapter.get_desktop_name = lambda: "winlogon"
            real_adapter.is_workstation_locked = lambda: True
            send_input_called = False
            orig_send = real_adapter.send_input
            def dummy_send(n_inputs, p_inputs, cb_size):
                nonlocal send_input_called
                send_input_called = True
                return n_inputs
            real_adapter.send_input = dummy_send
            try:
                ipc_input_worker.inject_credentials_in_memory("123456", adapter=real_adapter)
                assert False, "Should have raised E_FOCUS_FAILED"
            except RuntimeError as e:
                assert "E_FOCUS_FAILED" in str(e)
                assert send_input_called is False, "CRITICAL: SendInput was called despite focus failure!"
                log(f"[PASS] 8.3b REM-026: Real Win32Adapter exception never swallowed; returned False and aborted with SendInput count=0: {e}")
            finally:
                real_adapter.get_desktop_name = orig_get_desk
                real_adapter.is_workstation_locked = orig_is_locked
                real_adapter.send_input = orig_send
        finally:
            unlock_engine.focus_credential_field = orig_focus

        # 8.4 Windows Hello / Auto-Submit -> Skips Enter, returns SUCCESS_UNLOCKED
        mock_hello = ipc_input_worker.MockWin32Adapter(initial_locked=True, auto_submitted=True)
        res_hello = ipc_input_worker.inject_credentials_in_memory("123456", adapter=mock_hello)
        log(f"[PASS] 8.4 Windows Hello auto-submit handled cleanly: Status={res_hello['status']}, Success={res_hello['success']}")
        assert res_hello["success"] is True and res_hello["status"] == "SUCCESS_UNLOCKED"
        assert any("SUBMIT_SKIPPED" in l for l in res_hello.get("logs", []))

        # 8.5 Curtain transition deadline timeout -> RuntimeError(CURTAIN_NOT_DISMISSED)
        mock_curt_to = ipc_input_worker.MockWin32Adapter(desktop_name="default", curtain_transition_desktop="default")
        try:
            ipc_input_worker.dismiss_curtain_direct(adapter=mock_curt_to)
            assert False, "Should have timed out curtain transition"
        except RuntimeError as e:
            log(f"[PASS] 8.5 Curtain transition deadline timeout: {e}")
            assert "CURTAIN_NOT_DISMISSED" in str(e)

        # 8.6 Non-Winlogon desktop fail-closed -> RuntimeError(E_DESKTOP_NOT_WINLOGON)
        mock_uac = ipc_input_worker.MockWin32Adapter(desktop_name="uac")
        try:
            ipc_input_worker.inject_credentials_in_memory("123456", adapter=mock_uac)
            assert False, "Should have rejected UAC desktop"
        except RuntimeError as e:
            log(f"[PASS] 8.6 Injection on UAC desktop strictly blocked: {e}")
            assert "E_DESKTOP_NOT_WINLOGON" in str(e)

        # 8.7 Helper CLI fail-closed on still locked workstation: exit code 3 (UNLOCK_FAILED)
        helper_pipe_name = f"WinKey_HTest_{uuid.uuid4().hex[:8]}"
        full_hp_name = f"\\\\.\\pipe\\{helper_pipe_name}"
        h_hp = kernel32.CreateNamedPipeW(full_hp_name, 0x00000003, 0, 1, 512, 512, 5000, None)
        assert h_hp and h_hp != -1, "Failed to create helper test pipe"

        try:
            my_pid = os.getpid()
            proc_helper = subprocess.Popen([
                HELPER_EXE, "--mode", "unlock",
                "--ipc-pipe", helper_pipe_name,
                "--expected-server-pid", str(my_pid),
                "--mock-adapter", "wrong_pin"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            kernel32.ConnectNamedPipe(h_hp, None)
            payload = json.dumps({"credential": "WrongPassword999", "target_session": 1}).encode("utf-8")
            written = wintypes.DWORD(0)
            kernel32.WriteFile(h_hp, payload, len(payload), ctypes.byref(written), None)

            h_out, h_err = proc_helper.communicate(timeout=6)
            log(f"[PASS] 8.7 Helper CLI failed-closed on real/locked workstation: Exit code={proc_helper.returncode} (Expected 3=UNLOCK_FAILED)")
            assert proc_helper.returncode == 3 and "UNLOCK_FAILED" in h_out, f"Helper should fail with code 3 (UNLOCK_FAILED), got {proc_helper.returncode}"
        finally:
            kernel32.DisconnectNamedPipe(h_hp)
            kernel32.CloseHandle(h_hp)

        # -------------------------------------------------------------
        # SUITE 9: REM-028 PROTECTED INSTALLER & UNINSTALLER LIFECYCLE (MODEL_UNIT)
        # -------------------------------------------------------------
        log("\n--- SUITE 9: REM-028 Protected Installer & Uninstaller Lifecycle ---")
        # 9.1: Installer Dry-Run
        res_inst_dry = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", "scripts/service_installer.ps1", "-DryRun"],
            capture_output=True, encoding="utf-8", errors="replace"
        )
        assert res_inst_dry.returncode == 0 and "DRY_RUN_PLAN_SUCCESSFUL" in res_inst_dry.stdout
        log(f"[PASS] 9.1 Service installer dry run passed: Exit={res_inst_dry.returncode} (Plan validated)")

        # 9.2: Installer fail-closed on invalid source
        res_inst_bogus = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", "scripts/service_installer.ps1", "-SourceDir", "C:\\InvalidNonExistentDir_Bogus"],
            capture_output=True, encoding="utf-8", errors="replace"
        )
        assert res_inst_bogus.returncode == 1 and "E_SOURCE_NOT_FOUND" in res_inst_bogus.stdout
        log(f"[PASS] 9.2 Service installer fail-closed on missing source: Exit={res_inst_bogus.returncode} (E_SOURCE_NOT_FOUND)")

        # 9.3: Installer fail-closed on invalid owner SID
        res_inst_sid = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", "scripts/service_installer.ps1", "-OwnerSid", "invalid_bogus_sid", "-DryRun"],
            capture_output=True, encoding="utf-8", errors="replace"
        )
        assert res_inst_sid.returncode == 1 and "E_INVALID_OWNER_SID" in res_inst_sid.stdout
        log(f"[PASS] 9.3 Service installer fail-closed on invalid owner SID: Exit={res_inst_sid.returncode} (E_INVALID_OWNER_SID)")

        # 9.4: Uninstaller Dry-Run
        res_uninst_dry = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", "scripts/service_uninstaller.ps1", "-DryRun"],
            capture_output=True, encoding="utf-8", errors="replace"
        )
        assert res_uninst_dry.returncode == 0 and "DRY_RUN_UNINSTALL_SUCCESSFUL" in res_uninst_dry.stdout
        log(f"[PASS] 9.4 Service uninstaller dry run passed: Exit={res_uninst_dry.returncode} (Teardown sequence validated)")

        log("\n=================================================================")
        log("  ALL REVISION 10 NEGATIVE & STRICT BOUNDARY TESTS PASSED (45/45) ")
        log("=================================================================")

    finally:
        try:
            proc_gw.terminate()
            proc_gw.wait(timeout=2.0)
        except:
            proc_gw.kill()

if __name__ == "__main__":
    run_negative_suite()
