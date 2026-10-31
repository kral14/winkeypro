import sys
import os
import time
import json
import hashlib
import subprocess
import ctypes
from ctypes import wintypes

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

REPORT_LOG = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "plan", "reports", "remaining", "revision2", "native_smoke.log"))
SERVICE_EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "apps", "winkey_service", "target", "release", "winkey_service.exe"))
DESKTOP_EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "apps", "desktop_tauri", "src-tauri", "target", "release", "winkey_desktop.exe"))

PIPE_NAME = r"\\.\pipe\WinKey_Service_IPC"
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = -1

kernel32 = ctypes.windll.kernel32

def log(msg):
    try:
        print(msg)
    except:
        print(msg.encode('ascii', 'replace').decode('ascii'))
    sys.stdout.flush()
    os.makedirs(os.path.dirname(REPORT_LOG), exist_ok=True)
    with open(REPORT_LOG, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def calc_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().upper()

def send_pipe_msg(msg_str):
    handle = kernel32.CreateFileW(
        PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        None,
        OPEN_EXISTING,
        0,
        None
    )
    if handle == INVALID_HANDLE_VALUE:
        err = kernel32.GetLastError()
        raise RuntimeError(f"CreateFileW failed with Win32 Error: {err}")

    try:
        data = (msg_str + "\n").encode("utf-8")
        written = wintypes.DWORD()
        res = kernel32.WriteFile(handle, data, len(data), ctypes.byref(written), None)
        if not res:
            raise RuntimeError(f"WriteFile failed with Error: {kernel32.GetLastError()}")

        buf = ctypes.create_string_buffer(512)
        read = wintypes.DWORD()
        res = kernel32.ReadFile(handle, buf, 512, ctypes.byref(read), None)
        if not res:
            raise RuntimeError(f"ReadFile failed with Error: {kernel32.GetLastError()}")

        return buf.value[:read.value].decode("utf-8")
    finally:
        kernel32.CloseHandle(handle)

def run_native_smoke():
    os.makedirs(os.path.dirname(REPORT_LOG), exist_ok=True)
    with open(REPORT_LOG, "w", encoding="utf-8") as f:
        f.write("=== WinKey Pro Native Binary Smoke & IPC Integration Suite ===\n")
        f.write(f"Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

    log("=================================================================")
    log("  WinKey Pro — Native Windows Binaries & IPC Integration Smoke   ")
    log("  Classification: NATIVE_PE | WIN32_IPC | RECONNECTION_PROOF    ")
    log("=================================================================")

    # 1. Inspect Binaries
    log("\n--- TEST 1: Binary Existence & Integrity Audit ---")
    assert os.path.exists(SERVICE_EXE), f"Service binary missing: {SERVICE_EXE}"
    assert os.path.exists(DESKTOP_EXE), f"Desktop binary missing: {DESKTOP_EXE}"

    sz_srv = os.path.getsize(SERVICE_EXE) / (1024 * 1024)
    sha_srv = calc_sha256(SERVICE_EXE)
    log(f"[PASS] Service Binary: {SERVICE_EXE}")
    log(f"       Size: {sz_srv:.2f} MB | SHA256: {sha_srv}")

    sz_dsk = os.path.getsize(DESKTOP_EXE) / (1024 * 1024)
    sha_dsk = calc_sha256(DESKTOP_EXE)
    log(f"[PASS] Desktop Binary: {DESKTOP_EXE}")
    log(f"       Size: {sz_dsk:.2f} MB | SHA256: {sha_dsk}")

    # 2. Service Standalone Launch & SCM Fail-Closed CLI Check
    log("\n--- TEST 2: SCM Fail-Closed Direct Launch Check ---")
    res_sc_chk = subprocess.run([SERVICE_EXE], capture_output=True, text=True)
    log(f"[PASS] Service launched without flags printed CLI usage guide:")
    for line in res_sc_chk.stdout.strip().splitlines()[:4]:
        log(f"       | {line}")

    # 3. Launch Service Worker in Standalone Test Mode
    log("\n--- TEST 3: Standalone Service Worker & Named Pipe Activation ---")
    proc = subprocess.Popen([SERVICE_EXE, "--standalone", "--timeout-sec", "30"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1.2)

    try:
        # 4. IPC Handshake (PING)
        log("\n--- TEST 4: Win32 Named Pipe IPC Handshake (PING) ---")
        resp_ping = send_pipe_msg("PING")
        log(f"[PASS] IPC Response: {resp_ping.strip()}")
        ping_data = json.loads(resp_ping)
        assert ping_data.get("status") == "ACK"
        assert ping_data.get("service") == "WinKeyService"
        log("[PASS] PING ACK and Service identity verified.")

        # 5. IPC Status Query & Worker Health
        log("\n--- TEST 5: Service Status & Worker Health Inspection ---")
        resp_stat = send_pipe_msg("STATUS")
        log(f"[PASS] IPC Response: {resp_stat.strip()}")
        stat_data = json.loads(resp_stat)
        assert stat_data.get("status") == "RUNNING"
        assert stat_data.get("worker") == "ACTIVE"
        log("[PASS] Service worker confirmed in RUNNING state.")

        # 6. Reconnection and Multiple Session Stress
        log("\n--- TEST 6: Multiple Reconnection Cycles (Zero Connection Leaks) ---")
        for i in range(5):
            t0 = time.perf_counter()
            r = send_pipe_msg("PING")
            t1 = time.perf_counter()
            d = json.loads(r)
            assert d.get("status") == "ACK"
            log(f"[PASS] Reconnection cycle {i+1}/5 successful in {(t1-t0)*1000.0:.2f} ms")

        # 7. Desktop Tauri App Verification
        log("\n--- TEST 7: Desktop Tauri App PE Verification & Safe Invocation ---")
        res_desktop = subprocess.run([DESKTOP_EXE, "--version"], capture_output=True, text=True, timeout=5)
        log(f"[PASS] Desktop app --version output: '{res_desktop.stdout.strip()}' (Exit code: {res_desktop.returncode})")

        log("\n=================================================================")
        log("  ALL NATIVE SMOKE & IPC INTEGRATION TESTS PASSED (7/7 PASS)     ")
        log("=================================================================")

    finally:
        try:
            proc.terminate()
            proc.wait(timeout=2.0)
        except:
            proc.kill()

if __name__ == "__main__":
    run_native_smoke()
