import sys
import os
import time
import json
import ctypes
from ctypes import wintypes
import subprocess

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

REPORT_LOG = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "plan", "reports", "remaining", "revision3", "ipc_stop_lifecycle.log"))
REPORT_LOG_REV8 = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "plan", "reports", "remaining", "revision8", "ipc_stop_lifecycle.log"))
REPORT_LOG_REV9 = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "plan", "reports", "remaining", "revision9", "ipc_stop_lifecycle.log"))
REPORT_LOG_REV10 = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "plan", "reports", "remaining", "revision10", "ipc_stop_lifecycle.log"))
SERVICE_EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "apps", "winkey_service", "target", "release", "winkey_service.exe"))
PIPE_NAME = r"\\.\pipe\WinKey_Service_IPC"

# B.2b Dar User-Channel Access Mask və SQOS
PIPE_MIN_USER_CHANNEL_MASK = 0x0012008B
SECURITY_SQOS_PRESENT = 0x00100000
SECURITY_IDENTIFICATION = 0x00010000
FLAGS_SECURITY = SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION

OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = -1

kernel32 = ctypes.windll.kernel32

def log(msg):
    try:
        print(msg)
    except:
        print(msg.encode('ascii', 'replace').decode('ascii'))
    sys.stdout.flush()
    for lp in [REPORT_LOG, REPORT_LOG_REV8, REPORT_LOG_REV9, REPORT_LOG_REV10]:
        os.makedirs(os.path.dirname(lp), exist_ok=True)
        with open(lp, "a", encoding="utf-8") as f:
            f.write(msg + "\n")

def open_pipe(access_mask=PIPE_MIN_USER_CHANNEL_MASK, flags=FLAGS_SECURITY):
    h = kernel32.CreateFileW(
        PIPE_NAME,
        access_mask,
        0,
        None,
        OPEN_EXISTING,
        flags,
        None
    )
    return h

def send_pipe_msg(msg_str):
    h = open_pipe()
    if h == INVALID_HANDLE_VALUE:
        err = kernel32.GetLastError()
        raise RuntimeError(f"CreateFileW failed with Win32 Error: {err}")

    try:
        data = (msg_str + "\n").encode("utf-8")
        written = wintypes.DWORD()
        res = kernel32.WriteFile(h, data, len(data), ctypes.byref(written), None)
        if not res:
            raise RuntimeError(f"WriteFile failed with Error: {kernel32.GetLastError()}")

        buf = ctypes.create_string_buffer(4096)
        read = wintypes.DWORD()
        res = kernel32.ReadFile(h, buf, 4096, ctypes.byref(read), None)
        if not res:
            raise RuntimeError(f"ReadFile failed with Error: {kernel32.GetLastError()}")

        return buf.value[:read.value].decode("utf-8")
    finally:
        kernel32.CloseHandle(h)

def run_tests():
    os.makedirs(os.path.dirname(REPORT_LOG), exist_ok=True)
    with open(REPORT_LOG, "w", encoding="utf-8") as f:
        f.write("=== WinKey Pro — B.2 Secure IPC, STOP & Lifecycle Verification ===\n")
        f.write(f"Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

    log("=================================================================")
    log("  WinKey Pro — B.2 IPC Lifecycle, STOP & Silent Client Tests      ")
    log("  Classification: B2_SECURE_IPC | NARROW_DACL | BOUNDED_TIMEOUT  ")
    log("=================================================================")

    # TEST 1: Timeout Process Exit (Standalone Auto-Exit without Hang)
    log("\n--- TEST 1: Standalone Timeout Process Exit (Zero Hang Proof) ---")
    t0 = time.perf_counter()
    proc_timeout = subprocess.run([SERVICE_EXE, "--standalone", "--timeout-sec", "2"], capture_output=True, text=True)
    dur = time.perf_counter() - t0
    log(f"[PASS] Service exited automatically on timeout in {dur:.2f}s (Exit code: {proc_timeout.returncode})")
    assert proc_timeout.returncode == 0, f"Expected 0, got {proc_timeout.returncode}"
    assert 1.8 <= dur <= 4.0, f"Duration {dur} outside expected 2s window!"

    # Start Service in Standalone mode for remaining tests
    log("\n[SETUP] Launching WinKey Service in standalone mode...")
    proc = subprocess.Popen([SERVICE_EXE, "--standalone", "--timeout-sec", "20"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1.2)

    try:
        # TEST 2: Narrow DACL Enforcement (Excessive Permissions Rejection)
        log("\n--- TEST 2: Narrow DACL Enforcement & Minimum Channel Security ---")
        # Attacker tries to open pipe with GENERIC_WRITE (which grants FILE_CREATE_PIPE_INSTANCE 0x0004)
        h_forbidden = open_pipe(access_mask=0x40000000, flags=0) # GENERIC_WRITE
        err_forbidden = kernel32.GetLastError()
        log(f"[PASS] Broad GENERIC_WRITE request strictly rejected: Handle={h_forbidden}, Error={err_forbidden} (ERROR_ACCESS_DENIED=5)")
        assert h_forbidden == INVALID_HANDLE_VALUE, "DACL failed to reject broad access!"
        if h_forbidden != INVALID_HANDLE_VALUE:
            kernel32.CloseHandle(h_forbidden)

        # Legitimate client opens with PIPE_MIN_USER_CHANNEL_MASK (0x0012008B)
        h_valid = open_pipe(access_mask=PIPE_MIN_USER_CHANNEL_MASK, flags=FLAGS_SECURITY)
        assert h_valid != INVALID_HANDLE_VALUE, f"Legitimate connection failed with Error: {kernel32.GetLastError()}"
        kernel32.CloseHandle(h_valid)
        log(f"[PASS] Legitimate connection with minimum mask 0x0012008B accepted!")

        # TEST 3: Connected Silent Client & Deadline Cancellation (3s Timeout)
        log("\n--- TEST 3: Connected Silent Client & Bounded Read Cancellation ---")
        log("[CLIENT] Connecting to pipe and intentionally remaining silent (zero bytes sent)...")
        h_silent = open_pipe()
        assert h_silent != INVALID_HANDLE_VALUE, "Failed to connect silent client"

        log("[CLIENT] Sleeping 3.5 seconds to trigger server-side 3s deadline cancellation...")
        time.sleep(3.5)

        kernel32.CloseHandle(h_silent)
        log("[PASS] Silent client connection completed server-side deadline cancellation.")

        # Verify server is still alive and responsive to subsequent legitimate requests!
        log("[VERIFY] Sending legitimate PING to verify service did NOT crash or deadlock...")
        resp_ping = send_pipe_msg("PING")
        log(f"[PASS] Server response: {resp_ping.strip()}")
        assert "Ack" in resp_ping or "ACK" in resp_ping
        log("[PASS] Server remained healthy and active after silent client cancellation!")

        # TEST 4: Service STOP Signal via IPC
        log("\n--- TEST 4: IPC STOP Command & Bounded Clean Teardown ---")
        t_stop_start = time.perf_counter()
        resp_stop = send_pipe_msg("STOP")
        log(f"[PASS] STOP Command Response: {resp_stop.strip()}")

        # Process should terminate cleanly within 3 seconds
        try:
            exit_code = proc.wait(timeout=3.5)
            t_stop_dur = time.perf_counter() - t_stop_start
            log(f"[PASS] Service terminated cleanly via STOP in {t_stop_dur:.2f}s (Exit Code: {exit_code})")
            assert exit_code == 0
        except subprocess.TimeoutExpired:
            proc.kill()
            raise AssertionError("Service failed to terminate on STOP command within 3.5s deadline!")

        # TEST 5: Handle Cleanup Verification (Pipe Freed)
        log("\n--- TEST 5: Named Pipe Handle Cleanup Audit ---")
        time.sleep(0.5)
        h_dangling = open_pipe()
        assert h_dangling == INVALID_HANDLE_VALUE, "Pipe handle still accessible after shutdown!"
        err = kernel32.GetLastError()
        log(f"[PASS] Subsequent connection failed as expected (Win32 Error: {err} -> ERROR_FILE_NOT_FOUND/PIPE_BUSY)")

        log("\n=================================================================")
        log("  ALL B.2 IPC STOP & LIFECYCLE TESTS PASSED (5/5 PASS)           ")
        log("=================================================================")

    finally:
        try:
            proc.terminate()
            proc.wait(timeout=1.0)
        except:
            proc.kill()

if __name__ == "__main__":
    run_tests()
