import sys
import os
import time
import subprocess
import psutil

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

DESKTOP_EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "apps", "desktop_tauri", "src-tauri", "target", "release", "winkey_desktop.exe"))

def get_winkey_desktop_pids():
    pids = []
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            if proc.info['exe'] and os.path.normcase(os.path.realpath(proc.info['exe'])) == os.path.normcase(os.path.realpath(DESKTOP_EXE)):
                pids.append(proc.info['pid'])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return pids

def test_singleton_lifecycle():
    print("=================================================================")
    print("  WinKey Pro — Desktop Single-Instance & Mutex Lifecycle Test   ")
    print("  Classification: SINGLETON_VALIDATION | SESSION_MUTEX | TRAY    ")
    print("=================================================================")

    # Never terminate a user's existing app. Test only a process created here.
    stale = get_winkey_desktop_pids()
    if stale:
        print("[NOT_TESTED] Existing desktop instance is open; left untouched. Close it via tray Exit before rerunning.")
        return

    # 1. Launch Primary Instance
    print("\n[LAUNCH 1] Starting Primary WinKey Desktop instance...")
    proc1 = subprocess.Popen([DESKTOP_EXE], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(2.5)

    try:
        active_pids = get_winkey_desktop_pids()
        print(f"[STATUS] Active desktop processes: {active_pids}")
        assert len(active_pids) == 1, f"Expected 1 active process, got {len(active_pids)}"
        assert proc1.pid in active_pids, "Primary process not in active PIDs"
        print(f"[PASS] Primary desktop process running: PID={proc1.pid}")

        # 2. Launch Secondary Duplicate Instance
        print("\n[LAUNCH 2] Attempting to launch second instance...")
        t0 = time.time()
        res2 = subprocess.run([DESKTOP_EXE], capture_output=True, text=True, timeout=5)
        dt = time.time() - t0
        print(f"[RESULT] Second instance exit code: {res2.returncode} in {dt:.2f}s")
        print(f"[RESULT] Second instance stdout: '{res2.stdout.strip()}'")
        assert res2.returncode == 0, f"Second instance failed with code {res2.returncode}: {res2.stderr}"
        assert "[SINGLETON]" in res2.stdout, "Singleton message not found in stdout"
        assert "Session" in res2.stdout, "Session info not found in stdout"

        # Verify still strictly 1 active process
        active_after = get_winkey_desktop_pids()
        print(f"[STATUS] Active desktop processes after duplicate launch: {active_after}")
        assert len(active_after) == 1, f"Duplicate process leaked! Active: {active_after}"
        assert active_after[0] == proc1.pid
        print("[PASS] Duplicate launch strictly rejected by session mutex and closed without leaking a second process (tray icon count not measured)!")

        # 3. Burst Launch Stress Test (8 rapid concurrent/sequential launches)
        print("\n[STRESS] Burst launching 8 rapid duplicate instances...")
        for i in range(8):
            res_burst = subprocess.run([DESKTOP_EXE], capture_output=True, text=True, timeout=4)
            assert res_burst.returncode == 0
            assert "[SINGLETON]" in res_burst.stdout

        stress_pids = get_winkey_desktop_pids()
        print(f"[STATUS] Active desktop processes after 8 rapid launches: {stress_pids}")
        assert len(stress_pids) == 1 and stress_pids[0] == proc1.pid
        print("[PASS] Stress launch test passed: Exactly 1 primary process remains alive across 8 rapid attempts (one process; tray icon count not measured).")

        print("\n=================================================================")
        print("  SINGLETON PROCESS TEST PASSED; TRAY CLICK/EXIT STILL REQUIRE UI TEST         ")
        print("=================================================================")

    finally:
        print("\n[CLEANUP] Terminating primary test process...")
        try:
            proc1.terminate()
            proc1.wait(timeout=2.0)
        except:
            proc1.kill()
        time.sleep(0.5)

if __name__ == "__main__":
    test_singleton_lifecycle()
