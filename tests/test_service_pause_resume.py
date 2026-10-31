import subprocess
import time
import os
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

def main():
    service_exe = os.path.abspath("apps/winkey_service/target/release/winkey_service.exe")
    desktop_exe = os.path.abspath("apps/desktop_tauri/src-tauri/target/release/winkey_desktop.exe")

    if not os.path.exists(service_exe):
        print(f"FAIL: service exe not found: {service_exe}")
        sys.exit(1)
    if not os.path.exists(desktop_exe):
        print(f"FAIL: desktop exe not found: {desktop_exe}")
        sys.exit(1)

    print("[TEST] WinKey Service standalone rejimdə işə salınır...")
    service_proc = subprocess.Popen(
        [service_exe, "--standalone", "--mock", "--timeout-sec", "30"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    time.sleep(1.0)
    service_pid = service_proc.pid
    os.environ["WINKEY_TRUSTED_SERVICE_PID"] = str(service_pid)

    try:
        # 1. Status yoxla
        print(f"[TEST 1] Desktop vasitəsilə --service-status göndərilir (Service PID={service_pid})...")
        res_stat = subprocess.run([desktop_exe, "--service-status"], capture_output=True, text=True, timeout=5)
        print("Status çıxışı:", res_stat.stdout.strip())
        assert res_stat.returncode == 0, f"Status failed: {res_stat.stderr}"
        assert "OK_SERVICE_STATUS" in res_stat.stdout, "OK_SERVICE_STATUS gözlənilirdi"

        # 2. Pause göndər
        print("[TEST 2] Desktop vasitəsilə --service-pause göndərilir...")
        res_pause = subprocess.run([desktop_exe, "--service-pause"], capture_output=True, text=True, timeout=5)
        print("Pause çıxışı:", res_pause.stdout.strip())
        assert res_pause.returncode == 0, f"Pause failed: {res_pause.stderr}"
        assert "OK_SERVICE_PAUSED" in res_pause.stdout, "OK_SERVICE_PAUSED gözlənilirdi"

        # 3. Resume göndər
        print("[TEST 3] Desktop vasitəsilə --service-resume göndərilir...")
        res_resume = subprocess.run([desktop_exe, "--service-resume"], capture_output=True, text=True, timeout=5)
        print("Resume çıxışı:", res_resume.stdout.strip())
        assert res_resume.returncode == 0, f"Resume failed: {res_resume.stderr}"
        assert "OK_SERVICE_RESUMED" in res_resume.stdout, "OK_SERVICE_RESUMED gözlənilirdi"

        print("[PASS] Desktop -> Service Pause/Resume/Status IPC axını 100% uğurla tamamlandı!")

    finally:
        service_proc.terminate()
        try:
            service_proc.wait(timeout=3)
        except Exception:
            service_proc.kill()

if __name__ == "__main__":
    main()
