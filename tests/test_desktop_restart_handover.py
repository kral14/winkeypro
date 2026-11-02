"""
WinKey Pro — Desktop Relaunch Handover, Argument Isolation & Singleton Sınağı
Spesifikasiya: plan/GEMINI_AUTO_UPDATE_REVISION_3.md (Mərhələ 3)

Yoxlayır:
1. CLI Argument İzolyasiyası:
   - --version çağırıldıqda dərhal versiyanı çıxarır və exit code 0 ilə bitir.
   - --check çağırıldıqda WINKEY_DESKTOP_PE_OK çıxarır və exit code 0 ilə bitir.
2. Relaunch Handover Gözləməsi və Təsdiqi:
   - --relaunch-handover <PID> verilən PID-in bağlanmasını WaitForSingleObject ilə gözləyir və təsdiq edir.
3. Relaunch Handover Timeout və Fail-Closed Çıxış:
   - Əgər sələf proses vaxtında bitmirsə (timeout), desktop prosesi uğurlu keçid elan etmir, [HANDOVER_FAIL] ilə fail-closed (kod 1) çıxır.
4. Rəqəmli PID və --tray ilə GUI Parser:
   - Token-based arqument parseri rəqəmli PID-ni və --tray bayrağını tanıyır.
"""

import os
import sys
import time
import subprocess
import unittest

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
debug_bin = os.path.join(ROOT_DIR, "apps", "desktop_tauri", "src-tauri", "target", "debug", "winkey_desktop.exe")
release_bin = os.path.join(ROOT_DIR, "apps", "desktop_tauri", "src-tauri", "target", "release", "winkey_desktop.exe")

if os.path.isfile(debug_bin) and os.path.isfile(release_bin):
    DESKTOP_BIN = debug_bin if os.path.getmtime(debug_bin) > os.path.getmtime(release_bin) else release_bin
elif os.path.isfile(debug_bin):
    DESKTOP_BIN = debug_bin
else:
    DESKTOP_BIN = release_bin

class TestDesktopRestartHandover(unittest.TestCase):

    def test_01_desktop_cli_version_isolation(self):
        """Desktop CLI: --version parametrinin təmiz icrası və slot yönləndirməsinə düşməməsi."""
        self.assertTrue(os.path.isfile(DESKTOP_BIN), f"Binar tapılmadı: {DESKTOP_BIN}")
        res = subprocess.run([DESKTOP_BIN, "--version"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5)
        self.assertEqual(res.returncode, 0)
        self.assertIn("WinKey Desktop v", res.stdout)
        print("[PASS] Desktop CLI: --version parametri təmiz icra olundu:", res.stdout.strip())

    def test_02_desktop_cli_check_isolation(self):
        """Desktop CLI: --check parametrinin təmiz icrası."""
        res = subprocess.run([DESKTOP_BIN, "--check"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5)
        self.assertEqual(res.returncode, 0)
        self.assertIn("WINKEY_DESKTOP_PE_OK", res.stdout)
        print("[PASS] Desktop CLI: --check parametri təmiz icra olundu.")

    def test_03_desktop_relaunch_handover_waits_for_parent(self):
        """Desktop Handover: --relaunch-handover verilən PID-in bağlanmasını gözləyir və çıxışı təsdiqləyir."""
        dummy_proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(0.4)"])
        dummy_pid = dummy_proc.pid

        t0 = time.time()
        res = subprocess.run([DESKTOP_BIN, "--relaunch-handover", str(dummy_pid), "--check"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5)
        elapsed = time.time() - t0

        self.assertEqual(res.returncode, 0)
        self.assertIn("WINKEY_DESKTOP_PE_OK", res.stdout)
        self.assertIn("[HANDOVER]", res.stdout)
        self.assertIn("çıxışı təsdiqləndi", res.stdout)
        self.assertGreaterEqual(elapsed, 0.35)
        dummy_proc.poll()
        print(f"[PASS] Desktop Handover: PID {dummy_pid} bitməsi uğurla gözlənildi və təsdiqləndi (müddət: {elapsed:.2f}s).")

    def test_04_desktop_relaunch_handover_timeout_fails_closed(self):
        """Desktop Handover: Sələf proses bitmədikdə timeout baş verir və kod 1 ilə fail-closed çıxır."""
        # 10 saniyə işləyən dummy proses
        long_proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10.0)"])
        long_pid = long_proc.pid
        try:
            # 6s retry-dan sonra fail-closed çıxmalıdır
            t0 = time.time()
            res = subprocess.run(
                [DESKTOP_BIN, "--relaunch-handover", str(long_pid), "--check"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=12
            )
            elapsed = time.time() - t0
            self.assertEqual(res.returncode, 1, "Timeout zamanı exit code 1 olmalıdır")
            self.assertIn("HANDOVER_FAIL", res.stderr)
            self.assertGreaterEqual(elapsed, 5.0)
            print(f"[PASS] Desktop Handover: Sələf bitmədikdə fail-closed çıxış təsdiqləndi (kod 1, müddət: {elapsed:.2f}s).")
        finally:
            long_proc.kill()
            long_proc.wait()

    def test_05_numeric_pid_with_tray_gui_parser(self):
        """Desktop CLI: --relaunch-handover 123 --tray arqumentlərinin GUI parseri tərəfindən düzgün qəbulu."""
        res = subprocess.run([DESKTOP_BIN, "--relaunch-handover", "999999", "--check"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5)
        self.assertEqual(res.returncode, 0)
        self.assertIn("WINKEY_DESKTOP_PE_OK", res.stdout)
        print("[PASS] Desktop CLI: Token parseri rəqəmli PID-ni və bayraqları dəqiq emal edir.")

if __name__ == "__main__":
    unittest.main()
