import unittest
import os
import sys
import time
import shutil
import tempfile
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

def find_winkey_service_exe():
    dbg = ROOT_DIR / "apps" / "winkey_service" / "target" / "debug" / "winkey_service.exe"
    if dbg.is_file():
        return str(dbg)
    rel = ROOT_DIR / "deploy" / "pre_signed_slot_a" / "winkey_service.exe"
    if rel.is_file():
        return str(rel)
    raise RuntimeError("winkey_service.exe not found")

class TestSlotProcessCleanup(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="winkey_test_cleanup_")
        self.svc_exe = find_winkey_service_exe()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_sibling_directory_process_preserved(self):
        # Create slot_a and slot_a_other
        slot_a = Path(self.tmp_dir) / "slot_a"
        slot_a_other = Path(self.tmp_dir) / "slot_a_other"
        slot_a.mkdir(parents=True, exist_ok=True)
        slot_a_other.mkdir(parents=True, exist_ok=True)

        sibling_exe = slot_a_other / "winkey_desktop.exe"
        shutil.copy2(sys.executable, sibling_exe)

        # Launch sleeping child from slot_a_other
        proc = subprocess.Popen([str(sibling_exe), "-c", "import time; time.sleep(10)"])
        time.sleep(0.3)
        try:
            self.assertIsNone(proc.poll(), "Sibling process must be running")

            # Clean slot_a (target_dir = slot_a)
            res = subprocess.run(
                [self.svc_exe, "--clean-slot", str(slot_a)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace"
            )
            self.assertEqual(res.returncode, 0)
            self.assertIn("PASS_SLOT_CLEANED", res.stdout)

            # Sibling process in slot_a_other MUST STILL BE RUNNING!
            self.assertIsNone(proc.poll(), "Sibling directory process must NOT be terminated!")
        finally:
            proc.kill()
            proc.wait()

    def test_02_inactive_slot_process_deferred_not_killed(self):
        """Slot cleanup must NOT forcibly terminate processes; it must defer safely with E_TARGET_SLOT_IN_USE."""
        slot_a = Path(self.tmp_dir) / "slot_a"
        slot_a.mkdir(parents=True, exist_ok=True)

        target_exe = slot_a / "winkey_desktop.exe"
        shutil.copy2(sys.executable, target_exe)

        # Launch sleeping child inside slot_a
        proc = subprocess.Popen([str(target_exe), "-c", "import time; time.sleep(10)"])
        time.sleep(0.3)
        try:
            self.assertIsNone(proc.poll(), "Target slot process must be running")

            # Clean/inspect slot_a
            res = subprocess.run(
                [self.svc_exe, "--clean-slot", str(slot_a)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace"
            )
            # Must return non-zero error indicating slot is in use (safe deferral)
            self.assertNotEqual(res.returncode, 0, "Must defer when process is running in slot")
            self.assertIn("E_TARGET_SLOT_IN_USE", res.stderr)

            # CRITICAL: Target process in slot_a MUST NOT BE FORCIBLY KILLED!
            time.sleep(0.3)
            self.assertIsNone(proc.poll(), "Target process must NOT be forcibly terminated; update is safely deferred!")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()

    def test_03_root_and_system_directory_cleaning_prohibited(self):
        # Attempting to clean root or Windows folder must fail closed
        res_root = subprocess.run(
            [self.svc_exe, "--clean-slot", "C:\\"],
            capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
        self.assertNotEqual(res_root.returncode, 0)
        self.assertIn("E_TARGET_DIR_IS_ROOT_PROHIBITED", res_root.stderr)

        res_sys = subprocess.run(
            [self.svc_exe, "--clean-slot", "C:\\Windows\\System32"],
            capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
        self.assertNotEqual(res_sys.returncode, 0)
        self.assertIn("E_TARGET_DIR_IS_SYSTEM_PROHIBITED", res_sys.stderr)

    def test_04_reparse_point_prohibited(self):
        """Reparse point / directory junction must fail closed with E_TARGET_DIR_IS_REPARSE_POINT_PROHIBITED."""
        real_target = Path(self.tmp_dir) / "real_slot"
        real_target.mkdir(parents=True, exist_ok=True)
        junction_target = Path(self.tmp_dir) / "junction_slot"

        # Create NTFS junction on Windows
        try:
            subprocess.run(["cmd", "/c", "mklink", "/J", str(junction_target), str(real_target)],
                           capture_output=True, check=True)
        except Exception:
            self.skipTest("mklink /J not supported in this environment")

        try:
            res_junc = subprocess.run(
                [self.svc_exe, "--clean-slot", str(junction_target)],
                capture_output=True, text=True, encoding="utf-8", errors="replace"
            )
            self.assertNotEqual(res_junc.returncode, 0)
            self.assertIn("E_TARGET_DIR_IS_REPARSE_POINT_PROHIBITED", res_junc.stderr)
        finally:
            subprocess.run(["cmd", "/c", "rmdir", str(junction_target)], capture_output=True)

if __name__ == "__main__":
    unittest.main()
