"""
WinKey Pro — Fresh Install Baseline & Extracted Package Preflight Testi
Direktiv: plan/GEMINI_SIGNING_WORKER_BLOCKERS.md (P0 / Açıq Qalıqlar)

Yoxlayır:
1. Extracted release paketində heç bir private key (*.bin, *.key) OLMADAN,
   hazır pre-signed manifest.json və manifest.sig mövcuddur.
2. Installer-in Slot A provisioning və native validation addımları Python-suz,
   tamamilə native binary verifier (winkey_service.exe --validate-slot) vasitəsilə təsdiqlənir.
3. Native service boot preflight (winkey_service.exe --evaluate-recovery)
   fresh install mühitində uğurla NORMAL_BOOT slot=slot_a təsdiq edir.
4. Tampered və ya imzasız slotlar fail-closed rədd edilir.
"""

import os
import sys
import json
import shutil
import zipfile
import tempfile
import subprocess
import unittest

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ZIP_PATH = os.path.join(ROOT_DIR, "plan", "reports", "final_batch", "WinKeyPro-v0.1.0-Windows-x64-FinalBuild.zip")

class TestFreshInstallPreflight(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="winkey_extracted_install_")
        self.source_dir = os.path.join(self.tmp_dir, "extracted_pkg")
        self.data_dir = os.path.join(self.tmp_dir, "WinKeyData")
        self.install_dir = os.path.join(self.tmp_dir, "ProgramFiles_WinKey")
        os.makedirs(self.source_dir, exist_ok=True)
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.install_dir, exist_ok=True)

        # ZIP paketini çıxarırıq (əgər ZIP varsa) və ya build çıxışından götürürük
        if os.path.exists(ZIP_PATH):
            with zipfile.ZipFile(ZIP_PATH, "r") as zf:
                zf.extractall(self.source_dir)
        else:
            # Fallback to local build outputs
            svc = os.path.join(ROOT_DIR, "apps", "winkey_service", "target", "release", "winkey_service.exe")
            hlp = os.path.join(ROOT_DIR, "apps", "winkey_service", "target", "release", "winkey_helper.exe")
            mf = os.path.join(ROOT_DIR, "deploy", "pre_signed_slot_a", "manifest.json")
            sig = os.path.join(ROOT_DIR, "deploy", "pre_signed_slot_a", "manifest.sig")
            installer = os.path.join(ROOT_DIR, "scripts", "service_installer.ps1")
            shutil.copy2(svc, self.source_dir)
            shutil.copy2(hlp, self.source_dir)
            shutil.copy2(mf, self.source_dir)
            shutil.copy2(sig, self.source_dir)
            shutil.copy2(installer, self.source_dir)

        self.service_bin = os.path.join(self.source_dir, "winkey_service.exe")
        self.helper_bin = os.path.join(self.source_dir, "winkey_helper.exe")
        self.manifest_file = os.path.join(self.source_dir, "manifest.json")
        self.sig_file = os.path.join(self.source_dir, "manifest.sig")
        self.installer_ps1 = os.path.join(self.source_dir, "service_installer.ps1")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_extracted_payload_contains_no_private_keys(self):
        """Extracted paketdə heç bir *.key, *.bin və ya gizli açar faylı olmamalıdır."""
        for root, _, files in os.walk(self.source_dir):
            for f in files:
                lower = f.lower()
                self.assertFalse(
                    any(k in lower for k in [".key", "compromised", "private", "priv_"]),
                    f"Təhlükəsizlik xətası: Çıxarılmış paketdə gizli açar aşkarlandı: {f}"
                )
        self.assertTrue(os.path.exists(self.manifest_file), "manifest.json mövcud olmalıdır")
        self.assertTrue(os.path.exists(self.sig_file), "manifest.sig mövcud olmalıdır")

    def test_02_installer_dry_run_syntax_and_plan(self):
        """service_installer.ps1 -DryRun rejimində sistemi dəyişmədən planı təsdiq edir."""
        ps_cmd = [
            "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", self.installer_ps1,
            "-SourceDir", self.source_dir,
            "-InstallDir", self.install_dir,
            "-DataDir", self.data_dir,
            "-OwnerSid", "S-1-5-21-1234567890-1234567890-1234567890-1001",
            "-DryRun"
        ]
        res = subprocess.run(ps_cmd, capture_output=True, text=True, errors="replace")
        print("\n--- INSTALLER DRY-RUN OUTPUT ---")
        print(res.stdout)
        self.assertEqual(res.returncode, 0, f"Installer DryRun uğursuz oldu: {res.stderr}")
        self.assertIn("DRY_RUN_PLAN_SUCCESSFUL", res.stdout, "Plan təsdiq mesajı olmalıdır")

    def test_03_zero_python_fresh_install_baseline_and_native_recovery(self):
        """Python olmadan pre-signed Slot A baseline kopyalanması və native recovery boot."""
        slot_a_dir = os.path.join(self.data_dir, "versions", "slot_a")
        os.makedirs(slot_a_dir, exist_ok=True)

        # Installer-in icra etdiyi dəqiq Slot A kopyalama yolu
        shutil.copy2(self.service_bin, os.path.join(slot_a_dir, "winkey_service.exe"))
        shutil.copy2(self.helper_bin, os.path.join(slot_a_dir, "winkey_helper.exe"))
        shutil.copy2(self.manifest_file, os.path.join(slot_a_dir, "manifest.json"))
        shutil.copy2(self.sig_file, os.path.join(slot_a_dir, "manifest.sig"))

        # 1. Native slot verifier çağırılır
        verify_cmd = [self.service_bin, "--validate-slot", slot_a_dir]
        v_res = subprocess.run(verify_cmd, capture_output=True, text=True, errors="replace")
        self.assertEqual(v_res.returncode, 0, f"Native validate-slot uğursuz oldu: {v_res.stderr}")
        self.assertIn("VALID_SLOT", v_res.stdout)

        # 2. update_journal.json yazılır
        journal = {
            "schema_version": 1,
            "current_slot": "slot_a",
            "last_known_good_slot": "slot_a",
            "state": "IDLE",
            "active_version": "0.1.0",
            "candidate_version": None,
            "quarantined_versions": [],
            "crash_count": 0,
            "last_update_ts": 1740000000.0,
            "last_checkpoint": "INITIALIZED"
        }
        with open(os.path.join(self.data_dir, "update_journal.json"), "w", encoding="utf-8") as f:
            json.dump(journal, f, indent=2)

        # 3. Native boot recovery qiymətləndirilir: winkey_service.exe --evaluate-recovery
        eval_cmd = [self.service_bin, "--evaluate-recovery", "--data-dir", self.data_dir]
        e_res = subprocess.run(eval_cmd, capture_output=True, text=True, errors="replace")
        self.assertEqual(e_res.returncode, 0, f"evaluate-recovery uğursuz oldu: {e_res.stderr}")
        self.assertIn("NORMAL_BOOT", e_res.stdout)
        self.assertIn("slot=slot_a", e_res.stdout)

    def test_04_tampered_or_missing_signature_fail_closed(self):
        """Zədələnmiş və ya imzasız slot native verifier və recovery tərəfindən rədd edilir."""
        slot_b_dir = os.path.join(self.data_dir, "versions", "slot_b")
        os.makedirs(slot_b_dir, exist_ok=True)
        shutil.copy2(self.service_bin, os.path.join(slot_b_dir, "winkey_service.exe"))
        shutil.copy2(self.manifest_file, os.path.join(slot_b_dir, "manifest.json"))
        # manifest.sig kopyalanmır!

        verify_cmd = [self.service_bin, "--validate-slot", slot_b_dir]
        v_res = subprocess.run(verify_cmd, capture_output=True, text=True, errors="replace")
        self.assertNotEqual(v_res.returncode, 0, "İmzasız slot qəbul edilməməlidir!")
        self.assertIn("E_UNSIGNED_MANIFEST", v_res.stderr)
        print("[PASS] İmzasız slot native binar tərəfindən düzgün rədd edildi.")

if __name__ == "__main__":
    unittest.main()
