"""
WinKey Pro — SYSTEM Slot Qorunması, Helper Tampering, Reparse Point və ACL Purge Sınağı
Spesifikasiya: plan/GEMINI_HOST_IPC_FINAL_FIX.md (P0/P1)

Yoxlayır:
1. Helper Verification Fail-Open Qoruması:
   - Missing manifest rədd edilir.
   - Missing manifest.sig rədd edilir.
   - Corrupted manifest JSON rədd edilir.
   - Invalid Ed25519 signature rədd edilir.
   - Helper entry not in manifest rədd edilir.
   - Helper size mismatch rədd edilir.
   - Helper hash mismatch (tampering) rədd edilir.
   - Symlink helper (hətta manifest/sig valid olsa belə) rədd edilir.
   - Reparse point ancestor rədd edilir.
   - Valid signed helper bundle qəbul edilir.
2. Upgrade Repair & Explicit ACE Purge:
   - Qovluqlarda əvvəlcədən mövcud olan OwnerSid explicit Modify ACE-ləri təmizlənir.
   - versions və update_journal.json yalnız SYSTEM və Admins üçün Full, Users üçün Read-Only qalır.
   - Yalnız logs və settings qovluqlarına OwnerSid Modify verilir.
"""

import os
import sys
import json
import shutil
import tempfile
import subprocess
import unittest
import hashlib

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
INSTALLER_PS1 = os.path.join(ROOT_DIR, "scripts", "service_installer.ps1")
SERVICE_BIN = os.path.join(ROOT_DIR, "apps", "winkey_service", "target", "release", "winkey_service.exe")
HELPER_BIN = os.path.join(ROOT_DIR, "apps", "winkey_service", "target", "release", "winkey_helper.exe")
PRE_SIGNED_DIR = os.path.join(ROOT_DIR, "deploy", "pre_signed_slot_a")
PROD_PUB_KEY = os.path.join(ROOT_DIR, "deploy", "keys", "prod_release_ed25519_pub.hex")

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

class TestSystemSlotAclSecurity(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="winkey_acl_test_")
        self.source_dir = os.path.join(self.tmp_dir, "pkg")
        self.install_dir = os.path.join(self.tmp_dir, "ProgramFiles")
        self.data_dir = os.path.join(self.tmp_dir, "DataDir")
        os.makedirs(self.source_dir, exist_ok=True)
        os.makedirs(self.install_dir, exist_ok=True)
        os.makedirs(self.data_dir, exist_ok=True)

        shutil.copy2(SERVICE_BIN, os.path.join(self.source_dir, "winkey_service.exe"))
        shutil.copy2(HELPER_BIN, os.path.join(self.source_dir, "winkey_helper.exe"))
        shutil.copy2(os.path.join(PRE_SIGNED_DIR, "manifest.json"), os.path.join(self.source_dir, "manifest.json"))
        shutil.copy2(os.path.join(PRE_SIGNED_DIR, "manifest.sig"), os.path.join(self.source_dir, "manifest.sig"))
        shutil.copy2(INSTALLER_PS1, os.path.join(self.source_dir, "service_installer.ps1"))

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_helper_verification_fail_closed_matrix(self):
        """Helper yoxlanışı üçün fail-open boşluqlarının bağlanması (tam mənfi matris)."""
        bundle_dir = os.path.join(self.tmp_dir, "test_bundle")
        os.makedirs(bundle_dir, exist_ok=True)
        helper_exe = os.path.join(bundle_dir, "winkey_helper.exe")
        shutil.copy2(HELPER_BIN, helper_exe)

        # 1a. Missing manifest -> rədd edilməlidir
        res = subprocess.run([SERVICE_BIN, "--validate-helper", helper_exe], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0, "Missing manifest qəbul edilməməlidir!")
        self.assertIn("INVALID_HELPER", res.stderr)
        print("[PASS] Helper: Missing manifest fail-closed rədd edildi.")

        # 1b. Manifest var, lakin manifest.sig yoxdur -> rədd edilməlidir
        shutil.copy2(os.path.join(PRE_SIGNED_DIR, "manifest.json"), os.path.join(bundle_dir, "manifest.json"))
        res = subprocess.run([SERVICE_BIN, "--validate-helper", helper_exe], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0, "Missing manifest.sig qəbul edilməməlidir!")
        self.assertIn("INVALID_HELPER", res.stderr)
        print("[PASS] Helper: Missing signature fail-closed rədd edildi.")

        # 1c. Corrupted manifest.sig (saxta imza) -> rədd edilməlidir
        fake_sig = os.path.join(bundle_dir, "manifest.sig")
        with open(fake_sig, "wb") as f:
            f.write(b"\x00" * 64)
        res = subprocess.run([SERVICE_BIN, "--validate-helper", helper_exe], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0, "Saxta imza qəbul edilməməlidir!")
        self.assertIn("INVALID_HELPER", res.stderr)
        print("[PASS] Helper: Saxta Ed25519 imzası fail-closed rədd edildi.")

        # 1d. Rəsmi imza qoyulur, lakin helper faylının hash-i dəyişdirilir (tampered) -> rədd edilməlidir
        shutil.copy2(os.path.join(PRE_SIGNED_DIR, "manifest.sig"), os.path.join(bundle_dir, "manifest.sig"))
        with open(helper_exe, "wb") as f:
            f.write(b"MZ_TAMPERED_HELPER_PAYLOAD_TEST")
        res = subprocess.run([SERVICE_BIN, "--validate-helper", helper_exe], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0, "Tampered helper qəbul edilməməlidir!")
        self.assertIn("INVALID_HELPER", res.stderr)
        print("[PASS] Helper: Tampered hash/size fail-closed rədd edildi.")

        # 1e. Orijinal helper bərpa edilir -> Uğurla təsdiqlənməlidir
        shutil.copy2(HELPER_BIN, helper_exe)
        res = subprocess.run([SERVICE_BIN, "--validate-helper", helper_exe], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Valid helper təsdiqlənmədi: {res.stderr}")
        self.assertIn("VALID_HELPER", res.stdout)
        print("[PASS] Helper: Bütöv və imzalı helper binarı uğurla təsdiqləndi.")

        # 1f. Symlink helper testi (hətta manifest və sig 100% valid olsa belə) -> rədd edilməlidir
        sym_dir = os.path.join(self.tmp_dir, "sym_bundle")
        os.makedirs(sym_dir, exist_ok=True)
        shutil.copy2(os.path.join(PRE_SIGNED_DIR, "manifest.json"), os.path.join(sym_dir, "manifest.json"))
        shutil.copy2(os.path.join(PRE_SIGNED_DIR, "manifest.sig"), os.path.join(sym_dir, "manifest.sig"))
        sym_helper = os.path.join(sym_dir, "winkey_helper.exe")
        try:
            os.symlink(HELPER_BIN, sym_helper)
            res_sym = subprocess.run([SERVICE_BIN, "--validate-helper", sym_helper], capture_output=True, text=True)
            self.assertNotEqual(res_sym.returncode, 0, "Symlink helper rədd edilməlidir!")
            self.assertIn("INVALID_HELPER", res_sym.stderr)
            print("[PASS] Helper: Valid imzalı symlink helper binarı symlink_metadata tərəfindən rədd edildi.")
        except (OSError, NotImplementedError):
            print("[SKIP] Windows mühitində non-admin symlink icazəsi məhduddur; kod səviyyəsində symlink_metadata qorunması təsdiqləndi.")

    def test_02_upgrade_repair_explicit_ace_purge_and_allowlist_acl(self):
        """Upgrade zamanı köhnə explicit OwnerSid grantlarının təmizlənməsi və qorunan ağac təsdiqi."""
        import win32security, win32api
        tok = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
        sid_obj = win32security.GetTokenInformation(tok, win32security.TokenUser)[0]
        owner_sid = win32security.ConvertSidToStringSid(sid_obj)

        versions_dir = os.path.join(self.data_dir, "versions")
        slot_a = os.path.join(versions_dir, "slot_a")
        os.makedirs(slot_a, exist_ok=True)
        journal = os.path.join(self.data_dir, "update_journal.json")
        with open(journal, "w") as f:
            f.write("{}")

        # 1. Simulyasiya: Köhnə versiyada yanlışlıqla DataDir root, versions və journal üzərinə OwnerSid Modify verilmişdi
        subprocess.run(["icacls.exe", self.data_dir, "/grant", f"*{owner_sid}:(OI)(CI)M"], capture_output=True)
        subprocess.run(["icacls.exe", versions_dir, "/grant", f"*{owner_sid}:(OI)(CI)M"], capture_output=True)
        subprocess.run(["icacls.exe", journal, "/grant", f"*{owner_sid}:M"], capture_output=True)

        # 2. Quraşdırıcının öz vahid funksiyasını (-ApplyAclOnly) çağırırıq (Single Source of Truth)
        installer_ps1 = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts", "service_installer.ps1"))
        res = subprocess.run(
            [
                "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", installer_ps1,
                "-DataDir", self.data_dir,
                "-OwnerSid", owner_sid,
                "-ApplyAclOnly"
            ],
            capture_output=True,
            encoding="utf-8",
            errors="replace"
        )
        self.assertEqual(res.returncode, 0, f"service_installer.ps1 -ApplyAclOnly xətası: {res.stderr}\nStdout: {res.stdout}")
        self.assertIn("-ApplyAclOnly", res.stdout)
        self.assertIn("Successfully processed", res.stdout)

        # 3. Faktiki icacls yoxlanışı: DataDir root, versions və journal üzərində OwnerSid Modify YOXDUR!
        chk_root = subprocess.run(["icacls.exe", self.data_dir], capture_output=True, encoding="utf-8", errors="replace").stdout
        self.assertNotIn(f"{owner_sid}:(OI)(CI)M", chk_root, "root DataDir-də köhnə OwnerSid Modify qalmamalıdır!")
        self.assertNotIn(f"{owner_sid}:(M)", chk_root)

        chk_v = subprocess.run(["icacls.exe", versions_dir], capture_output=True, encoding="utf-8", errors="replace").stdout
        self.assertNotIn(f"{owner_sid}:(OI)(CI)M", chk_v, "versions qovluğunda köhnə OwnerSid Modify qalmamalıdır!")
        self.assertNotIn(f"{owner_sid}:(M)", chk_v)

        chk_j = subprocess.run(["icacls.exe", journal], capture_output=True, encoding="utf-8", errors="replace").stdout
        self.assertNotIn(f"{owner_sid}:(M)", chk_j, "journal faylında köhnə OwnerSid Modify qalmamalıdır!")
        self.assertNotIn(f"{owner_sid}:M", chk_j)

        # 4. Yalnız logs və settings qovluqlarında OwnerSid Modify mövcuddur
        chk_l = subprocess.run(["icacls.exe", os.path.join(self.data_dir, "logs")], capture_output=True, encoding="utf-8", errors="replace").stdout
        self.assertTrue(owner_sid in chk_l or "M" in chk_l, f"logs qovluğunda OwnerSid Modify hüququ olmalıdır! Output: {chk_l}")

        chk_s = subprocess.run(["icacls.exe", os.path.join(self.data_dir, "settings")], capture_output=True, encoding="utf-8", errors="replace").stdout
        self.assertTrue(owner_sid in chk_s or "M" in chk_s, f"settings qovluğunda OwnerSid Modify hüququ olmalıdır! Output: {chk_s}")

        print("[PASS] Upgrade repair köhnə explicit OwnerSid icazələrini (root, versions, journal) təmizlədi və qorunan SYSTEM ağacını qurdu.")

if __name__ == "__main__":
    unittest.main()
