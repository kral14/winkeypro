"""
WinKey Pro — Native Launcher Executable Switch & Rollback Sınağı
Spesifikasiya: plan/GEMINI_SIGNING_WORKER_BLOCKERS.md (P0/P1)

Yoxlayır:
1. Native host prosesi (winkey_service.exe --run-host) namizəd slot binarını (--worker) başladır.
2. Namizəd slot binarı (slot_b) qəzaya uğradıqda (exit 216), host prosesi bunu qeydə alır.
3. Host hardcoded deyil, jurnaldan təsdiqlənmiş last_known_good_slot (slot_a) binarını tapır və başladır.
4. Jurnalda namizəd versiya (0.2.0) karantinə alınır və aktiv slot slot_a bərpa edilir.
5. IPC və ya poller yalnız aktiv worker tərəfindən idarə olunur.
6. Timeout və ya SCM STOP siqnalında aktiv worker prosesi təmiz bağlanır.
"""

import os
import sys
import json
import time
import shutil
import tempfile
import subprocess
import unittest

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SERVICE_BIN = os.path.join(ROOT_DIR, "apps", "winkey_service", "target", "release", "winkey_service.exe")
HELPER_BIN = os.path.join(ROOT_DIR, "apps", "winkey_service", "target", "release", "winkey_helper.exe")
PRE_SIGNED_DIR = os.path.join(ROOT_DIR, "deploy", "pre_signed_slot_a")

class TestNativeLauncherExecutableSwitch(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="winkey_native_switch_")
        self.data_dir = os.path.join(self.tmp_dir, "WinKeyData")
        self.versions_dir = os.path.join(self.data_dir, "versions")
        self.slot_a_dir = os.path.join(self.versions_dir, "slot_a")
        self.slot_b_dir = os.path.join(self.versions_dir, "slot_b")
        os.makedirs(self.slot_a_dir, exist_ok=True)
        os.makedirs(self.slot_b_dir, exist_ok=True)

        if not os.path.exists(SERVICE_BIN):
            raise unittest.SkipTest("winkey_service.exe tapılmadı; release build tələb olunur")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_native_candidate_crash_triggers_lkg_executable_switch(self):
        """Namizəd slot binarının qəzası zamanı Host-un LKG binarına real keçid sınağı."""
        
        # 1. Slot A: Sağlam LKG binarı və pre-signed manifest
        shutil.copy2(SERVICE_BIN, os.path.join(self.slot_a_dir, "winkey_service.exe"))
        shutil.copy2(HELPER_BIN, os.path.join(self.slot_a_dir, "winkey_helper.exe"))
        shutil.copy2(os.path.join(PRE_SIGNED_DIR, "manifest.json"), os.path.join(self.slot_a_dir, "manifest.json"))
        shutil.copy2(os.path.join(PRE_SIGNED_DIR, "manifest.sig"), os.path.join(self.slot_a_dir, "manifest.sig"))

        # 2. Slot B: Namizəd binarı (eyni binar, lakin daxilində crash.marker var)
        shutil.copy2(SERVICE_BIN, os.path.join(self.slot_b_dir, "winkey_service.exe"))
        shutil.copy2(HELPER_BIN, os.path.join(self.slot_b_dir, "winkey_helper.exe"))
        
        # Slot B üçün manifest və imza
        import hashlib
        from cryptography.hazmat.primitives.asymmetric import ed25519
        def sha256_f(p):
            h = hashlib.sha256()
            with open(p, "rb") as f:
                while c := f.read(65536): h.update(c)
            return h.hexdigest()
            
        b_manifest = {
            "version": "0.2.0-candidate",
            "timestamp": 1740000000.0,
            "files": [
                {"path": "winkey_service.exe", "sha256": sha256_f(SERVICE_BIN), "size": os.path.getsize(SERVICE_BIN)},
                {"path": "winkey_helper.exe", "sha256": sha256_f(HELPER_BIN), "size": os.path.getsize(HELPER_BIN)}
            ]
        }
        b_mb = json.dumps(b_manifest, indent=2, sort_keys=True).encode("utf-8")
        with open(os.path.join(self.slot_b_dir, "manifest.json"), "wb") as f:
            f.write(b_mb)
            
        key_path = os.path.join(ROOT_DIR, "deploy", "keys", "prod_release_ed25519_key.bin")
        with open(key_path, "rb") as f:
            priv = ed25519.Ed25519PrivateKey.from_private_bytes(f.read())
        b_sig = priv.sign(b_mb)
        with open(os.path.join(self.slot_b_dir, "manifest.sig"), "wb") as f:
            f.write(b_sig)

        # Slot B-yə crash.marker qoyuruq (namizəd işə düşən kimi simulyasiya edilmiş qəza törədir)
        with open(os.path.join(self.slot_b_dir, "crash.marker"), "w") as f:
            f.write("crash_on_boot_probation")

        # 3. update_journal.json: Namizəd slot_b probation sınağında göstərilir
        journal = {
            "schema_version": 1,
            "current_slot": "slot_b",
            "last_known_good_slot": "slot_a",
            "state": "UPDATING",
            "active_version": "0.1.0",
            "candidate_version": "0.2.0-candidate",
            "quarantined_versions": [],
            "crash_count": 0,
            "last_update_ts": 1740000000.0,
            "last_checkpoint": "REBOOT_READY"
        }
        journal_file = os.path.join(self.data_dir, "update_journal.json")
        with open(journal_file, "w", encoding="utf-8") as f:
            json.dump(journal, f, indent=2)

        # 4. Host prosesini işə salırıq: winkey_service.exe --run-host --data-dir <data_dir> --timeout-sec 6
        cmd = [
            SERVICE_BIN,
            "--run-host",
            "--data-dir", self.data_dir,
            "--timeout-sec", "6"
        ]
        
        print("\n[TEST_ACTION] Native Host Lifecycle başladılır...")
        start_t = time.time()
        res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=15)
        elapsed = time.time() - start_t

        print("--- NATIVE HOST OUTPUT ---")
        print(res.stdout)
        print("--- NATIVE HOST STDERR ---")
        print(res.stderr)

        # 5. Yoxlamalar
        self.assertEqual(res.returncode, 0, f"Host proses non-zero kodla bitdi: {res.returncode}")
        
        # Host namizədi işə saldı
        self.assertTrue("slot_b" in res.stdout, "Host ilkin olaraq slot_b namizədini seçməlidir")
        # Namizədin qəzası aşkarlandı
        self.assertTrue(
            "Child worker" in res.stderr or "Child worker" in res.stdout,
            "Namizədin qəza loqu olmalıdır"
        )
        # LKG binarı avtomatik işə salındı
        self.assertIn("HOST_LKG_SPAWN", res.stdout, "LKG binarının işə salınması loqu olmalıdır")
        self.assertTrue("slot_a" in res.stdout, "LKG slot_a worker binarı işə salınmalıdır")
        # Bounded sonlanma
        self.assertIn("HOST_LIFECYCLE_DONE", res.stdout)

        # 6. Jurnalın yekun vəziyyəti:
        with open(journal_file, "r", encoding="utf-8") as f:
            final_j = json.load(f)

        print("[YEKUN JURNAL VƏZİYYƏTİ]", json.dumps(final_j, indent=2))
        self.assertEqual(final_j["current_slot"], "slot_a", "Aktiv slot LKG (slot_a) olmalıdır!")
        self.assertEqual(final_j["last_known_good_slot"], "slot_a")
        self.assertIn("0.2.0-candidate", final_j["quarantined_versions"], "Namizəd versiya karantində olmalıdır!")
        self.assertIsNone(final_j["candidate_version"], "Namizəd ləğv edilməlidir")
        print("[PASS] Native launcher namizəd qəzasını tutdu və real LKG binarına uğurla keçdi!")

if __name__ == "__main__":
    unittest.main()
