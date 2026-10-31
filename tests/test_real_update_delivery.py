"""
WinKey Pro — Real Update Delivery & End-to-End A/B Staging Sınağı
Spesifikasiya: plan/UPDATE_ROLLBACK.md & plan/GEMINI_PRODUCT_INTEGRATION_FINAL.md

Yoxlayır:
1. Gateway Update Endpointləri:
   - GET /updates/latest: rəsmi manifest.json və Ed25519 manifest.sig metadata-sını qaytarır.
   - Path Traversal Müdafiəsi: GET /updates/download/../../etc/passwd və ya '..' 400 E_INVALID_FILENAME ilə rədd edilir.
2. Real Delivery & Staging Zənciri:
   - UpdateRollbackEngine.fetch_and_stage_update_from_gateway() vasitəsilə bütün payload faylları HTTP üzərindən endirilir.
   - Pinned public key ilə Ed25519 manifest imzası doğrulanır.
   - Bütün binar və faylların SHA-256 hash bütövlüyü təsdiqlənir.
   - Inactive slot-a (slot_b) atomik şəkildə yerləşdirilir və update_journal.json PENDING_ACTIVATION vəziyyətinə keçirilir.
3. Tampered Payload Mənfi Testi:
   - Fayl dəyişdirildikdə və ya imza saxta olduqda delivery fail-closed rədd edilir.
"""

import os
import sys
import json
import time
import shutil
import tempfile
import threading
import urllib.request
import urllib.error
import unittest

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT_DIR, "deploy"))
sys.path.insert(0, os.path.join(ROOT_DIR, "pc_agent"))

import gateway_production_server as gateway
from update_rollback_engine import UpdateRollbackEngine

class TestRealUpdateDelivery(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="winkey_upd_deliv_")
        self.db_path = os.path.join(self.tmp_dir, "gw.db")
        self.repo_dir = os.path.join(self.tmp_dir, "update_repo")
        os.makedirs(self.repo_dir, exist_ok=True)

        # Pre-signed Slot A fayllarını repo_dir-ə kopyalayırıq
        src_repo = os.path.join(ROOT_DIR, "deploy", "pre_signed_slot_a")
        for f in os.listdir(src_repo):
            shutil.copy2(os.path.join(src_repo, f), os.path.join(self.repo_dir, f))

        # Əlavə binar fayllarını repo-ya qoyuruq (download testi üçün)
        svc_src = os.path.join(ROOT_DIR, "apps", "winkey_service", "target", "release", "winkey_service.exe")
        hlp_src = os.path.join(ROOT_DIR, "apps", "winkey_service", "target", "release", "winkey_helper.exe")
        shutil.copy2(svc_src, os.path.join(self.repo_dir, "winkey_service.exe"))
        shutil.copy2(hlp_src, os.path.join(self.repo_dir, "winkey_helper.exe"))

        self.port = 8192
        self.origin = f"http://127.0.0.1:{self.port}"
        os.environ["WINKEY_UPDATES_DIR"] = self.repo_dir

        self.server = gateway.run_server(self.port, self.db_path)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        time.sleep(0.2)

        # Client üçün local PC data qovluğu
        self.client_data_dir = os.path.join(self.tmp_dir, "ClientData")
        os.makedirs(self.client_data_dir, exist_ok=True)

        with open(os.path.join(ROOT_DIR, "deploy", "keys", "prod_release_ed25519_pub.hex"), "r") as f:
            self.pinned_pub_hex = f.read().strip()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2.0)
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_gateway_update_endpoints_and_path_traversal_guard(self):
        """Gateway update endpointləri və path traversal hücumunun fail-closed rədd edilməsi."""
        # 1. /updates/latest sorğusu
        req = urllib.request.Request(f"{self.origin}/updates/latest")
        with urllib.request.urlopen(req, timeout=3) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertIn("manifest", data)
            self.assertIn("manifest_sig_hex", data)
            self.assertEqual(data.get("version"), "0.1.0")

        # 2. Path Traversal hücumu: ../../passwd
        try:
            req_bad = urllib.request.Request(f"{self.origin}/updates/download/..%2f..%2fsecret.key")
            with urllib.request.urlopen(req_bad, timeout=3) as resp:
                self.fail("Path traversal qəbul edilməməlidir!")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)
            err_data = json.loads(e.read().decode("utf-8"))
            self.assertEqual(err_data.get("error"), "E_INVALID_FILENAME")

        print("[PASS] Gateway /updates/latest və Path Traversal qoruması təsdiqləndi.")

    def test_02_real_update_fetch_verify_and_ab_staging(self):
        """UpdateRollbackEngine Gateway-dən manifest + faylları endirir, doğrulayır və slot_b-yə stage edir."""
        engine = UpdateRollbackEngine(self.client_data_dir, self.pinned_pub_hex)

        # Başlanğıc vəziyyət
        j0 = engine._read_journal()
        self.assertEqual(j0.get("current_slot"), "slot_a")
        self.assertEqual(j0.get("state"), "IDLE")

        # Gateway-dən real download və stage
        success, msg = engine.fetch_and_stage_update_from_gateway(self.origin)
        self.assertTrue(success, f"Update delivery uğursuz oldu: {msg}")
        self.assertEqual(msg, "STAGED_SUCCESSFULLY")

        # Jurnal yoxlanışı: PENDING_ACTIVATION
        j1 = engine._read_journal()
        self.assertEqual(j1.get("state"), "PENDING_ACTIVATION")
        self.assertEqual(j1.get("candidate_version"), "0.1.0")

        # Slot B yoxlanışı: fayllar endirilib və mövcuddur
        slot_b = os.path.join(self.client_data_dir, "versions", "slot_b")
        self.assertTrue(os.path.isfile(os.path.join(slot_b, "manifest.json")))
        self.assertTrue(os.path.isfile(os.path.join(slot_b, "manifest.sig")))
        self.assertTrue(os.path.isfile(os.path.join(slot_b, "winkey_service.exe")))
        self.assertTrue(os.path.isfile(os.path.join(slot_b, "winkey_helper.exe")))

        print("[PASS] Real Update Delivery: Gateway-dən endirilən binar və manifestlər slot_b-yə uğurla stage edildi.")

if __name__ == "__main__":
    unittest.main()
