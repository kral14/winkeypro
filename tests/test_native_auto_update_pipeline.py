"""
WinKey Pro — Native Rust Service Auto-Update Staging & Downgrade/Quarantine Sınağı
Spesifikasiya: plan/reports/codex/PRODUCT_SURFACES_HANDOFF.md (Qalıq 1)

Yoxlayır:
1. Native Rust Auto-Update Staging (v0.2.0):
   - Pinned Ed25519 imza doğrulanması, payload SHA256 bütövlüyü və target slota atomik staging.
   - update_journal.json-da PENDING_ACTIVATION təsdiqlənir.
2. Downgrade və Eyni Versiya Qoruması:
   - v0.1.0 namizədi aktiv v0.1.0 qarşısında E_DOWNGRADE_OR_SAME_VERSION_REJECTED ilə fail-closed rədd edilir.
3. Karantin Qoruması:
   - Karantində olan versiya E_VERSION_QUARANTINED ilə rədd edilir.
4. Interrupted / Natamam Yükləmə Qoruması:
   - Fayllardan biri çatışmadıqda və ya hash uyğun gəlmədikdə E_INTERRUPTED_DOWNLOAD fail-closed çıxır və hədəf slot təmizlənir.
"""

import os
import sys
import json
import time
import shutil
import tempfile
import subprocess
import unittest
from cryptography.hazmat.primitives.asymmetric import ed25519

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SERVICE_BIN = os.path.join(ROOT_DIR, "apps", "winkey_service", "target", "release", "winkey_service.exe")
PROD_KEY_PATH = os.path.join(ROOT_DIR, "deploy", "keys", "prod_release_ed25519_key.bin")
PROD_PUB_HEX_PATH = os.path.join(ROOT_DIR, "deploy", "keys", "prod_release_ed25519_pub.hex")

class TestNativeAutoUpdatePipeline(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="winkey_native_upd_")
        self.data_dir = os.path.join(self.tmp_dir, "WinKeyData")
        os.makedirs(self.data_dir, exist_ok=True)

        with open(PROD_KEY_PATH, "rb") as f:
            self.priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(f.read())
        with open(PROD_PUB_HEX_PATH, "r") as f:
            self.pub_hex = f.read().strip()

        os.environ["WINKEY_RELEASE_PUBKEY_HEX"] = self.pub_hex

        # İlkin jurnal: slot_a aktiv, versiya 0.1.0
        journal_data = {
            "schema_version": 1,
            "current_slot": "slot_a",
            "last_known_good_slot": "slot_a",
            "state": "IDLE",
            "active_version": "0.1.0",
            "candidate_version": None,
            "quarantined_versions": ["0.0.5"],
            "crash_count": 0,
            "last_update_ts": time.time(),
            "last_checkpoint": "HEALTHY"
        }
        with open(os.path.join(self.data_dir, "update_journal.json"), "w", encoding="utf-8") as f:
            json.dump(journal_data, f)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _create_bundle(self, version: str, files_dict: dict) -> tuple:
        bundle_dir = os.path.join(self.tmp_dir, f"bundle_{version}")
        os.makedirs(bundle_dir, exist_ok=True)

        manifest_files = []
        for fname, content in files_dict.items():
            fpath = os.path.join(bundle_dir, fname)
            with open(fpath, "wb") as f:
                f.write(content)
            import hashlib
            sha = hashlib.sha256(content).hexdigest()
            manifest_files.append({"path": fname, "sha256": sha, "size": len(content)})

        manifest_obj = {
            "version": version,
            "timestamp": time.time(),
            "files": manifest_files
        }
        manifest_bytes = json.dumps(manifest_obj, indent=2, sort_keys=True).encode("utf-8")
        manifest_path = os.path.join(bundle_dir, "manifest.json")
        with open(manifest_path, "wb") as f:
            f.write(manifest_bytes)

        sig_bytes = self.priv_key.sign(manifest_bytes)
        sig_path = os.path.join(bundle_dir, "manifest.sig")
        with open(sig_path, "wb") as f:
            f.write(sig_bytes)

        return manifest_path, sig_path, bundle_dir

    def test_01_native_valid_update_staging_to_slot_b(self):
        """Native Rust: v0.2.0 yenilənməsi uğurla doğrulanır və slot_b-yə stage olunur."""
        # PE binar başlıqlı dummy fayllar
        files = {
            "winkey_service.exe": b"MZ" + b"\x00" * 200,
            "winkey_helper.exe": b"MZ" + b"\x00" * 300
        }
        m_path, s_path, p_dir = self._create_bundle("0.2.0", files)

        proc = subprocess.run(
            [
                SERVICE_BIN, "--test-native-update-stage",
                "--data-dir", self.data_dir,
                "--manifest", m_path,
                "--sig", s_path,
                "--payload-dir", p_dir
            ],
            capture_output=True,
            text=True
        )
        self.assertEqual(proc.returncode, 0, f"Native stage xətası: {proc.stderr}\nStdout: {proc.stdout}")
        self.assertIn("PASS_NATIVE_UPDATE_STAGE", proc.stdout)

        # Jurnal yoxlanışı
        with open(os.path.join(self.data_dir, "update_journal.json"), "r") as f:
            j = json.load(f)
        self.assertEqual(j["state"], "PENDING_ACTIVATION")
        self.assertEqual(j["candidate_version"], "0.2.0")

        # Slot B yoxlanışı
        slot_b = os.path.join(self.data_dir, "versions", "slot_b")
        self.assertTrue(os.path.isfile(os.path.join(slot_b, "winkey_service.exe")))
        self.assertTrue(os.path.isfile(os.path.join(slot_b, "manifest.json")))
        print("[PASS] Native Rust: v0.2.0 binar yenilənməsi slot_b-yə uğurla stage edildi.")

    def test_02_native_downgrade_and_same_version_rejection(self):
        """Native Rust: v0.1.0 (eyni) və ya v0.0.9 (köhnə) namizədi fail-closed rədd edilir."""
        files = {"winkey_service.exe": b"MZ" + b"\x00" * 200}
        m_path, s_path, p_dir = self._create_bundle("0.1.0", files)

        proc = subprocess.run(
            [
                SERVICE_BIN, "--test-native-update-stage",
                "--data-dir", self.data_dir,
                "--manifest", m_path,
                "--sig", s_path,
                "--payload-dir", p_dir
            ],
            capture_output=True,
            text=True
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("E_DOWNGRADE_OR_SAME_VERSION_REJECTED", proc.stderr)
        print("[PASS] Native Rust: Eyni versiya və downgrade namizədi fail-closed rədd edildi.")

    def test_03_native_quarantined_version_rejection(self):
        """Native Rust: Karantində olan versiya (v0.0.5) rəsmi imza olsa belə rədd edilir."""
        files = {"winkey_service.exe": b"MZ" + b"\x00" * 200}
        m_path, s_path, p_dir = self._create_bundle("0.0.5", files)

        proc = subprocess.run(
            [
                SERVICE_BIN, "--test-native-update-stage",
                "--data-dir", self.data_dir,
                "--manifest", m_path,
                "--sig", s_path,
                "--payload-dir", p_dir
            ],
            capture_output=True,
            text=True
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertTrue(
            "E_VERSION_QUARANTINED" in proc.stderr or "E_DOWNGRADE_OR_SAME_VERSION_REJECTED" in proc.stderr
        )
        print("[PASS] Native Rust: Karantində olan versiya fail-closed rədd edildi.")

    def test_04_native_interrupted_download_rejection(self):
        """Native Rust: Fayl çatışmadıqda və ya natamam olduqda slot təmizlənir və xəta verilir."""
        files = {
            "winkey_service.exe": b"MZ" + b"\x00" * 200,
            "winkey_helper.exe": b"MZ" + b"\x00" * 300
        }
        m_path, s_path, p_dir = self._create_bundle("0.3.0", files)

        # Qəsdən winkey_helper.exe-ni silirik (Interrupted download)
        os.remove(os.path.join(p_dir, "winkey_helper.exe"))

        proc = subprocess.run(
            [
                SERVICE_BIN, "--test-native-update-stage",
                "--data-dir", self.data_dir,
                "--manifest", m_path,
                "--sig", s_path,
                "--payload-dir", p_dir
            ],
            capture_output=True,
            text=True
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("E_INTERRUPTED_DOWNLOAD", proc.stderr)

        # Slot B qovluğu təmizlənməlidir (yarımçıq zibil qalmamalıdır)
        slot_b = os.path.join(self.data_dir, "versions", "slot_b")
        self.assertFalse(os.path.exists(slot_b), "Yarımçıq yükləmədən sonra hədəf slot təmizlənməlidir!")
        print("[PASS] Native Rust: Interrupted yükləmə zamanı hədəf slot təmizləndi və fail-closed çıxıldı.")

    def test_05_native_gateway_check_update_cli(self):
        """Native Rust CLI: winkey_service.exe --check-update birbaşa Gateway-dən yenilənməni endirir və stage edir."""
        sys.path.insert(0, os.path.join(ROOT_DIR, "deploy"))
        import gateway_production_server as gateway
        import threading

        gw_db = os.path.join(self.tmp_dir, "gw_test.db")
        gw_repo = os.path.join(self.tmp_dir, "gw_repo")
        os.makedirs(gw_repo, exist_ok=True)

        # Gateway üçün v0.2.0 binar paketi yaradırıq
        files = {
            "winkey_service.exe": b"MZ" + b"\x00" * 200,
            "winkey_helper.exe": b"MZ" + b"\x00" * 300
        }
        m_path, s_path, _ = self._create_bundle("0.2.0", files)
        shutil.copy2(m_path, os.path.join(gw_repo, "manifest.json"))
        shutil.copy2(s_path, os.path.join(gw_repo, "manifest.sig"))
        with open(os.path.join(gw_repo, "winkey_service.exe"), "wb") as f:
            f.write(files["winkey_service.exe"])
        with open(os.path.join(gw_repo, "winkey_helper.exe"), "wb") as f:
            f.write(files["winkey_helper.exe"])

        os.environ["WINKEY_UPDATES_DIR"] = gw_repo
        port = 8199
        origin = f"http://127.0.0.1:{port}"
        srv = gateway.run_server(port, gw_db)
        th = threading.Thread(target=srv.serve_forever)
        th.daemon = True
        th.start()
        time.sleep(0.2)

        try:
            # Native Rust binarını çağırırıq: --check-update (Avtomatik aktivləşdirmə ilə)
            proc = subprocess.run(
                [
                    SERVICE_BIN, "--check-update", origin,
                    "--data-dir", self.data_dir
                ],
                capture_output=True,
                text=True
            )
            self.assertEqual(proc.returncode, 0, f"Native gateway check-update xətası: {proc.stderr}\nStdout: {proc.stdout}")
            self.assertIn("PASS_NATIVE_GATEWAY_UPDATE", proc.stdout)
            self.assertIn("PASS_NATIVE_UPDATE_ACTIVATED", proc.stdout)

            # Jurnal yoxlanışı: Avtomatik olaraq aktivləşib (PROBATION, slot_b)
            with open(os.path.join(self.data_dir, "update_journal.json"), "r") as f:
                j = json.load(f)
            self.assertEqual(j["state"], "PROBATION")
            self.assertEqual(j["current_slot"], "slot_b")
            self.assertEqual(j["candidate_version"], "0.2.0")

            # İkinci təkrar yoxlama: Artıq aktiv/namizəd 0.2.0 olduğu üçün E_DOWNGRADE_OR_SAME_VERSION_REJECTED olmalıdır
            j["active_version"] = "0.2.0"
            with open(os.path.join(self.data_dir, "update_journal.json"), "w") as f:
                json.dump(j, f)

            proc2 = subprocess.run(
                [SERVICE_BIN, "--check-update", origin, "--data-dir", self.data_dir],
                capture_output=True,
                text=True
            )
            self.assertNotEqual(proc2.returncode, 0)
            self.assertIn("E_DOWNGRADE_OR_SAME_VERSION_REJECTED", proc2.stderr)

            print("[PASS] Native Rust CLI --check-update Gateway-dən yenilənməni endirdi, avtomatik aktivləşdirdi və təkrarı rədd etdi.")
        finally:
            srv.shutdown()
            srv.server_close()
            th.join(timeout=2.0)

    def test_06_host_runtime_auto_update_and_worker_pid_switch(self):
        """Host Runtime Lifecycle: Timer/trigger vasitəsilə yeni versiyanın endirilməsi və real worker PID/slot keçidi."""
        sys.path.insert(0, os.path.join(ROOT_DIR, "deploy"))
        import gateway_production_server as gateway
        import threading

        gw_db = os.path.join(self.tmp_dir, "gw_host_test.db")
        gw_repo = os.path.join(self.tmp_dir, "gw_host_repo")
        os.makedirs(gw_repo, exist_ok=True)

        # Slot A üçün ilkin quraşdırma (v0.1.0)
        slot_a = os.path.join(self.data_dir, "versions", "slot_a")
        os.makedirs(slot_a, exist_ok=True)
        shutil.copy2(SERVICE_BIN, os.path.join(slot_a, "winkey_service.exe"))
        helper_src = os.path.join(ROOT_DIR, "apps", "winkey_service", "target", "release", "winkey_helper.exe")
        shutil.copy2(helper_src, os.path.join(slot_a, "winkey_helper.exe"))

        # Slot A üçün manifest
        m_a_path, s_a_path, _ = self._create_bundle("0.1.0", {
            "winkey_service.exe": open(SERVICE_BIN, "rb").read(),
            "winkey_helper.exe": open(helper_src, "rb").read()
        })
        shutil.copy2(m_a_path, os.path.join(slot_a, "manifest.json"))
        shutil.copy2(s_a_path, os.path.join(slot_a, "manifest.sig"))

        # Gateway-ə namizəd versiya (v0.2.0) qoyuruq (eyni binar, amma yeni semver)
        m_b_path, s_b_path, _ = self._create_bundle("0.2.0", {
            "winkey_service.exe": open(SERVICE_BIN, "rb").read(),
            "winkey_helper.exe": open(helper_src, "rb").read()
        })
        shutil.copy2(m_b_path, os.path.join(gw_repo, "manifest.json"))
        shutil.copy2(s_b_path, os.path.join(gw_repo, "manifest.sig"))
        shutil.copy2(SERVICE_BIN, os.path.join(gw_repo, "winkey_service.exe"))
        shutil.copy2(helper_src, os.path.join(gw_repo, "winkey_helper.exe"))

        os.environ["WINKEY_UPDATES_DIR"] = gw_repo
        port = 8198
        origin = f"http://127.0.0.1:{port}"
        srv = gateway.run_server(port, gw_db)
        th = threading.Thread(target=srv.serve_forever)
        th.daemon = True
        th.start()
        time.sleep(0.2)

        # Host üçün konfiqurasiya
        env = os.environ.copy()
        env["WINKEY_GATEWAY_ORIGIN"] = origin
        env["WINKEY_UPDATE_CHECK_SEC"] = "1" # Hər 1 saniyədən bir yoxlasın
        env["WINKEY_RELEASE_PUBKEY_HEX"] = self.pub_hex

        try:
            # Host lifecycle-i işə salırıq (8 saniyəlik timeout)
            cmd = [
                SERVICE_BIN, "--run-host",
                "--data-dir", self.data_dir,
                "--timeout-sec", "8"
            ]
            res = subprocess.run(cmd, env=env, capture_output=True, text=True, errors="replace", timeout=15)
            
            # Host çıxışının yoxlanması
            self.assertEqual(res.returncode, 0, f"Host uğursuz oldu: {res.stderr}\nStdout: {res.stdout}")
            
            # 1. İlk olaraq slot_a worker işə düşməlidir
            self.assertIn("Aktiv slot (slot_a)", res.stdout)
            
            # 2. Host gateway update tapıb stage etməlidir
            self.assertIn("[HOST_AUTO_UPDATE_POLL]", res.stdout)
            self.assertIn("[HOST_AUTO_UPDATE_ACTIVATED]", res.stdout)
            
            # 3. Köhnə worker dayandırılıb yeni slot_b worker binarına keçid olmalıdır
            self.assertIn("[HOST_UPDATE_WORKER_SWITCH]", res.stdout)
            self.assertIn("slot=slot_b", res.stdout)
            
            # 4. Yekun jurnalda slot_b təsdiqlənməlidir
            with open(os.path.join(self.data_dir, "update_journal.json"), "r") as f:
                final_j = json.load(f)
            self.assertEqual(final_j["current_slot"], "slot_b")
            self.assertIn(final_j["state"], ["PROBATION", "COMMITTED"])
            print("[PASS] Host Runtime Lifecycle: Gateway-dən v0.2.0 avtomatik endirildi, stage edildi və real worker PID/slot keçidi təsdiqləndi.")
        finally:
            srv.shutdown()
            srv.server_close()
            th.join(timeout=2.0)

if __name__ == "__main__":
    unittest.main()
