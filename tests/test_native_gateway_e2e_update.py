from pathlib import Path
"""
WinKey Pro — Real Native Gateway Auto-Update E2E Integration Suite
Spesifikasiya: plan/GEMINI_AUTO_UPDATE_REVISION.md (Mərhələ 5 və 6)

Yoxlayır:
1. Real Local HTTP Server üzərindən Native Rust Service (winkey_service.exe) yüklənməsi və A/B slot staging.
2. Ed25519 Kriptoqrafik Pinned İmza doğrulanması və saxta açarın fail-closed rədd edilməsi.
3. SHA-256 və ölçü bütövlüyü: tampered/yarımçıq faylın fail-closed rədd edilməsi və hədəf slotun təmizlənməsi.
4. Downgrade və eyni versiya qoruması: aktiv versiyadan böyük olmayan paketlərin rədd edilməsi.
5. Host Protokol Uyğunluğu: min_host_protocol_version > 1 olduqda E_HOST_UPGRADE_REQUIRED çıxması.
6. Karantin Qoruması: karantində olan versiyanın rədd edilməsi.
7. İki ardıcıl A -> B -> A yenilənməsində hədəf slotun təmizlənməsi və file-lock yaranmaması.
8. Sınaq Müddəti (Probation) Qəzası və Avtomatik LKG Rollback: namizədin karantinə salınması və LKG-yə qayıdış.
"""

import os
import sys
import json
import time
import shutil
import hashlib
import tempfile
import threading
import subprocess
import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
debug_svc = os.path.join(ROOT_DIR, "apps", "winkey_service", "target", "debug", "winkey_service.exe")
release_svc = os.path.join(ROOT_DIR, "apps", "winkey_service", "target", "release", "winkey_service.exe")

if os.path.isfile(debug_svc) and os.path.isfile(release_svc):
    SERVICE_BIN = debug_svc if os.path.getmtime(debug_svc) > os.path.getmtime(release_svc) else release_svc
elif os.path.isfile(debug_svc):
    SERVICE_BIN = debug_svc
else:
    SERVICE_BIN = release_svc

class MockGatewayHandler(BaseHTTPRequestHandler):
    """Local disposable HTTP handler for update delivery."""

    def log_message(self, format, *args):
        pass  # Quiet test logging

    def do_GET(self):
        routes = self.server.routes
        clean_path = self.path.split("?")[0]
        if clean_path in routes:
            status, content_type, body = routes[clean_path]
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

class TestNativeGatewayE2EUpdate(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # 1. Generate disposable Ed25519 test keypair (NO private keys leaked or production keys touched)
        cls.signer = ed25519.Ed25519PrivateKey.generate()
        cls.pub_bytes = cls.signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        cls.pub_hex = cls.pub_bytes.hex()

        # 2. Start mock HTTP gateway on localhost with random port
        cls.http_server = HTTPServer(("127.0.0.1", 0), MockGatewayHandler)
        cls.port = cls.http_server.server_port
        cls.origin = f"http://127.0.0.1:{cls.port}"
        cls.http_server.routes = {}

        cls.server_thread = threading.Thread(target=cls.http_server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.http_server.shutdown()
        cls.http_server.server_close()
        cls.server_thread.join(timeout=2.0)

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="winkey_gw_e2e_")
        self.data_dir = os.path.join(self.tmp_dir, "WinKeyData")
        os.makedirs(self.data_dir, exist_ok=True)

        # Baseline: Slot A active, version 0.1.0, IDLE, valid LKG
        self.init_journal("slot_a", "0.1.0")
        self.populate_slot("slot_a", "0.1.0")

        # Subprocess env with test public key
        self.test_env = os.environ.copy()
        self.test_env["WINKEY_RELEASE_PUBKEY_HEX"] = self.pub_hex

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def init_journal(self, current_slot="slot_a", active_ver="0.1.0", quarantined=None):
        journal = {
            "schema_version": 1,
            "current_slot": current_slot,
            "last_known_good_slot": current_slot,
            "state": "IDLE",
            "active_version": active_ver,
            "candidate_version": None,
            "quarantined_versions": quarantined or [],
            "crash_count": 0,
            "last_update_ts": time.time(),
            "last_checkpoint": "HEALTHY"
        }
        with open(os.path.join(self.data_dir, "update_journal.json"), "w", encoding="utf-8") as f:
            json.dump(journal, f)

    def populate_slot(self, slot_name, version):
        slot_dir = os.path.join(self.data_dir, "versions", slot_name)
        os.makedirs(slot_dir, exist_ok=True)
        real_bin = Path(SERVICE_BIN).read_bytes()[:4096] if os.path.isfile(SERVICE_BIN) else (b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00" + b"\x00" * 1024)
        files = {
            "winkey_service.exe": real_bin,
            "winkey_helper.exe": real_bin[:2048],
            "winkey_desktop.exe": real_bin[:3072],
            "WebView2Loader.dll": real_bin[:1024],
        }
        files_meta = []
        for fname, content in files.items():
            fpath = os.path.join(slot_dir, fname)
            with open(fpath, "wb") as f:
                f.write(content)
            sha = hashlib.sha256(content).hexdigest()
            files_meta.append({"path": fname, "sha256": sha, "size": len(content)})

        manifest = {
            "version": version,
            "timestamp": time.time(),
            "min_host_protocol_version": 1,
            "files": files_meta
        }
        manifest_raw = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
        with open(os.path.join(slot_dir, "manifest.json"), "wb") as f:
            f.write(manifest_raw)

        sig_bytes = self.signer.sign(manifest_raw)
        with open(os.path.join(slot_dir, "manifest.sig"), "wb") as f:
            f.write(sig_bytes)

    def build_release_payload(self, version="0.2.0", files_dict=None, min_host_proto=1, tamper_file=None, custom_signer=None):
        if files_dict is None:
            real_bin = Path(SERVICE_BIN).read_bytes()[:4096] if os.path.isfile(SERVICE_BIN) else (b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00" + b"\x00" * 1024)
            files_dict = {
                "winkey_service.exe": real_bin,
                "winkey_helper.exe": real_bin[:2048],
                "winkey_desktop.exe": real_bin[:3072],
                "WebView2Loader.dll": real_bin[:1024],
            }

        files_meta = []
        routes = {}
        for fname, content in files_dict.items():
            sha = hashlib.sha256(content).hexdigest()
            files_meta.append({"path": fname, "sha256": sha, "size": len(content)})
            # If tampered, mutate last 4 bytes keeping exact same length (triggers hash mismatch)
            payload = (content[:-4] + b"CORR") if (tamper_file == fname) else content
            routes[f"/updates/download/{fname}"] = (200, "application/octet-stream", payload)

        manifest = {
            "version": version,
            "timestamp": time.time(),
            "min_host_protocol_version": min_host_proto,
            "files": files_meta
        }
        manifest_raw = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")

        signer = custom_signer or self.signer
        sig_bytes = signer.sign(manifest_raw)
        sig_hex = sig_bytes.hex()

        latest_resp = json.dumps({
            "version": version,
            "manifest": manifest,
            "manifest_raw": manifest_raw.decode("utf-8"),
            "manifest_sig_hex": sig_hex,
            "download_url_prefix": "/updates/download"
        }).encode("utf-8")

        routes["/updates/latest"] = (200, "application/json", latest_resp)
        return routes

    def test_01_e2e_valid_update_download_and_staging(self):
        """E2E Test 1: Real HTTP-dən imzalı v0.2.0 endirilməsi, Ed25519 doğrulanması və slot_b-yə staging."""
        self.http_server.routes = self.build_release_payload("0.2.0")

        res = subprocess.run(
            [SERVICE_BIN, "--check-update", self.origin, "--data-dir", self.data_dir, "--no-activate"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=self.test_env, timeout=10
        )
        self.assertEqual(res.returncode, 0, f"Xəta: {res.stderr}\n{res.stdout}")
        self.assertIn("PASS_NATIVE_GATEWAY_UPDATE", res.stdout)

        # Jurnal PENDING_ACTIVATION olmalıdır
        with open(os.path.join(self.data_dir, "update_journal.json"), "r") as f:
            j = json.load(f)
        self.assertEqual(j["state"], "PENDING_ACTIVATION")
        self.assertEqual(j["candidate_version"], "0.2.0")

        # Slot B faylları mövcud olmalıdır
        slot_b = os.path.join(self.data_dir, "versions", "slot_b")
        self.assertTrue(os.path.isfile(os.path.join(slot_b, "winkey_service.exe")))
        self.assertTrue(os.path.isfile(os.path.join(slot_b, "manifest.json")))
        print("[PASS] E2E 1: Real HTTP yükləməsi və Ed25519 təsdiqli slot_b staging uğurludur.")

    def test_02_e2e_downgrade_and_same_version_rejection(self):
        """E2E Test 2: Aktiv versiyadan (0.1.0) kiçik və ya bərabər versiyanın fail-closed rədd edilməsi."""
        # Aktiv versiya 0.1.0-dır, namizəd 0.1.0 təqdim olunur
        self.http_server.routes = self.build_release_payload("0.1.0")

        res = subprocess.run(
            [SERVICE_BIN, "--check-update", self.origin, "--data-dir", self.data_dir, "--no-activate"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=self.test_env, timeout=10
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("E_NO_NEWER_RELEASE", res.stderr + res.stdout)
        print("[PASS] E2E 2: Eyni/köhnə versiya (downgrade) fail-closed rədd edildi.")

    def test_03_e2e_corrupted_payload_fail_closed(self):
        """E2E Test 3: Şəbəkədən zədələnmiş binar gəldikdə bütövlük xətası ilə fail-closed rədd və təmizlənmə."""
        # winkey_desktop.exe faylı serverdə zədələnib
        self.http_server.routes = self.build_release_payload("0.2.0", tamper_file="winkey_desktop.exe")

        res = subprocess.run(
            [SERVICE_BIN, "--check-update", self.origin, "--data-dir", self.data_dir, "--no-activate"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=self.test_env, timeout=10
        )
        self.assertNotEqual(res.returncode, 0)
        out = res.stderr + res.stdout
        self.assertTrue("E_INTEGRITY_HASH_MISMATCH" in out or "E_INTERRUPTED_DOWNLOAD" in out)

        # Slot B təmizlənmiş olmalıdır (zədəli fayl qalmamalıdır)
        slot_b = os.path.join(self.data_dir, "versions", "slot_b")
        if os.path.isdir(slot_b):
            self.assertEqual(len(os.listdir(slot_b)), 0)
        print("[PASS] E2E 3: Hash uyğunsuzluğu dərhal fail-closed oldu və hədəf slot təmizləndi.")

    def test_04_e2e_untrusted_signature_rejection(self):
        """E2E Test 4: Saxta/fərqli açarla imzalanmış buraxılışın fayllar endirilmədən rədd edilməsi."""
        attacker_key = ed25519.Ed25519PrivateKey.generate()
        self.http_server.routes = self.build_release_payload("0.2.0", custom_signer=attacker_key)

        res = subprocess.run(
            [SERVICE_BIN, "--check-update", self.origin, "--data-dir", self.data_dir, "--no-activate"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=self.test_env, timeout=10
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("E_RELEASE_SIGNATURE", res.stderr + res.stdout)
        print("[PASS] E2E 4: Saxta Ed25519 imzası fayllar endirilməzdən əvvəl rədd edildi.")

    def test_05_e2e_incompatible_host_protocol_rejection(self):
        """E2E Test 5: min_host_protocol_version > 1 tələb edən buraxılışın E_HOST_UPGRADE_REQUIRED ilə rədd edilməsi."""
        self.http_server.routes = self.build_release_payload("0.2.0", min_host_proto=2)

        res = subprocess.run(
            [SERVICE_BIN, "--check-update", self.origin, "--data-dir", self.data_dir, "--no-activate"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=self.test_env, timeout=10
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("E_HOST_UPGRADE_REQUIRED", res.stderr + res.stdout)
        print("[PASS] E2E 5: Yeni host protokol tələbi aşkarlandıqda quraşdırıcı yenilənməsi tələb edildi.")

    def test_05b_e2e_protocol_overflow_rejection(self):
        """E2E Test 5b: min_host_protocol_version u64 daşması (4294967297) kəsilmədən düzgün rədd edilir."""
        self.http_server.routes = self.build_release_payload("0.2.0", min_host_proto=4294967297)

        res = subprocess.run(
            [SERVICE_BIN, "--check-update", self.origin, "--data-dir", self.data_dir, "--no-activate"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=self.test_env, timeout=10
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("E_HOST_UPGRADE_REQUIRED", res.stderr + res.stdout)
        print("[PASS] E2E 5b: 64-bitlik protokol daşması (4294967297) dəqiq fail-closed rədd edildi.")

    def test_05c_e2e_invalid_protocol_type_rejection(self):
        """E2E Test 5c: min_host_protocol_version yanlış tip olduqda fail-closed rədd edilir."""
        self.http_server.routes = self.build_release_payload("0.2.0", min_host_proto="invalid_string_proto")

        res = subprocess.run(
            [SERVICE_BIN, "--check-update", self.origin, "--data-dir", self.data_dir, "--no-activate"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=self.test_env, timeout=10
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("E_INVALID_PROTOCOL_VERSION_TYPE", res.stderr + res.stdout)
        print("[PASS] E2E 5c: Yanlış tipli protokol sahəsi dəqiq rədd edildi.")

    def test_06_e2e_quarantined_version_rejection(self):
        """E2E Test 6: Əvvəl qəzaya uğrayıb karantinə salınmış versiyanın təkrar quraşdırılmasının bloklanması."""
        self.init_journal("slot_a", "0.1.0", quarantined=["0.2.0"])
        self.http_server.routes = self.build_release_payload("0.2.0")

        res = subprocess.run(
            [SERVICE_BIN, "--check-update", self.origin, "--data-dir", self.data_dir, "--no-activate"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=self.test_env, timeout=10
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("E_VERSION_QUARANTINED", res.stderr + res.stdout)
        print("[PASS] E2E 6: Karantindəki versiyanın təkrar quraşdırılması fail-closed rədd edildi.")

    def test_07_e2e_consecutive_slot_switches_no_file_lock(self):
        """E2E Test 7: İki ardıcıl A -> B -> COMMITTED -> A yenilənməsində PROBATION bloklaması, LKG qorunması və file-lock-suz staging."""
        # Record initial LKG slot_a hash
        slot_a_svc = os.path.join(self.data_dir, "versions", "slot_a", "winkey_service.exe")
        with open(slot_a_svc, "rb") as f:
            initial_lkg_hash = hashlib.sha256(f.read()).hexdigest()

        # 1. Update A -> B (v0.2.0)
        self.http_server.routes = self.build_release_payload("0.2.0")
        res1 = subprocess.run(
            [SERVICE_BIN, "--check-update", self.origin, "--data-dir", self.data_dir, "--no-activate"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=self.test_env, timeout=10
        )
        self.assertEqual(res1.returncode, 0)

        # Aktivləşdiririk: slot_b aktiv olur (PROBATION vəziyyəti)
        res_act = subprocess.run(
            [SERVICE_BIN, "--activate-update", "--data-dir", self.data_dir],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=self.test_env, timeout=10
        )
        self.assertEqual(res_act.returncode, 0)

        with open(os.path.join(self.data_dir, "update_journal.json"), "r") as f:
            j_prob = json.load(f)
        self.assertEqual(j_prob["state"], "PROBATION")

        # 2. PROBATION zamanı növbəti v0.3.0 staging cəhdi BLOKLANMALIDIR (LKG qorunması)
        self.http_server.routes = self.build_release_payload("0.3.0")
        res_blocked = subprocess.run(
            [SERVICE_BIN, "--check-update", self.origin, "--data-dir", self.data_dir, "--no-activate"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=self.test_env, timeout=10
        )
        self.assertNotEqual(res_blocked.returncode, 0, "PROBATION zamanı yeni staging rədd edilməlidir")
        self.assertTrue("E_UPDATE_IN_PROGRESS" in res_blocked.stderr or "E_UPDATE_IN_PROGRESS" in res_blocked.stdout)

        # LKG slot_a hash-inin toxunulmaz qaldığını yoxlayırıq
        with open(slot_a_svc, "rb") as f:
            current_lkg_hash = hashlib.sha256(f.read()).hexdigest()
        self.assertEqual(initial_lkg_hash, current_lkg_hash, "PROBATION zamanı LKG slot faylları dəyişdirilməməlidir!")

        # 3. v0.2.0 rəsmi təsdiqlənir (COMMITTED)
        res_commit = subprocess.run(
            [SERVICE_BIN, "--mark-healthy", "--data-dir", self.data_dir],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=self.test_env, timeout=10
        )
        self.assertEqual(res_commit.returncode, 0)

        # 4. İndi B -> A (v0.3.0) təmiz icra olunmalıdır (A qovluğunda köhnə proses/lock olmadan)
        res2 = subprocess.run(
            [SERVICE_BIN, "--check-update", self.origin, "--data-dir", self.data_dir, "--no-activate"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=self.test_env, timeout=10
        )
        self.assertEqual(res2.returncode, 0, f"A->B->COMMITTED->A keçidində staging xətası: {res2.stderr}\n{res2.stdout}")

        with open(os.path.join(self.data_dir, "update_journal.json"), "r") as f:
            j = json.load(f)
        self.assertEqual(j["candidate_version"], "0.3.0")
        print("[PASS] E2E 7: A -> B -> COMMITTED -> A axınında LKG mühafizəsi və file-lock-suz staging tam təsdiqləndi.")

    def test_08_e2e_activation_crash_and_native_rollback(self):
        """E2E Test 8: Sınaq müddətində namizəd worker qəzası zamanı avtomatik LKG rollback və karantin."""
        # v0.2.0 stage edilir və aktivləşdirilir
        self.http_server.routes = self.build_release_payload("0.2.0")
        res_check = subprocess.run([SERVICE_BIN, "--check-update", self.origin, "--data-dir", self.data_dir],
                       capture_output=True, text=True, env=self.test_env, timeout=10)
        self.assertEqual(res_check.returncode, 0)

        # İndi slot_b PROBATION vəziyyətindədir
        with open(os.path.join(self.data_dir, "update_journal.json"), "r") as f:
            j = json.load(f)
        self.assertEqual(j["current_slot"], "slot_b")
        self.assertEqual(j["state"], "PROBATION")

        # Namizədin qəzaya uğraması qeydə alınır (--record-crash)
        rec = subprocess.run(
            [SERVICE_BIN, "--record-crash", "--data-dir", self.data_dir],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=self.test_env, timeout=10
        )
        self.assertEqual(rec.returncode, 0)
        self.assertIn("PASS_CRASH_RECORDED", rec.stdout)

        # Jurnal LKG (slot_a)-ya qayıtmalı və v0.2.0 karantinə salınmalıdır
        with open(os.path.join(self.data_dir, "update_journal.json"), "r") as f:
            j_after = json.load(f)

        self.assertEqual(j_after["current_slot"], "slot_a")
        self.assertEqual(j_after["state"], "ROLLED_BACK")
        self.assertIn("0.2.0", j_after["quarantined_versions"])
        print("[PASS] E2E 8: Qəza zamanı avtomatik native rollback və karantin 100% təsdiqləndi.")

if __name__ == "__main__":
    unittest.main()
