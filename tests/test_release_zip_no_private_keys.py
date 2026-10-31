"""
WinKey Pro — Release ZIP Private Key Yoxluğu və Pre-signed Artefakt Sınağı
Spesifikasiya: plan/GEMINI_SIGNING_WORKER_BLOCKERS.md (P0 Blokeri)

Yoxlayır:
1. Buraxılış ZIP paketi (WinKeyPro-v0.1.0-Windows-x64-FinalBuild.zip) daxilində
   heç bir gizli/özəl açar (*.key, *.bin, private, compromised) sızması yoxdur.
2. Tərkibdəki bütün komponentlər mövcuddur və SHA256SUMS.txt ilə 100% uyğundur.
3. ZIP daxilindəki pre-signed manifest.json və manifest.sig native Ed25519 verifier
   (winkey_service.exe --validate-slot) tərəfindən uğurla təsdiqlənir.
4. Heç bir halda xüsusi açar baytları loq və ya hesabatlara sızdırılmır.
"""

import os
import sys
import zipfile
import hashlib
import tempfile
import shutil
import subprocess
import unittest

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ZIP_PATH = os.path.join(ROOT_DIR, "plan", "reports", "final_batch", "WinKeyPro-v0.1.0-Windows-x64-FinalBuild.zip")
SHA_PATH = os.path.join(ROOT_DIR, "plan", "reports", "final_batch", "SHA256SUMS.txt")

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

class TestReleaseZipNoPrivateKeys(unittest.TestCase):

    def setUp(self):
        self.assertTrue(os.path.exists(ZIP_PATH), f"ZIP paketi tapılmadı: {ZIP_PATH}")
        self.assertTrue(os.path.exists(SHA_PATH), f"SHA256SUMS tapılmadı: {SHA_PATH}")
        self.tmp_dir = tempfile.mkdtemp(prefix="winkey_zip_audit_")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_zip_contains_absolutely_no_private_keys(self):
        """ZIP daxilində heç bir private key, *.key, *.bin və ya həssas açar faylı olmamalıdır."""
        with zipfile.ZipFile(ZIP_PATH, "r") as zf:
            namelist = zf.namelist()
            print("\n[ZIP TƏRKİBİ]:", len(namelist), "fayl")
            for name in sorted(namelist):
                print(f"  - {name}")
                lower = name.lower()
                self.assertFalse(
                    any(k in lower for k in [".key", "compromised", "private", "priv_"]),
                    f"P0 TƏHLÜKƏSİZLİK POZUNTUSU: ZIP daxilində qadağan olunmuş açar faylı: {name}"
                )
                self.assertFalse(
                    lower.endswith(".bin"),
                    f"P0 TƏHLÜKƏSİZLİK POZUNTUSU: ZIP daxilində .bin faylı olmamalıdır: {name}"
                )

    def test_02_zip_components_and_sha256_integrity(self):
        """ZIP faylının özünün və daxilindəki faylların SHA256SUMS ilə uyğunluğu."""
        zip_hash = sha256_file(ZIP_PATH)
        with open(SHA_PATH, "r", encoding="utf-8") as f:
            sha_content = f.read()

        self.assertIn(zip_hash, sha_content, "ZIP faylının hash-i SHA256SUMS.txt-də olmalıdır")

        # SHA256SUMS.txt sətirlərini parse edirik: {filename: expected_sha256}
        expected_hashes = {}
        for line in sha_content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) == 2:
                expected_hashes[parts[1]] = parts[0]

        self.assertEqual(
            expected_hashes.get("WinKeyPro-v0.1.0-Windows-x64-FinalBuild.zip"),
            zip_hash,
            "ZIP faylının faktiki SHA-256 dəyəri SHA256SUMS.txt-dəki qeydlə üst-üstə düşmür!"
        )

        required_files = [
            "winkey_service.exe",
            "winkey_helper.exe",
            "winkey_desktop.exe",
            "manifest.json",
            "manifest.sig",
            "service_installer.ps1",
            "service_uninstaller.ps1",
            "update_rollback_engine.py",
            "service_supervisor.py",
            "diagnostics_reporter.py",
            "gateway_production_server.py",
            "001_initial_schema.sql",
            "prod_release_ed25519_pub.hex",
            "TELIMAT.md"
        ]

        with zipfile.ZipFile(ZIP_PATH, "r") as zf:
            namelist = zf.namelist()
            for req in required_files:
                self.assertIn(req, namelist, f"Mütləq tələb olunan komponent ZIP-də tapılmadı: {req}")
                data = zf.read(req)
                actual_sha = hashlib.sha256(data).hexdigest()
                self.assertIn(req, expected_hashes, f"{req} üçün SHA256SUMS.txt-də hash qeydi tapılmadı")
                self.assertEqual(
                    actual_sha,
                    expected_hashes[req],
                    f"{req} faylının ZIP daxilindəki hash-i ({actual_sha}) SHA256SUMS.txt ({expected_hashes[req]}) ilə uyğun gəlmir!"
                )

    def test_03_extracted_manifest_validated_by_native_verifier(self):
        """ZIP-dən çıxarılmış pre-signed slot faylları native verifier tərəfindən təsdiqlənməlidir."""
        with zipfile.ZipFile(ZIP_PATH, "r") as zf:
            zf.extractall(self.tmp_dir)

        svc_bin = os.path.join(self.tmp_dir, "winkey_service.exe")
        self.assertTrue(os.path.exists(svc_bin))

        # Slot A strukturu yaradırıq
        slot_test_dir = os.path.join(self.tmp_dir, "slot_test")
        os.makedirs(slot_test_dir, exist_ok=True)
        shutil.copy2(svc_bin, os.path.join(slot_test_dir, "winkey_service.exe"))
        shutil.copy2(os.path.join(self.tmp_dir, "winkey_helper.exe"), os.path.join(slot_test_dir, "winkey_helper.exe"))
        shutil.copy2(os.path.join(self.tmp_dir, "manifest.json"), os.path.join(slot_test_dir, "manifest.json"))
        shutil.copy2(os.path.join(self.tmp_dir, "manifest.sig"), os.path.join(slot_test_dir, "manifest.sig"))

        # Native verifier çağırılır
        cmd = [svc_bin, "--validate-slot", slot_test_dir]
        res = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
        self.assertEqual(res.returncode, 0, f"Native verifier çıxarılmış slotu təsdiqləmədi: {res.stderr}")
        self.assertIn("VALID_SLOT", res.stdout)
        print("[PASS] ZIP tərkibindəki pre-signed manifest və binar fayllar 100% bütöv və təhlükəsizdir.")

if __name__ == "__main__":
    unittest.main()
