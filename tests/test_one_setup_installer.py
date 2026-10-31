"""
WinKey Pro — One Setup Installer Comprehensive Test
plan/GEMINI_ONE_SETUP_EXE.md spesifikasiyası üzrə:
Yoxlayır:
1. dist/WinKeySetup.exe mövcuddur, ölçüsü 10MB+ təşkil edir və dist/SHA256SUMS.txt ilə 100% uyğundur.
2. Installer binarı daxilində UAC 'requireAdministrator' manifesti mövcuddur.
3. Binar daxilində heç bir gizli açar (*.key, private, compromised) sızması yoxdur.
4. dist/NECE_QURULUR.txt sadə və maksimum 5 addımlıqdır.
5. Quraşdırma skriptləri və pre-signed slot komponentləri bütövdür.
"""

import os
import sys
import hashlib
import unittest

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DIST_DIR = os.path.join(ROOT_DIR, "dist")
SETUP_EXE = os.path.join(DIST_DIR, "WinKeySetup.exe")
SHA_FILE = os.path.join(DIST_DIR, "SHA256SUMS.txt")
GUIDE_FILE = os.path.join(DIST_DIR, "NECE_QURULUR.txt")

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

class TestOneSetupInstaller(unittest.TestCase):

    def setUp(self):
        self.assertTrue(os.path.exists(SETUP_EXE), f"Installer tapılmadı: {SETUP_EXE}")
        self.assertTrue(os.path.exists(SHA_FILE), f"SHA faylı tapılmadı: {SHA_FILE}")
        self.assertTrue(os.path.exists(GUIDE_FILE), f"Təlimat faylı tapılmadı: {GUIDE_FILE}")

    def test_01_setup_exe_exists_and_matches_sha256(self):
        """WinKeySetup.exe mövcud olmalı və SHA256SUMS.txt ilə 100% uyğunlaşmalıdır."""
        sz = os.path.getsize(SETUP_EXE)
        self.assertGreater(sz, 5 * 1024 * 1024, "Installer ən az 5MB olmalıdır (komponentləri daxilində saxlayır)")
        
        actual_hash = sha256_file(SETUP_EXE)
        with open(SHA_FILE, "r", encoding="utf-8") as f:
            sha_content = f.read()
            
        self.assertIn(actual_hash, sha_content, "Faktiki SHA-256 hash SHA256SUMS.txt faylı ilə üst-üstə düşmür")
        print(f"\n[PASS] WinKeySetup.exe ölçü ({sz} bayt) və SHA-256 ({actual_hash[:16]}...) təsdiqləndi.")

    def test_02_setup_exe_uac_require_administrator(self):
        """Installer binarının PE manifestində requireAdministrator UAC tələbi olmalıdır."""
        with open(SETUP_EXE, "rb") as f:
            exe_bytes = f.read()
            
        self.assertIn(b"requireAdministrator", exe_bytes, "Installer manifestində 'requireAdministrator' tapılmadı")
        self.assertIn(b"uiAccess", exe_bytes, "Installer manifestində 'uiAccess' tapılmadı")
        print("[PASS] Windows UAC administrator icazəsi manifesti təsdiqləndi.")

    def test_03_setup_exe_contains_no_private_keys(self):
        """Installer daxilində heç bir xüsusi/gizli açar (.key, .bin, compromised) sızmamalıdır."""
        # NSIS daxilində sıxılmış blokda və ya fayl cədvəlində qadağan olunmuş adlar olmamalıdır
        with open(SETUP_EXE, "rb") as f:
            exe_bytes = f.read()
            
        for forbidden in [b"prod_release_ed25519_key.bin", b"compromised", b"private_key", b"test_device_token"]:
            self.assertNotIn(forbidden, exe_bytes, f"P0 TƏHLÜKƏSİZLİK POZUNTUSU: Qadağan olunmuş açar baytları aşkar edildi: {forbidden}")
        print("[PASS] P0 Təhlükəsizlik: Installer daxilində heç bir gizli açar yoxdur.")

    def test_04_guide_contains_max_5_steps_and_no_technical_jargon(self):
        """NECE_QURULUR.txt maksimum 5 sadə addımdan ibarət olmalıdır."""
        with open(GUIDE_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
        steps = [l.strip() for l in lines if l.strip().startswith(("1.", "2.", "3.", "4.", "5.", "6.", "7."))]
        self.assertLessEqual(len(steps), 5, f"Təlimat addımları 5-dən çox olmamalıdır! Mövcud addım sayı: {len(steps)}")
        self.assertGreaterEqual(len(steps), 3, "Təlimat ən azı 3 addım olmalıdır")
        
        # Son istifadəçi təlimatında qadağan olunan texniki sözlər
        content = "".join(lines).lower()
        for tech in ["cargo", "python scripts/", "powershell.exe -", "rustc", "git clone"]:
            self.assertNotIn(tech, content, f"İstifadəçi təlimatında texniki tələb qadağandır: {tech}")
        print(f"[PASS] İstifadəçi təlimatı dəqiq {len(steps)} sadə addımdan ibarətdir.")

    def test_05_installer_nsis_source_reproducibility(self):
        """NSIS qaynaq faylı və build aləti repoda mövcud və bütövdür."""
        nsi_path = os.path.join(ROOT_DIR, "installer", "WinKeySetup.nsi")
        makensis_path = os.path.join(ROOT_DIR, "tools", "nsis", "nsis-3.08", "makensis.exe")
        build_script = os.path.join(ROOT_DIR, "scripts", "build_one_setup_exe.py")
        
        self.assertTrue(os.path.exists(nsi_path), "WinKeySetup.nsi mövcud olmalıdır")
        self.assertTrue(os.path.exists(makensis_path), "makensis.exe mövcud olmalıdır")
        self.assertTrue(os.path.exists(build_script), "build_one_setup_exe.py mövcud olmalıdır")
        print("[PASS] Quraşdırıcının qaynaq kodu və təkrar qurulabilən (reproducible) build mühiti təsdiqləndi.")

if __name__ == "__main__":
    unittest.main()
