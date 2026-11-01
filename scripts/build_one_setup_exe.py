"""
WinKey Pro — One Setup EXE Build & Verification Script
plan/GEMINI_ONE_SETUP_EXE.md spesifikasiyası üzrə:
1. dist/WinKeySetup.exe yaradılması (NSIS x64 UAC-elevated installer)
2. Binarın hash və ölçüsünün təyin edilməsi
3. dist/SHA256SUMS.txt və dist/NECE_QURULUR.txt generasiyası
"""

import os
import sys
import hashlib
import subprocess
import time

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DIST_DIR = os.path.join(ROOT_DIR, "dist")
MAKENSIS_EXE = os.path.join(ROOT_DIR, "tools", "nsis", "nsis-3.08", "makensis.exe")
NSI_SCRIPT = os.path.join(ROOT_DIR, "installer", "WinKeySetup.nsi")
SETUP_EXE = os.path.join(DIST_DIR, "WinKeySetup.exe")
SHA_FILE = os.path.join(DIST_DIR, "SHA256SUMS.txt")
GUIDE_FILE = os.path.join(DIST_DIR, "NECE_QURULUR.txt")

REQUIRED_PAYLOAD_FILES = [
    os.path.join(ROOT_DIR, "apps", "desktop_tauri", "src-tauri", "target", "release", "winkey_desktop.exe"),
    os.path.join(ROOT_DIR, "apps", "winkey_service", "target", "release", "winkey_service.exe"),
    os.path.join(ROOT_DIR, "apps", "winkey_service", "target", "release", "winkey_helper.exe"),
    os.path.join(ROOT_DIR, "deploy", "pre_signed_slot_a", "manifest.json"),
    os.path.join(ROOT_DIR, "deploy", "pre_signed_slot_a", "manifest.sig"),
    os.path.join(ROOT_DIR, "scripts", "service_installer.ps1"),
    os.path.join(ROOT_DIR, "scripts", "service_uninstaller.ps1"),
    os.path.join(ROOT_DIR, "docs", "USER_GUIDE.md"),
    os.path.join(ROOT_DIR, "deploy", "migrations", "001_initial_schema.sql"),
    os.path.join(ROOT_DIR, "deploy", "keys", "prod_release_ed25519_pub.hex"),
]

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def check_payload():
    print("[1/4] Quraşdırılacaq təməl binar və konfiqurasiya faylları yoxlanılır...")
    for p in REQUIRED_PAYLOAD_FILES:
        if not os.path.exists(p):
            raise FileNotFoundError(f"Məcburi komponent tapılmadı: {p}")
        sz = os.path.getsize(p)
        print(f"  ✓ {os.path.basename(p):<30} ({sz:>10} bayt)")
    print("[PASS] Bütün 10 təməl komponent mövcuddur.")

def build_installer():
    print("\n[2/4] NSIS ilə dist/WinKeySetup.exe tərtib edilir...")
    if not os.path.exists(MAKENSIS_EXE):
        raise FileNotFoundError(f"makensis.exe tapılmadı: {MAKENSIS_EXE}")
    if not os.path.exists(NSI_SCRIPT):
        raise FileNotFoundError(f"NSIS skripti tapılmadı: {NSI_SCRIPT}")
        
    os.makedirs(DIST_DIR, exist_ok=True)
    cmd = [MAKENSIS_EXE, NSI_SCRIPT]
    res = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if res.returncode != 0:
        print("makensis XƏTASI:\n", res.stderr or res.stdout)
        raise RuntimeError(f"NSIS tərtibatı uğursuz oldu (exit code {res.returncode})")
        
    if not os.path.exists(SETUP_EXE):
        raise FileNotFoundError(f"Gözlənilən installer EXE faylı yaranmadı: {SETUP_EXE}")
        
    sz = os.path.getsize(SETUP_EXE)
    sha = sha256_file(SETUP_EXE)
    print(f"[PASS] dist/WinKeySetup.exe uğurla yaradıldı!")
    print(f"  Ölçü  : {sz} bayt ({sz / (1024*1024):.2f} MB)")
    print(f"  SHA256: {sha}")
    return sz, sha

def write_artifacts(size, sha):
    print("\n[3/4] SHA256SUMS və istifadəçi təlimatı faylları yazılır...")
    
    with open(SHA_FILE, "w", encoding="utf-8") as f:
        f.write("# WinKey Pro v0.1.0 One-Click Setup Hash (SHA-256)\n")
        f.write(f"# Yaradılma tarixi: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"{sha}  WinKeySetup.exe\n")
    print(f"  ✓ {SHA_FILE}")
    
    guide_text = """==================================================================
   WinKey Pro — Quraşdırma və İstifadə Təlimatı (Maksimum 5 Addım)
==================================================================

1. WinKeySetup.exe faylını açın və Windows UAC ekranında "Bəli" seçin.
2. Açılan pəncərədə "Quraşdır" düyməsini sıxın.
   (Arxa plan xidməti, təhlükəsizlik icazələri və qısayollar avtomatik qurulacaq).
3. Quraşdırma bitdikdə "Bitir" düyməsini sıxın — WinKey Pro pəncərəsi açılacaq.
4. Ekranda kompüterinizin adını yoxlayın və Windows açılış PIN-inizi daxil edin
   (PIN Windows DPAPI ilə yalnız yerli yaddaşda qorunur, serverə getmir).
5. Mobil telefonunuzla ekrandakı QR kodu oxudub Kilidlə / Kilidi aç səhifəsini açın.

Qeyd:
- Heç bir terminal, PowerShell, Python və ya qovluq köçürmə tələb olunmur.
- Proqram bağlandıqda bildiriş panelində (Tray) arxa planda işləməyə davam edir.
"""
    with open(GUIDE_FILE, "w", encoding="utf-8") as f:
        f.write(guide_text)
    print(f"  ✓ {GUIDE_FILE}")

def main():
    print("==================================================================")
    print("   WinKey Pro — One-Click Setup EXE Generator (dist/WinKeySetup)  ")
    print("==================================================================")
    t0 = time.time()
    check_payload()
    sz, sha = build_installer()
    write_artifacts(sz, sha)
    dur = time.time() - t0
    print(f"\n[4/4] Bütün əməliyyatlar {dur:.2f} saniyəyə uğurla başa çatdı!")

if __name__ == "__main__":
    main()
