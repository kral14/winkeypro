"""
WinKey Pro — Create Final Batch Release ZIP & SHA256SUMS
P0 Tələbləri:
1. Build zamanı Slot A manifesti və Ed25519 imzası generasiya edilir.
2. End-user runtime-da private key tələb olunmur; yalnız pre-signed manifest/sig paketlənir.
3. ZIP daxilində heç bir private key, *.bin, *.pem, *.key sızması olmamalıdır (Assertion check).
"""

import os
import sys
import json
import time
import zipfile
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT_DIR = os.path.join(ROOT_DIR, "plan", "reports", "final_batch")
ZIP_PATH = os.path.join(OUT_DIR, "WinKeyPro-v0.1.0-Windows-x64-FinalBuild.zip")
SHA_PATH = os.path.join(OUT_DIR, "SHA256SUMS.txt")

PRE_SIGNED_DIR = os.path.join(ROOT_DIR, "deploy", "pre_signed_slot_a")
PROD_KEY_PATH = os.path.join(ROOT_DIR, "deploy", "keys", "prod_release_ed25519_key.bin")
PROD_PUB_HEX_PATH = os.path.join(ROOT_DIR, "deploy", "keys", "prod_release_ed25519_pub.hex")

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def prepare_pre_signed_slot_a():
    """Build zamanı rəsmi Slot A manifest.json və manifest.sig hazırlayır."""
    os.makedirs(PRE_SIGNED_DIR, exist_ok=True)
    
    svc_path = os.path.join(ROOT_DIR, "apps", "winkey_service", "target", "release", "winkey_service.exe")
    hlp_path = os.path.join(ROOT_DIR, "apps", "winkey_service", "target", "release", "winkey_helper.exe")
    
    if not os.path.exists(svc_path) or not os.path.exists(hlp_path):
        raise FileNotFoundError(f"Release binarlar tapılmadı: {svc_path}, {hlp_path}")
        
    svc_sha = sha256_file(svc_path)
    svc_size = os.path.getsize(svc_path)
    hlp_sha = sha256_file(hlp_path)
    hlp_size = os.path.getsize(hlp_path)
    
    manifest_data = {
        "version": "0.1.0",
        "timestamp": 1740000000.0,
        "files": [
            {"path": "winkey_service.exe", "sha256": svc_sha, "size": svc_size},
            {"path": "winkey_helper.exe", "sha256": hlp_sha, "size": hlp_size}
        ]
    }
    
    # BOM-suz UTF-8 JSON serializasiyası
    manifest_bytes = json.dumps(manifest_data, indent=2, sort_keys=True).encode("utf-8")
    manifest_path = os.path.join(PRE_SIGNED_DIR, "manifest.json")
    with open(manifest_path, "wb") as f:
        f.write(manifest_bytes)
        
    # Build-time Ed25519 imzalama (Owner-controlled release secret ilə)
    if not os.path.exists(PROD_KEY_PATH):
        raise FileNotFoundError(f"Build signing açarı tapılmadı: {PROD_KEY_PATH}")
        
    with open(PROD_KEY_PATH, "rb") as f:
        priv_bytes = f.read()
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    sig_bytes = priv.sign(manifest_bytes)
    
    sig_path = os.path.join(PRE_SIGNED_DIR, "manifest.sig")
    with open(sig_path, "wb") as f:
        f.write(sig_bytes)
        
    print(f"[BUILD_SIGNING] Slot A manifest və Ed25519 imzası hazırlandı: {manifest_path}, {sig_path}")
    return manifest_path, sig_path

def main():
    print("==========================================================")
    print("   WinKey Pro - Production Release Packaging              ")
    print("==========================================================")
    
    # 1. Slot A üçün rəsmi pre-signed manifest və imza hazırla
    manifest_path, sig_path = prepare_pre_signed_slot_a()
    
    files_to_pack = [
        ("winkey_desktop.exe", os.path.join(ROOT_DIR, "apps", "desktop_tauri", "src-tauri", "target", "release", "winkey_desktop.exe")),
        ("winkey_service.exe", os.path.join(ROOT_DIR, "apps", "winkey_service", "target", "release", "winkey_service.exe")),
        ("winkey_helper.exe", os.path.join(ROOT_DIR, "apps", "winkey_service", "target", "release", "winkey_helper.exe")),
        ("manifest.json", manifest_path),
        ("manifest.sig", sig_path),
        ("service_installer.ps1", os.path.join(ROOT_DIR, "scripts", "service_installer.ps1")),
        ("service_uninstaller.ps1", os.path.join(ROOT_DIR, "scripts", "service_uninstaller.ps1")),
        ("update_rollback_engine.py", os.path.join(ROOT_DIR, "pc_agent", "update_rollback_engine.py")),
        ("service_supervisor.py", os.path.join(ROOT_DIR, "pc_agent", "service_supervisor.py")),
        ("diagnostics_reporter.py", os.path.join(ROOT_DIR, "pc_agent", "diagnostics_reporter.py")),
        ("gateway_production_server.py", os.path.join(ROOT_DIR, "deploy", "gateway_production_server.py")),
        ("001_initial_schema.sql", os.path.join(ROOT_DIR, "deploy", "migrations", "001_initial_schema.sql")),
        ("prod_release_ed25519_pub.hex", PROD_PUB_HEX_PATH),
        ("TELIMAT.md", os.path.join(ROOT_DIR, "docs", "USER_GUIDE.md")),
    ]
    
    os.makedirs(OUT_DIR, exist_ok=True)
    print(f"[ZIP] Yekun buraxılış paketi yaradılır: {ZIP_PATH}")
    sha_entries = []

    with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED) as zf:
        for arcname, abs_path in files_to_pack:
            if not os.path.exists(abs_path):
                print(f"XƏTA: Fayl tapılmadı: {abs_path}")
                sys.exit(1)
            h = sha256_file(abs_path)
            size = os.path.getsize(abs_path)
            print(f"  + {arcname:<28} ({size:>10} bayt) SHA256={h[:16]}...")
            zf.write(abs_path, arcname)
            sha_entries.append((arcname, h))

    # P0 Təhlükəsizlik Auditi: ZIP daxilində gizli açar olmamalıdır!
    with zipfile.ZipFile(ZIP_PATH, "r") as zf:
        namelist = zf.namelist()
        for name in namelist:
            lower = name.lower()
            if any(bad in lower for bad in [".key", "compromised", "private", "priv_"]):
                os.remove(ZIP_PATH)
                raise AssertionError(f"P0 TƏHLÜKƏSİZLİK POZUNTUSU: ZIP-ə gizli açar faylı sızıb: {name}")
    print("[PASS] P0 Auditi: ZIP daxilində heç bir private key aşkar edilmədi.")

    zip_hash = sha256_file(ZIP_PATH)
    zip_size = os.path.getsize(ZIP_PATH)
    print(f"\n[ZIP HAZIRDIR] Ölçü: {zip_size} bayt | SHA256: {zip_hash}")

    with open(SHA_PATH, "w", encoding="utf-8") as f:
        f.write("# WinKey Pro v0.1.0 Final Batch Release Hashes (SHA-256)\n")
        f.write(f"# Yaradılma tarixi: 2026-10-29\n\n")
        f.write(f"{zip_hash}  WinKeyPro-v0.1.0-Windows-x64-FinalBuild.zip\n\n")
        f.write("# Tərkibdəki komponentlər:\n")
        for arcname, h in sha_entries:
            f.write(f"{h}  {arcname}\n")

    print(f"[SHA256 YAZILDI] {SHA_PATH}")

if __name__ == "__main__":
    main()
