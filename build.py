"""
WinKey Pro — Vahid və Avtomatlaşdırılmış Build Sistemi (build.py)
==================================================================
Tələblər:
1. Son kodları release rejimində compile edir:
   - winkey_service.exe və winkey_helper.exe (apps/winkey_service)
   - winkey_desktop.exe (apps/desktop_tauri)
2. Slot A manifest.json faylını hesablayır və Ed25519 ilə imzalayır (manifest.sig).
3. NSIS ilə tək dist/WinKeySetup.exe faylını yaradır (UAC Admin manifestli).
4. Avtomatik quraşdırma və ya kilidləmə icra ETMİR (İstifadəçi özü açıb yoxlayacaq).
5. Xəta baş verərsə dərhal terminalda aydın şəkildə əks etdirir.
"""

import os
import sys
import json
import time
import hashlib
import subprocess
import shutil
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
DIST_DIR = os.path.join(ROOT_DIR, "dist")
SETUP_EXE = os.path.join(DIST_DIR, "WinKeySetup.exe")
MAKENSIS_EXE = os.path.join(ROOT_DIR, "tools", "nsis", "nsis-3.08", "makensis.exe")
NSI_SCRIPT = os.path.join(ROOT_DIR, "installer", "WinKeySetup.nsi")

SERVICE_CARGO = os.path.join(ROOT_DIR, "apps", "winkey_service", "Cargo.toml")
DESKTOP_CARGO = os.path.join(ROOT_DIR, "apps", "desktop_tauri", "src-tauri", "Cargo.toml")

SERVICE_EXE = os.path.join(ROOT_DIR, "apps", "winkey_service", "target", "release", "winkey_service.exe")
HELPER_EXE = os.path.join(ROOT_DIR, "apps", "winkey_service", "target", "release", "winkey_helper.exe")
DESKTOP_EXE = os.path.join(ROOT_DIR, "apps", "desktop_tauri", "src-tauri", "target", "release", "winkey_desktop.exe")

PRE_SIGNED_DIR = os.path.join(ROOT_DIR, "deploy", "pre_signed_slot_a")
PROD_KEY_PATH = os.path.join(ROOT_DIR, "deploy", "keys", "prod_release_ed25519_key.bin")

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def run_cmd(cmd, desc):
    print(f"\n[İŞ] {desc}...")
    res = subprocess.run(cmd, cwd=ROOT_DIR, capture_output=True, text=True, errors="replace")
    if res.returncode != 0:
        print(f"\n❌ XƏTA: {desc} uğursuz oldu (Exit Code: {res.returncode})!")
        if res.stderr:
            print("--- Standart Xəta Loqu (stderr) ---")
            print(res.stderr)
        if res.stdout:
            print("--- Standart Çıxış Loqu (stdout) ---")
            print(res.stdout)
        sys.exit(res.returncode)
    print(f"✓ {desc} uğurla tamamlandı.")
    return res

def step_compile_rust():
    print("\n" + "="*60)
    print(" 1/3. RUST BİNARLARININ OPTİMİZASİYA EDİLMİŞ TƏRTİBATI (RELEASE)")
    print("="*60)

    # Kilidlənmiş faylların qarşısını almaq üçün köhnə prosesləri dayandırırıq
    for name in ["winkey_desktop.exe", "winkey_service.exe", "winkey_helper.exe"]:
        subprocess.run(["taskkill", "/F", "/IM", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)

    # 1.1 Service & Helper
    run_cmd(
        ["cargo", "build", "--release", "--manifest-path", SERVICE_CARGO],
        "WinKey Service & Session Helper kompilyasiyası"
    )

    step_build_helper()

    # 1.2 Tauri Desktop
    run_cmd(
        ["cargo", "build", "--release", "--manifest-path", DESKTOP_CARGO],
        "WinKey Desktop (Tauri GUI) kompilyasiyası"
    )

    for exe in [SERVICE_EXE, HELPER_EXE, DESKTOP_EXE]:
        if not os.path.isfile(exe):
            raise RuntimeError(f"Missing build artifact: {exe}")


def step_build_helper():
    # Onedir: runtime is installed once, never extracted per unlock operation.
    run_cmd(
        [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
         "--distpath", os.path.dirname(HELPER_EXE),
         "--workpath", os.path.join(ROOT_DIR, "build", "helper"),
         os.path.join(ROOT_DIR, "winkey_helper.spec")],
        "Session helper ve fokus resursunun paketlenmesi"
    )
    output = Path(HELPER_EXE).parent / 'winkey_helper'
    runtime = Path(HELPER_EXE).parent / 'helper_runtime'
    if runtime.exists():
        shutil.rmtree(runtime)
    shutil.copytree(output / 'helper_runtime', runtime)
    shutil.copy2(output / 'winkey_helper.exe', HELPER_EXE)
    run_cmd([HELPER_EXE, "--check-focus-resource"], "Paketlenmis fokus resursunun yoxlanisi (input yoxdur)")
    run_cmd([HELPER_EXE, "--check-input-abi"], "Paketlenmis INPUT ABI yoxlanisi (input yoxdur)")

def step_sign_manifest():
    print("\n" + "="*60)
    print(" 2/3. SLOT A MANİFESTİ VƏ ED25519 RƏSMİ İMZALAMA")
    print("="*60)

    os.makedirs(PRE_SIGNED_DIR, exist_ok=True)
    svc_sha = sha256_file(SERVICE_EXE)
    svc_sz = os.path.getsize(SERVICE_EXE)
    hlp_sha = sha256_file(HELPER_EXE)
    hlp_sz = os.path.getsize(HELPER_EXE)

    manifest_data = {
        "version": "0.1.0",
        "timestamp": 1740000000.0,
        "files": [
            {"path": "winkey_service.exe", "sha256": svc_sha, "size": svc_sz},
            {"path": "winkey_helper.exe", "sha256": hlp_sha, "size": hlp_sz}
        ]
    }
    runtime = Path(HELPER_EXE).parent / 'helper_runtime'
    if runtime.is_dir():
        for file in sorted(runtime.rglob('*')):
            if file.is_file():
                manifest_data['files'].append({
                    'path': file.relative_to(runtime.parent).as_posix(),
                    'sha256': sha256_file(file), 'size': file.stat().st_size})

    manifest_bytes = json.dumps(manifest_data, indent=2, sort_keys=True).encode("utf-8")
    manifest_path = os.path.join(PRE_SIGNED_DIR, "manifest.json")
    with open(manifest_path, "wb") as f:
        f.write(manifest_bytes)

    if not os.path.exists(PROD_KEY_PATH):
        print(f"❌ XƏTA: Ed25519 açar faylı tapılmadı: {PROD_KEY_PATH}")
        sys.exit(1)

    with open(PROD_KEY_PATH, "rb") as f:
        priv_bytes = f.read()

    priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    sig_bytes = priv.sign(manifest_bytes)

    sig_path = os.path.join(PRE_SIGNED_DIR, "manifest.sig")
    with open(sig_path, "wb") as f:
        f.write(sig_bytes)

    print(f"  ✓ manifest.json ({os.path.getsize(manifest_path)} bayt)")
    print(f"  ✓ manifest.sig  ({len(sig_bytes)} bayt Ed25519 rəsmi imza)")

def step_build_installer():
    print("\n" + "="*60)
    print(" 3/3. TƏK QURAŞDIRICI YARADILMASI (dist/WinKeySetup.exe)")
    print("="*60)

    if not os.path.exists(MAKENSIS_EXE):
        print(f"❌ XƏTA: makensis.exe tapılmadı: {MAKENSIS_EXE}")
        sys.exit(1)

    os.makedirs(DIST_DIR, exist_ok=True)
    run_cmd([MAKENSIS_EXE, "/INPUTCHARSET", "UTF8", NSI_SCRIPT], "NSIS ilə WinKeySetup.exe paketlənməsi")

    if not os.path.exists(SETUP_EXE):
        print(f"❌ XƏTA: dist/WinKeySetup.exe yaranmadı!")
        sys.exit(1)

    sz = os.path.getsize(SETUP_EXE)
    sha = sha256_file(SETUP_EXE)

    sha_file = os.path.join(DIST_DIR, "SHA256SUMS.txt")
    with open(sha_file, "w", encoding="utf-8") as f:
        f.write(f"{sha}  WinKeySetup.exe\n")

    print("\n" + "#"*60)
    print(" 🎉 BUILD UĞURLA BAŞA ÇATDI!")
    print("#"*60)
    print(f" Çıxış Faylı : {SETUP_EXE}")
    print(f" Ölçü        : {sz} bayt ({sz / (1024*1024):.2f} MB)")
    print(f" SHA-256     : {sha}")
    print(f" İcazə Növü  : UAC Administrator (SYSTEM Xidmətini avtomatik qurur)")
    print(f" Qeyd        : Avtomatik quraşdırma/kilidləmə edilmədi.")
    print(f"               İndi dist/WinKeySetup.exe faylını açıb birbaşa test edə bilərsiniz.")
    print("#"*60)

def main():
    t0 = time.time()
    step_compile_rust()
    step_sign_manifest()
    step_build_installer()
    total_time = time.time() - t0
    print(f"\nÜmumi icra müddəti: {total_time:.2f} saniyə.\n")

if __name__ == "__main__":
    main()
