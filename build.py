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
import argparse
import importlib.util
import zipfile
import urllib.request
import getpass
import re
from pathlib import Path

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
BUILD_LOG = Path(ROOT_DIR) / "build" / "logs" / "build_latest.log"
RELEASE_VERSION = '0.1.1'


def preflight():
    if os.name != 'nt':
        raise RuntimeError('Bu build Windows x64 üçündür.')
    missing = []
    if not shutil.which('cargo'):
        missing.append('Rust cargo (MSVC toolchain və Visual Studio C++ Build Tools)')
    for module, package in [('cryptography', 'cryptography'), ('PyInstaller', 'pyinstaller')]:
        if importlib.util.find_spec(module) is None:
            missing.append(f'{package}: "{sys.executable}" -m pip install {package}')
    for path in [MAKENSIS_EXE, NSI_SCRIPT, SERVICE_CARGO, DESKTOP_CARGO,
                 str(Path(ROOT_DIR) / 'installer' / 'winkey_helper.spec'), PROD_KEY_PATH,
                 str(Path(ROOT_DIR) / 'deploy' / 'keys' / 'prod_release_ed25519_pub.hex')]:
        if not Path(path).is_file():
            missing.append(f'Fayl tapılmadı: {path}')
    if missing:
        raise RuntimeError('\n'.join(missing))
    if Path(PROD_KEY_PATH).stat().st_size != 32:
        raise RuntimeError('Mövcud imzalama açarının formatı yanlışdır; yeni açar yaratmayın.')
    print('[PASS] Build alətləri və yerli imzalama faylları mövcuddur.', flush=True)

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def run_cmd(cmd, desc):
    print(f"\n[İŞ] {desc}...", flush=True)
    BUILD_LOG.parent.mkdir(parents=True, exist_ok=True)
    with BUILD_LOG.open('a', encoding='utf-8') as log:
        log.write(f'\n[İŞ] {desc}\n')
        with subprocess.Popen(cmd, cwd=ROOT_DIR, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, errors='replace') as process:
            for line in process.stdout:
                print(line, end='', flush=True)
                log.write(line)
                log.flush()
            code = process.wait()
        if code:
            raise RuntimeError(f'{desc}: exit={code}. Loq: {BUILD_LOG}. Fayl kilidlidirsə həmin build exe-sini bağlayın; quraşdırılmış xidmətə toxunulmur.')
    print(f"✓ {desc} uğurla tamamlandı.")

def step_compile_rust():
    print("\n" + "="*60)
    print(" 1/3. RUST BİNARLARININ OPTİMİZASİYA EDİLMİŞ TƏRTİBATI (RELEASE)")
    print("="*60)

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
         os.path.join(ROOT_DIR, "installer", "winkey_helper.spec")],
        "Session helper ve fokus resursunun paketlenmesi"
    )
    output = Path(HELPER_EXE).parent / 'winkey_helper'
    runtime = Path(HELPER_EXE).parent / 'helper_runtime'
    if runtime.exists():
        expected = (Path(ROOT_DIR) / 'apps' / 'winkey_service' / 'target' / 'release' / 'helper_runtime').resolve()
        if runtime.resolve() != expected or runtime.is_symlink():
            raise RuntimeError('Helper runtime yolu gözlənilən build qovluğunda deyil.')
        shutil.rmtree(runtime)
    shutil.copytree(output / 'helper_runtime', runtime)
    shutil.copy2(output / 'winkey_helper.exe', HELPER_EXE)
    run_cmd([HELPER_EXE, "--check-focus-resource"], "Paketlenmis fokus resursunun yoxlanisi (input yoxdur)")
    run_cmd([HELPER_EXE, "--check-input-abi"], "Paketlenmis INPUT ABI yoxlanisi (input yoxdur)")

def step_sign_manifest():
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    print("\n" + "="*60)
    print(" 2/3. SLOT A MANİFESTİ VƏ ED25519 RƏSMİ İMZALAMA")
    print("="*60)

    os.makedirs(PRE_SIGNED_DIR, exist_ok=True)
    svc_sha = sha256_file(SERVICE_EXE)
    svc_sz = os.path.getsize(SERVICE_EXE)
    hlp_sha = sha256_file(HELPER_EXE)
    hlp_sz = os.path.getsize(HELPER_EXE)

    manifest_data = {
        "version": RELEASE_VERSION,
        "timestamp": time.time(),
        "files": [
            {"path": "winkey_service.exe", "sha256": svc_sha, "size": svc_sz},
            {"path": "winkey_helper.exe", "sha256": hlp_sha, "size": hlp_sz},
            {"path": "winkey_desktop.exe", "sha256": sha256_file(DESKTOP_EXE), "size": os.path.getsize(DESKTOP_EXE)}
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

    if not os.path.exists(PROD_KEY_PATH):
        print(f"❌ XƏTA: Ed25519 açar faylı tapılmadı: {PROD_KEY_PATH}")
        sys.exit(1)

    with open(PROD_KEY_PATH, "rb") as f:
        priv_bytes = f.read()

    priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    expected_pub = Path(ROOT_DIR, 'deploy', 'keys', 'prod_release_ed25519_pub.hex').read_text(encoding='ascii').strip().lower()
    actual_pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    if actual_pub != expected_pub:
        raise RuntimeError('İmzalama açarı mövcud public key ilə uyğun deyil; paket hazırlanmadı.')
    sig_bytes = priv.sign(manifest_bytes)
    priv.public_key().verify(sig_bytes, manifest_bytes)
    with open(manifest_path, "wb") as f:
        f.write(manifest_bytes)

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
    pending_setup = str(Path(DIST_DIR) / 'WinKeySetup-building.exe')
    run_cmd([MAKENSIS_EXE, "/INPUTCHARSET", "UTF8", f'/DOUTPUT_FILE={pending_setup}', f'/DPRODUCT_VERSION={RELEASE_VERSION}', NSI_SCRIPT], "NSIS ilə WinKeySetup.exe paketlənməsi")
    if not Path(pending_setup).is_file() or Path(pending_setup).stat().st_size < 500_000:
        raise RuntimeError('Yeni setup yaranmadı və ya ölçüsü yanlışdır. Əvvəlki setup qorundu.')
    os.replace(pending_setup, SETUP_EXE)

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
    global RELEASE_VERSION
    parser = argparse.ArgumentParser(description='WinKey Pro: compile → helper → imza → tək setup. Quraşdırma icra etmir.')
    parser.add_argument('--check', action='store_true', help='Yalnız build tələblərini yoxla')
    parser.add_argument('--version', help='Buraxılış versiyası, məsələn 0.1.2. Susmaya görə patch artırılır.')
    parser.add_argument('--publish', metavar='SERVER', help='Build-dən sonra imzalı paketi serverə yüklə və avtomatik yenilənməni başlat')
    args = parser.parse_args()
    preflight()
    if args.check:
        return
    if args.version:
        RELEASE_VERSION = args.version
    else:
        try:
            old=json.loads(Path(PRE_SIGNED_DIR,'manifest.json').read_text(encoding='utf-8'))['version']
            major,minor,patch=map(int,old.split('.'))
            RELEASE_VERSION=f'{major}.{minor}.{patch+1}'
        except (OSError,ValueError,KeyError):
            RELEASE_VERSION='0.1.1'
    if not re.fullmatch(r'\d+\.\d+\.\d+',RELEASE_VERSION):
        raise RuntimeError('Versiya MAJOR.MINOR.PATCH formatında olmalıdır.')
    print(f'[RELEASE] {RELEASE_VERSION}',flush=True)
    BUILD_LOG.parent.mkdir(parents=True, exist_ok=True)
    BUILD_LOG.write_text('WinKey Pro build\n', encoding='utf-8')
    t0 = time.time()
    step_compile_rust()
    step_sign_manifest()
    step_build_installer()
    package = create_update_package()
    if args.publish:
        token=os.environ.get('WINKEY_ADMIN_SECRET') or getpass.getpass('Server admin açarı (ekranda görünməyəcək): ')
        if not token:
            raise RuntimeError('Admin açarı verilmədi; paket hazırdır, serverə göndərilmədi.')
        request=urllib.request.Request(args.publish.rstrip('/')+'/admin/updates/publish',
            data=package.read_bytes(),headers={'Authorization':'Bearer '+token,'Content-Type':'application/zip'},method='POST')
        try:
            with urllib.request.urlopen(request,timeout=300) as response:
                result=json.load(response)
        except Exception:
            raise RuntimeError('E_RELEASE_PUBLISH_FAILED: serverə yükləmə alınmadı. Yerli paket qorundu; server loqunu yoxlayın.') from None
        print('[PUBLISHED] version='+result['version']+'; qoşulmuş proqramlara yenilənmə bildirişi göndərildi.')
    total_time = time.time() - t0
    print(f"\nÜmumi icra müddəti: {total_time:.2f} saniyə.\n")


def create_update_package():
    manifest=Path(PRE_SIGNED_DIR,'manifest.json')
    data=json.loads(manifest.read_text(encoding='utf-8'))
    target=Path(DIST_DIR,'WinKeyUpdate-'+data['version']+'.zip')
    temporary=target.with_suffix('.building.zip')
    with zipfile.ZipFile(temporary,'w',zipfile.ZIP_DEFLATED) as package:
        package.write(manifest,'manifest.json')
        package.write(Path(PRE_SIGNED_DIR,'manifest.sig'),'manifest.sig')
        for entry in data['files']:
            source=Path(DESKTOP_EXE) if entry['path']=='winkey_desktop.exe' else Path(SERVICE_EXE).parent/entry['path']
            if sha256_file(source)!=entry['sha256']:
                raise RuntimeError('E_PACKAGE_CHANGED_DURING_BUILD')
            package.write(source,entry['path'])
    os.replace(temporary,target)
    print('[UPDATE_PACKAGE] '+str(target))
    return target

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('\n[XƏTA] Build dayandırıldı. Setup avtomatik açılmadı.')
        sys.exit(130)
    except Exception as error:
        print(f'\n[XƏTA] {error}', file=sys.stderr, flush=True)
        sys.exit(1)
