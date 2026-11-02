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
WEBVIEW2_DLL = os.path.join(ROOT_DIR, "apps", "desktop_tauri", "src-tauri", "target", "release", "WebView2Loader.dll")

PRE_SIGNED_DIR = os.path.join(ROOT_DIR, "deploy", "pre_signed_slot_a")
PROD_KEY_PATH = os.path.join(ROOT_DIR, "deploy", "keys", "prod_release_ed25519_key.bin")
BUILD_LOG = Path(ROOT_DIR) / "build" / "logs" / "build_latest.log"
RELEASE_VERSION = '0.1.1'
_BUILD_LOCK = None


def acquire_build_lock():
    global _BUILD_LOCK
    import msvcrt
    directory=Path(ROOT_DIR)/'build'
    directory.mkdir(exist_ok=True)
    handle=(directory/'release-build.lock').open('a+b')
    if handle.seek(0,os.SEEK_END)==0:
        handle.write(b'0'); handle.flush()
    handle.seek(0)
    try:
        msvcrt.locking(handle.fileno(),msvcrt.LK_NBLCK,1)
    except OSError:
        handle.close()
        raise RuntimeError('Başqa build artıq işləyir; ikinci build başladılmadı.') from None
    _BUILD_LOCK=handle


def preflight():
    if os.name != 'nt':
        raise RuntimeError('Bu build Windows x64 üçündür.')
    missing = []
    if not shutil.which('cargo'):
        missing.append('Rust cargo (MSVC toolchain və Visual Studio C++ Build Tools)')
    for module, package in [('cryptography', 'cryptography'), ('PyInstaller', 'pyinstaller'), ('psutil', 'psutil')]:
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


STAGING_PRE_SIGNED_DIR = Path(ROOT_DIR, "build", "staging_pre_signed_slot_a")

def sync_project_metadata(version: str) -> dict:
    backups = {}
    targets = [
        Path(SERVICE_CARGO),
        Path(SERVICE_CARGO).parent / 'Cargo.lock',
        Path(DESKTOP_CARGO),
        Path(DESKTOP_CARGO).parent / 'Cargo.lock',
        Path(ROOT_DIR, 'apps', 'desktop_tauri', 'src-tauri', 'tauri.conf.json'),
        Path(ROOT_DIR, 'Cargo.lock'),
    ]
    try:
        for p in targets:
            if p.is_file():
                backups[p] = p.read_bytes()

        svc_cargo = Path(SERVICE_CARGO)
        if svc_cargo.is_file():
            text = backups[svc_cargo].decode('utf-8')
            new_text = re.sub(r'(?m)^version\s*=\s*"[^"]+"', f'version = "{version}"', text, count=1)
            svc_cargo.write_bytes(new_text.replace('\r\n', '\n').encode('utf-8'))

        dsk_cargo = Path(DESKTOP_CARGO)
        if dsk_cargo.is_file():
            text = backups[dsk_cargo].decode('utf-8')
            new_text = re.sub(r'(?m)^version\s*=\s*"[^"]+"', f'version = "{version}"', text, count=1)
            dsk_cargo.write_bytes(new_text.replace('\r\n', '\n').encode('utf-8'))

        tauri_conf = Path(ROOT_DIR, 'apps', 'desktop_tauri', 'src-tauri', 'tauri.conf.json')
        if tauri_conf.is_file():
            text = backups[tauri_conf].decode('utf-8')
            data = json.loads(text)
            data['version'] = version
            tauri_conf.write_text(json.dumps(data, indent=2), encoding='utf-8')
    except Exception as e:
        restore_project_metadata(backups)
        raise RuntimeError(f"E_METADATA_SYNC_FAILED: {e}") from e
    return backups

def restore_project_metadata(backups: dict):
    restore_errors = []
    for path, content in backups.items():
        try:
            path.write_bytes(content)
            current = path.read_bytes()
            if current != content:
                restore_errors.append(f"{path}: restore verification failed (bytes mismatch)")
        except Exception as ex:
            restore_errors.append(f"{path}: {ex}")
    if restore_errors:
        raise RuntimeError("E_METADATA_RESTORE_FAILED: " + "; ".join(restore_errors))

RUNTIME_PINNED_PUBKEY_HEX = "56524c1040e3a8309e938332037d0a0167cc2da30761abcfb77c93a899ad61da"

OFFICIAL_RELEASE_PUBKEYS = [
    # Server (deploy/update_repository.py), Service (recovery_engine.rs) və Desktop (slot_update.rs) rəsmi public key
    RUNTIME_PINNED_PUBKEY_HEX,
    # Build sistemi və deploy/keys/prod_release_ed25519_pub.hex yerli imzalama public key
    "4c7fa3c7a37b79b840e939741138f0748087ae0f06fa94e728557ec2a558fc54"
]

def check_signing_key_consistency():
    """
    Kriptoqrafik təhlükəsizlik yoxlanışı:
    Build sisteminin imzalama açarı ilə runtime komponentlərində (Service, Desktop, Server)
    pinned olan ictimai açar mütləq eyni olmalıdır.
    Fərqlilik olarsa, build warning vermir, dərhal dayandırılır (fail-closed).
    """
    # Test environment must never change the trust anchor of a production build.
    expected = RUNTIME_PINNED_PUBKEY_HEX.lower()

    if not os.path.exists(PROD_KEY_PATH):
        raise RuntimeError(f"E_KEY_MISSING: İmzalama açarı tapılmadı: {PROD_KEY_PATH}")

    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    with open(PROD_KEY_PATH, "rb") as f:
        priv_bytes = f.read()
    if len(priv_bytes) != 32:
        raise RuntimeError("E_KEY_INVALID_LENGTH: İmzalama açarı 32 bayt olmalıdır.")

    priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    actual_pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex().lower()

    # Hex faylı ilə yoxlanış
    pub_file = Path(ROOT_DIR) / 'deploy' / 'keys' / 'prod_release_ed25519_pub.hex'
    if pub_file.is_file():
        file_pub = pub_file.read_text(encoding='ascii').strip().lower()
        if actual_pub != file_pub:
            raise RuntimeError(
                f"E_KEY_MISMATCH: Yerli private key ({actual_pub[:16]}...) "
                f"prod_release_ed25519_pub.hex ({file_pub[:16]}...) ilə uyğun deyil!"
            )

    # Runtime pinned açarla yoxlanış
    if actual_pub != expected:
        raise RuntimeError(
            f"E_KEY_MISMATCH: Yerli imzalama açarı ({actual_pub[:16]}...) "
            f"runtime pinned ictimai açarla ({expected[:16]}...) uyğun deyil! "
            f"Paket buraxılışı dayandırıldı (xidmət və desktop tərəfindən rədd ediləcək paket hazırlana bilməz)."
        )
    return actual_pub

def is_pre_signed_dir_or_recovery(dir_path: Path) -> bool:
    try:
        resolved = Path(dir_path).resolve()
        for base in [Path(PRE_SIGNED_DIR).resolve(), Path(STAGING_PRE_SIGNED_DIR).resolve()]:
            if resolved == base or resolved == base.parent / (base.name + ".candidate") or resolved == base.parent / (base.name + ".backup"):
                return True
    except Exception:
        pass
    return False

def get_candidate_public_keys(pub_key_hex: str = None) -> list:
    # Açıq test injection arqumenti verildikdə yalnız həmin test açarı yoxlanılır
    if pub_key_hex:
        return [bytes.fromhex(pub_key_hex.strip())]

    # Açıq test injection mühiti (unit test izolyasiyası üçün)
    test_env_key = os.environ.get("WINKEY_RELEASE_PUBKEY_HEX")
    if test_env_key:
        return [bytes.fromhex(test_env_key.strip())]

    # Production doğrulaması: yalnız rəsmi təsdiqlənmiş etibar lövbəri (trust anchor)
    keys = [bytes.fromhex(RUNTIME_PINNED_PUBKEY_HEX)]
    pub_file = Path(ROOT_DIR) / 'deploy' / 'keys' / 'prod_release_ed25519_pub.hex'
    if pub_file.is_file():
        try:
            kh = bytes.fromhex(pub_file.read_text(encoding='ascii').strip())
            if kh not in keys:
                keys.append(kh)
        except Exception:
            pass
    return keys

def get_release_public_key_bytes(pub_key_hex: str = None) -> bytes:
    keys = get_candidate_public_keys(pub_key_hex)
    return keys[0]

def verify_release_dir(dir_path: Path, pub_key_hex: str = None) -> tuple:
    dir_path = Path(dir_path)
    if not dir_path.is_dir():
        return False, None, "DIRECTORY_NOT_FOUND"

    manifest_file = dir_path / "manifest.json"
    sig_file = dir_path / "manifest.sig"
    if not manifest_file.is_file():
        return False, None, "MISSING_MANIFEST_JSON"
    if not sig_file.is_file():
        return False, None, "MISSING_MANIFEST_SIG"

    try:
        manifest_bytes = manifest_file.read_bytes()
        manifest_data = json.loads(manifest_bytes.decode("utf-8"))
        if not isinstance(manifest_data, dict) or "version" not in manifest_data or "files" not in manifest_data:
            return False, None, "INVALID_MANIFEST_SCHEMA"
    except Exception as e:
        return False, None, f"CORRUPT_MANIFEST_JSON: {e}"

    sig_bytes = sig_file.read_bytes()
    if len(sig_bytes) != 64:
        return False, None, f"INVALID_SIG_LEN_{len(sig_bytes)}"

    # 1. Kriptoqrafik Ed25519 İmza Yoxlanışı (raw və Windows CRLF->LF normalizasiyası üzrə)
    from cryptography.hazmat.primitives.asymmetric import ed25519
    candidate_keys = get_candidate_public_keys(pub_key_hex)
    verified = False

    byte_variants = [manifest_bytes]
    if b'\r\n' in manifest_bytes:
        byte_variants.append(manifest_bytes.replace(b'\r\n', b'\n'))

    for k_bytes in candidate_keys:
        try:
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(k_bytes)
            for b_cand in byte_variants:
                try:
                    pub_key.verify(sig_bytes, b_cand)
                    verified = True
                    break
                except Exception:
                    pass
            if verified:
                break
        except Exception:
            pass

    if not verified:
        return False, None, "INVALID_SIGNATURE"

    # 2. Fayl Bütövlüyü və Çatışmayan Fayl Yoxlanışı (P1 Tələbi)
    # Əgər qovluq xüsusi yalnız-manifest metadata qovluğu deyilsə (məsələn pre_signed_slot_a),
    # manifestdə göstərilən BÜTÜN fayllar mövcud olmalı və SHA-256 uyğun gəlməlidir!
    is_metadata_only = is_pre_signed_dir_or_recovery(dir_path) and not any(
        (dir_path / f["path"]).is_file() for f in manifest_data.get("files", [])
    )

    if not is_metadata_only:
        from pathlib import PurePosixPath
        for fentry in manifest_data.get("files", []):
            rel_name = fentry.get("path", "")
            if not rel_name:
                return False, None, "EMPTY_PAYLOAD_PATH"
            # Path traversal və injection qadağası (P0 security)
            p_posix = PurePosixPath(rel_name)
            if p_posix.is_absolute() or '..' in p_posix.parts or '\\' in rel_name or ':' in rel_name or str(p_posix) != rel_name:
                return False, None, f"INVALID_PAYLOAD_PATH_{rel_name}"

            fpath = dir_path / rel_name
            if not fpath.is_file():
                return False, None, f"MISSING_PAYLOAD_FILE_{rel_name}"
            # Size yoxlanışı
            if "size" in fentry and fpath.stat().st_size != fentry["size"]:
                return False, None, f"FILE_SIZE_MISMATCH_{rel_name}"
            # SHA-256 hash yoxlanışı
            if sha256_file(fpath) != fentry.get("sha256"):
                return False, None, f"FILE_HASH_MISMATCH_{rel_name}"

    return True, manifest_data, "VALID"

def recover_release_dir(target_dir: Path, pub_key_hex: str = None) -> bool:
    target_dir = Path(target_dir).resolve()
    backup_dir = target_dir.parent / (target_dir.name + ".backup")
    candidate_dir = target_dir.parent / (target_dir.name + ".candidate")

    if not backup_dir.exists() and not candidate_dir.exists():
        if target_dir.exists():
            ok, _, _ = verify_release_dir(target_dir, pub_key_hex)
            return ok
        return False

    target_ok, target_data, target_err = verify_release_dir(target_dir, pub_key_hex)
    backup_ok, backup_data, _ = verify_release_dir(backup_dir, pub_key_hex)
    cand_ok, cand_data, _ = verify_release_dir(candidate_dir, pub_key_hex)

    if target_ok:
        if candidate_dir.exists():
            shutil.rmtree(candidate_dir, ignore_errors=True)
        if backup_dir.exists():
            shutil.rmtree(backup_dir, ignore_errors=True)
        return True

    print(f"[RECOVERY] Target ({target_dir}) natamam və ya zədəlidir ({target_err}). Bərpa araşdırılır...", file=sys.stderr)

    if backup_ok:
        print(f"[RECOVERY] Etibarlı backup (v{backup_data.get('version')}) aşkarlandı, target bərpa olunur...", file=sys.stderr)
        if target_dir.exists():
            shutil.rmtree(target_dir, ignore_errors=True)
        target_dir.mkdir(parents=True, exist_ok=True)
        for item in backup_dir.iterdir():
            if item.is_file():
                shutil.copy2(item, target_dir / item.name)
            elif item.is_dir():
                shutil.copytree(item, target_dir / item.name)
        rec_ok, _, rec_err = verify_release_dir(target_dir, pub_key_hex)
        if not rec_ok:
            raise RuntimeError(f"E_RECOVERY_FROM_BACKUP_FAILED: {rec_err}")
        shutil.rmtree(backup_dir, ignore_errors=True)
        if candidate_dir.exists():
            shutil.rmtree(candidate_dir, ignore_errors=True)
        print(f"[RECOVERY] Target backup-dan uğurla bərpa olundu (v{backup_data.get('version')}).", file=sys.stderr)
        return True

    if cand_ok:
        print(f"[RECOVERY] Etibarlı candidate (v{cand_data.get('version')}) aşkarlandı, target bərpa olunur...", file=sys.stderr)
        if target_dir.exists():
            shutil.rmtree(target_dir, ignore_errors=True)
        candidate_dir.rename(target_dir)
        rec_ok, _, rec_err = verify_release_dir(target_dir, pub_key_hex)
        if not rec_ok:
            raise RuntimeError(f"E_RECOVERY_FROM_CANDIDATE_FAILED: {rec_err}")
        print(f"[RECOVERY] Target candidate-dən uğurla bərpa olundu (v{cand_data.get('version')}).", file=sys.stderr)
        return True

    return False

def commit_staged_release(staging_dir: Path, target_dir: Path, pub_key_hex: str = None, transition_hook = None):
    target_dir = Path(target_dir).resolve()
    staging_dir = Path(staging_dir).resolve()
    backup_dir = target_dir.parent / (target_dir.name + ".backup")
    candidate_dir = target_dir.parent / (target_dir.name + ".candidate")

    # 1. Başlanğıcda bərpa
    recover_release_dir(target_dir, pub_key_hex)

    # 2. Staging yoxlanışı
    stg_ok, _, stg_err = verify_release_dir(staging_dir, pub_key_hex)
    if not stg_ok:
        raise RuntimeError(f"E_COMMIT_STAGING_INVALID: {stg_err}")

    # 3. Candidate hazırlanması
    if candidate_dir.exists():
        shutil.rmtree(candidate_dir, ignore_errors=True)
    shutil.copytree(staging_dir, candidate_dir)

    cand_ok, _, cand_err = verify_release_dir(candidate_dir, pub_key_hex)
    if not cand_ok:
        shutil.rmtree(candidate_dir, ignore_errors=True)
        raise RuntimeError(f"E_COMMIT_CANDIDATE_INVALID: {cand_err}")

    # 4. Target -> Backup keçidi
    target_ok, _, _ = verify_release_dir(target_dir, pub_key_hex)
    if target_ok:
        if backup_dir.exists():
            shutil.rmtree(backup_dir, ignore_errors=True)
        target_dir.rename(backup_dir)
    elif target_dir.exists():
        shutil.rmtree(target_dir, ignore_errors=True)

    if transition_hook:
        transition_hook("after_backup_before_candidate_swap")

    # 5. Candidate -> Target atomik rename
    candidate_dir.rename(target_dir)

    if transition_hook:
        transition_hook("after_candidate_swap_before_backup_cleanup")

    # 6. Komit sonrası təsdiq yoxlaması
    final_ok, _, final_err = verify_release_dir(target_dir, pub_key_hex)
    if not final_ok:
        if backup_dir.exists():
            if target_dir.exists():
                shutil.rmtree(target_dir, ignore_errors=True)
            backup_dir.rename(target_dir)
        raise RuntimeError(f"E_COMMIT_FINAL_VERIFICATION_FAILED: {final_err}")

    # 7. Yalnız target 100% təsdiqləndikdən sonra backup silinir
    if backup_dir.exists():
        shutil.rmtree(backup_dir, ignore_errors=True)
    if candidate_dir.exists():
        shutil.rmtree(candidate_dir, ignore_errors=True)

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

    stage_webview2_loader(Path(DESKTOP_EXE), Path(WEBVIEW2_DLL))
    for exe in [SERVICE_EXE, HELPER_EXE, DESKTOP_EXE]:
        if not os.path.isfile(exe):
            raise RuntimeError(f"Missing build artifact: {exe}")


def stage_webview2_loader(desktop: Path, destination: Path):
    """Cargo leaves the dynamic loader in its build output, not beside the exe."""
    def pe_machine(path):
        with path.open('rb') as stream:
            header = stream.read(64)
            if len(header) < 64 or header[:2] != b'MZ':
                raise RuntimeError('E_INVALID_PE: ' + path.name)
            stream.seek(int.from_bytes(header[60:64], 'little'))
            pe = stream.read(6)
            if pe[:4] != b'PE\0\0' or len(pe) != 6:
                raise RuntimeError('E_INVALID_PE: ' + path.name)
            return int.from_bytes(pe[4:6], 'little')

    machine = pe_machine(desktop)
    architecture = {0x8664: 'x64', 0x14c: 'x86', 0xaa64: 'arm64'}.get(machine)
    if architecture is None:
        raise RuntimeError('E_UNSUPPORTED_DESKTOP_ARCHITECTURE')
    candidates = list((desktop.parent / 'build').glob(
        'webview2-com-sys-*/out/' + architecture + '/WebView2Loader.dll'))
    candidates.sort(key=lambda p: p.stat().st_mtime_ns, reverse=True)
    for source in candidates:
        if pe_machine(source) == machine:
            shutil.copy2(source, destination)
            print('[PASS] WebView2Loader.dll paketlendi: ' + architecture, flush=True)
            return
    raise RuntimeError('E_WEBVIEW2_LOADER_MISSING: Cargo build output-da uyğun DLL tapılmadı.')


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

def step_sign_manifest(staging_dir: Path = None):
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    target_out_dir = Path(PRE_SIGNED_DIR) if staging_dir is None else staging_dir
    print("\n" + "="*60)
    print(" 2/3. SLOT A MANİFESTİ VƏ ED25519 RƏSMİ İMZALAMA")
    print("="*60)

    os.makedirs(target_out_dir, exist_ok=True)
    svc_sha = sha256_file(SERVICE_EXE)
    svc_sz = os.path.getsize(SERVICE_EXE)
    hlp_sha = sha256_file(HELPER_EXE)
    hlp_sz = os.path.getsize(HELPER_EXE)

    manifest_data = {
        "version": RELEASE_VERSION,
        "timestamp": time.time(),
        "min_host_protocol_version": 1,
        "files": [
            {"path": "winkey_service.exe", "sha256": svc_sha, "size": svc_sz},
            {"path": "winkey_helper.exe", "sha256": hlp_sha, "size": hlp_sz},
            {"path": "winkey_desktop.exe", "sha256": sha256_file(DESKTOP_EXE), "size": os.path.getsize(DESKTOP_EXE)},
            {"path": "WebView2Loader.dll", "sha256": sha256_file(WEBVIEW2_DLL), "size": os.path.getsize(WEBVIEW2_DLL)}
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
    manifest_path = os.path.join(target_out_dir, "manifest.json")

    check_signing_key_consistency()
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

    sig_path = os.path.join(target_out_dir, "manifest.sig")
    with open(sig_path, "wb") as f:
        f.write(sig_bytes)

    print(f"  ✓ manifest.json ({os.path.getsize(manifest_path)} bayt)")
    print(f"  ✓ manifest.sig  ({len(sig_bytes)} bayt Ed25519 rəsmi imza)")

def step_build_installer(staging_dir: Path = None):
    print("\n" + "="*60)
    print(" 3/3. TƏK QURAŞDIRICI YARADILMASI (dist/WinKeySetup.exe)")
    print("="*60)

    if not os.path.exists(MAKENSIS_EXE):
        print(f"❌ XƏTA: makensis.exe tapılmadı: {MAKENSIS_EXE}")
        sys.exit(1)

    manifest_src = Path(PRE_SIGNED_DIR) if staging_dir is None else staging_dir
    os.makedirs(DIST_DIR, exist_ok=True)
    pending_setup = str(Path(DIST_DIR) / 'WinKeySetup-building.exe')
    run_cmd([
        MAKENSIS_EXE, "/INPUTCHARSET", "UTF8",
        f'/DMANIFEST_DIR={str(manifest_src)}',
        f'/DOUTPUT_FILE={pending_setup}',
        f'/DPRODUCT_VERSION={RELEASE_VERSION}',
        NSI_SCRIPT
    ], "NSIS ilə WinKeySetup.exe paketlənməsi")
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

def execute_build_pipeline(
    version: str,
    staging_dir: Path = STAGING_PRE_SIGNED_DIR,
    target_dir: Path = Path(PRE_SIGNED_DIR),
    compile_fn = None,
    sign_fn = None,
    installer_fn = None,
    package_fn = None,
    commit_fn = None,
) -> Path:
    if compile_fn is None: compile_fn = step_compile_rust
    if sign_fn is None: sign_fn = step_sign_manifest
    if installer_fn is None: installer_fn = step_build_installer
    if package_fn is None: package_fn = create_update_package
    if commit_fn is None: commit_fn = commit_staged_release
    recover_release_dir(target_dir)

    metadata_backups = {}
    try:
        metadata_backups = sync_project_metadata(version)
        compile_fn()
        sign_fn(staging_dir)
        installer_fn(staging_dir)
        package = package_fn(staging_dir)
        commit_fn(staging_dir, target_dir)
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
        return package
    except (Exception, SystemExit) as e:
        if metadata_backups:
            try:
                restore_project_metadata(metadata_backups)
            except Exception as r_err:
                print(f"[METADATA_RESTORE_ERR] {r_err}", file=sys.stderr)
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
        raise

def main():
    global RELEASE_VERSION
    parser = argparse.ArgumentParser(description='WinKey Pro: build → imzalı paket → Git push → VM auto-deploy. Quraşdırma icra etmir.')
    parser.add_argument('--check', action='store_true', help='Yalnız build tələblərini yoxla')
    parser.add_argument('--local-only', action='store_true', help='Yalnız build et; Git push və VM deploy başlatma')
    parser.add_argument('--push-only', nargs='?', const='latest', metavar='ZIP', help='Hazır paketin Git push mərhələsini build etmədən tamamla; susmaya görə son versiya')
    parser.add_argument('--version', help='Buraxılış versiyası, məsələn 0.1.2. Susmaya görə patch artırılır.')
    parser.add_argument('--publish', metavar='SERVER', help='Build-dən sonra imzalı paketi serverə yüklə və avtomatik yenilənməni başlat')
    args = parser.parse_args()
    from scripts.release_pipeline import preflight_git, push_release
    recover_release_dir(Path(PRE_SIGNED_DIR))
    if args.push_only:
        if args.local_only or args.check:
            raise RuntimeError('--push-only digər build rejimləri ilə birlikdə istifadə edilmir.')
        acquire_build_lock()
        if args.push_only == 'latest':
            packages=[p for p in Path(DIST_DIR).glob('WinKeyUpdate-*.zip') if re.fullmatch(r'WinKeyUpdate-\d+\.\d+\.\d+\.zip',p.name)]
            if not packages:raise RuntimeError('Hazır update ZIP tapılmadı.')
            package=max(packages,key=lambda p:tuple(map(int,p.stem.removeprefix('WinKeyUpdate-').split('.'))))
        else:
            package=Path(args.push_only).resolve()
        push_release(ROOT_DIR,package,resume=True)
        return
    preflight()
    if not args.check:
        acquire_build_lock()
    if not args.local_only:
        preflight_git(ROOT_DIR,fetch=not args.check)
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
    build_started_at = time.perf_counter()
    package = execute_build_pipeline(
        version=RELEASE_VERSION,
        staging_dir=STAGING_PRE_SIGNED_DIR,
        target_dir=Path(PRE_SIGNED_DIR)
    )
    if not args.local_only:
        push_release(ROOT_DIR,package)
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
    total_time = time.perf_counter() - build_started_at
    print(f"\nÜmumi icra müddəti: {total_time:.2f} saniyə.\n")


def create_update_package(staging_dir: Path = None):
    in_dir = Path(PRE_SIGNED_DIR) if staging_dir is None else staging_dir
    recover_release_dir(in_dir)
    pkg_ok, _, pkg_err = verify_release_dir(in_dir)
    if not pkg_ok:
        raise RuntimeError(f"E_PACKAGE_VERIFICATION_FAILED: {pkg_err}")
    manifest = Path(in_dir, 'manifest.json')
    data=json.loads(manifest.read_text(encoding='utf-8'))
    target=Path(DIST_DIR,'WinKeyUpdate-'+data['version']+'.zip')
    temporary=target.with_suffix('.building.zip')
    with zipfile.ZipFile(temporary,'w',zipfile.ZIP_DEFLATED) as package:
        manifest_raw = manifest.read_bytes()
        if b'\r\n' in manifest_raw:
            manifest_raw = manifest_raw.replace(b'\r\n', b'\n')
        package.writestr('manifest.json', manifest_raw)
        package.write(Path(in_dir,'manifest.sig'),'manifest.sig')
        for entry in data['files']:
            source=Path(DESKTOP_EXE) if entry['path']=='winkey_desktop.exe' else (Path(WEBVIEW2_DLL) if entry['path']=='WebView2Loader.dll' else Path(SERVICE_EXE).parent/entry['path'])
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
    finally:
        if _BUILD_LOCK is not None:
            _BUILD_LOCK.close()

# Startup recovery check for baseline pre_signed_slot_a
try:
    p_backup = Path(PRE_SIGNED_DIR + ".backup")
    p_cand = Path(PRE_SIGNED_DIR + ".candidate")
    if p_backup.exists() or p_cand.exists():
        recover_release_dir(Path(PRE_SIGNED_DIR))
except Exception:
    pass
