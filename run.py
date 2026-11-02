"""
WinKey Pro — Sürətli Tərtibatsız (No-Build) Dev & Canlı Sınaq Başladıcı
Bu skript:
1. SQLite bazasında avtomatik yerli cihazı və aktiv cütləşmə kodunu qeydiyyatdan keçirir.
2. Gateway Serveri (8788 portu) arxa planda başladır.
3. Həqiqi oxunabilən QR kod təqdim edir.
4. Brauzerdə Dev UI interfeysini açır.
5. Telefon "Kompüteri Kilidlə" basdıqda kompüterin ekranını kilidləyir!
"""

import os
import sys
import time
import socket
import sqlite3
import secrets
import hashlib
import subprocess
import webbrowser
import urllib.parse
import io
try:
    import qrcode
except ModuleNotFoundError:
    qrcode = None
from http.server import SimpleHTTPRequestHandler, HTTPServer
import threading
from pathlib import Path


def tauri_source_snapshot(root=None):
    """Watch source inputs only; target/cache/runtime files cannot cause rebuild loops."""
    base = Path(root or Path(__file__).resolve().parent) / 'apps' / 'desktop_tauri'
    paths = []
    for directory in (base / 'ui', base / 'src-tauri' / 'src', base / 'src-tauri' / 'capabilities'):
        if directory.exists():
            paths.extend(p for p in directory.rglob('*') if p.is_file() and p.suffix in {'.rs', '.js', '.css', '.html', '.json', '.svg'})
    paths.extend(base / 'src-tauri' / name for name in ('Cargo.toml', 'Cargo.lock', 'build.rs', 'tauri.conf.json'))
    result = {}
    for path in paths:
        try:
            stat = path.stat()
            result[str(path)] = (stat.st_mtime_ns, stat.st_size)
        except FileNotFoundError:
            pass
    return result


def stop_owned_dev_process(proc):
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def dev_client_environment(lan_ip, port, base_env=None):
    env = dict(os.environ if base_env is None else base_env)
    env['WINKEY_GATEWAY_ORIGIN'] = f'http://{lan_ip}:{port}'
    env['WINKEY_DEV_GATEWAY_ORIGIN'] = f'http://{lan_ip}:{port}'
    # Account passwords stay on this PC's loopback interface in debug mode.
    env['WINKEY_DEV_ACCOUNT_ORIGIN'] = f'http://127.0.0.1:{port}'
    return env


def is_ipc_pipe_active(pipe_name=r"\\.\pipe\WinKey_Service_IPC"):
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        res = kernel32.WaitNamedPipeW(pipe_name, 0)
        err = kernel32.GetLastError()
        return res != 0 or err in (0, 121, 5, 231)
    except Exception:
        return False

def check_run_dependencies():
    import importlib.util
    missing = [name for name in ('qrcode', 'PIL', 'cryptography') if importlib.util.find_spec(name) is None]
    if missing:
        print('[XƏTA] Çatışmayan paketlər: ' + ', '.join(missing))
        print(f'Quraşdırmaq üçün: "{sys.executable}" -m pip install -r requirements-dev.txt')
        return False
    print('[PASS] Run üçün Python paketləri hazırdır.')
    return True
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
UI_DIR = os.path.join(ROOT_DIR, "apps", "desktop_tauri", "ui")
DB_PATH = os.path.join(ROOT_DIR, ".dev-runtime", "data", "winkey_prod.db")
GATEWAY_SCRIPT = os.path.join(ROOT_DIR, "deploy", "gateway_production_server.py")
GATEWAY_PORT = 8788
DEV_UI_PORT = 3000

CURRENT_PAIRING = {
    "device_id": "dev_local_pc",
    "pair_code": "",
    "pairing_url": "",
    "lan_ip": "127.0.0.1"
}

def get_lan_ip():
    try:
        ips = socket.gethostbyname_ex(socket.gethostname())[2]
        for ip in ips:
            if ip.startswith("192.168.0.") or ip.startswith("192.168.1."):
                return ip
        for ip in ips:
            if ip.startswith("192.168.") and not ip.endswith(".1"):
                return ip
        for ip in ips:
            if not ip.startswith("127.") and not ip.startswith("169.254."):
                return ip
    except Exception:
        pass
    return "192.168.0.101"

def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0

def setup_dev_device_and_pairing(lan_ip):
    """Serverin bazasında yerli kompüteri aktivləşdirir və rəsmi cütləşmə kodu açır."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # 1. Cihazı aktivləşdir
    dev_id = "dev_local_pc"
    hostname = socket.gethostname()
    token = "dev_secret_token_12345"
    sec_hash = hashlib.sha256(token.encode()).hexdigest()
    now = time.time()

    conn.execute("""
        INSERT OR REPLACE INTO devices 
        (device_id, computer_name, public_key_hex, device_secret_hash, status, created_at, last_seen_at, locked, pin_ready, owner_approved)
        VALUES (?, ?, 'pubkey_hex_demo', ?, 'ACTIVE', ?, ?, 0, 1, 1)
    """, (dev_id, hostname, sec_hash, now, now))

    # 2. Rəsmi Cütləşmə Kodu (1 saat etibarlı)
    code = "WK-" + secrets.token_hex(3).upper()
    expires_at = now + 3600
    conn.execute("""
        INSERT OR REPLACE INTO pairing_requests 
        (pair_code, device_id, challenge_hex, status, expires_at, created_at)
        VALUES (?, ?, 'chal_hex', 'PENDING', ?, ?)
    """, (code, dev_id, expires_at, now))
    conn.commit()
    conn.close()

    pairing_url = f"http://{lan_ip}:{GATEWAY_PORT}/remote?device={dev_id}&code={code}"
    CURRENT_PAIRING["device_id"] = dev_id
    CURRENT_PAIRING["pair_code"] = code
    CURRENT_PAIRING["pairing_url"] = pairing_url
    CURRENT_PAIRING["lan_ip"] = lan_ip

    print(f"[BAZA HAZIRDIR] Cihaz: {dev_id} ({hostname}) | Cütləşmə Kodu: {code}")
    print(f"[MOBİL LİNK] {pairing_url}")
    return pairing_url, code

def start_gateway_server():
    if is_port_in_use(GATEWAY_PORT):
        print(f"[OK] Gateway Server artıq {GATEWAY_PORT} portunda aktivdir.")
        return None
    
    print(f"[...] Gateway Server {GATEWAY_PORT} portunda işə salınır...")
    env = os.environ.copy()
    env["GATEWAY_HOST"] = "0.0.0.0"
    # Local developer admin session: never print the key or put it in a QR.
    admin_secret = secrets.token_hex(32)
    env["WINKEY_ADMIN_SECRET"] = admin_secret
    proc = subprocess.Popen(
        [sys.executable, GATEWAY_SCRIPT, str(GATEWAY_PORT), DB_PATH],
        cwd=ROOT_DIR,
        env=env,
        # Inherit the Run terminal: gateway errors must be visible.
    )
    time.sleep(1.0)
    if is_port_in_use(GATEWAY_PORT):
        print(f"[PASS] Gateway Server işə düşdü (Port {GATEWAY_PORT}).")
        print(f"[ADMIN] Sahib paneli: http://127.0.0.1:{GATEWAY_PORT}/admin")
        webbrowser.open(f"http://127.0.0.1:{GATEWAY_PORT}/admin#dev-admin={admin_secret}")
    return proc

class DevUIHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=UI_DIR, **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        
        # 1. Real QR Kod PNG Şəkli
        if parsed.path == "/api/qr":
            url_to_encode = CURRENT_PAIRING["pairing_url"]
            try:
                img = qrcode.make(url_to_encode)
                buf = io.BytesIO()
                try:
                    img.save(buf)
                except TypeError:
                    img.save(buf, "PNG")
                raw = buf.getvalue()
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self.wfile.write(raw)
                return
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(e).encode("utf-8"))
                return

        # 2. Cütləşmə Məlumatları API
        if parsed.path == "/api/pairing":
            import json
            data = {
                "device_id": CURRENT_PAIRING["device_id"],
                "computer_name": socket.gethostname(),
                "pair_code": CURRENT_PAIRING["pair_code"],
                "pairing_url": CURRENT_PAIRING["pairing_url"],
                "qr_image_url": "/api/qr",
                "expires_at": int(time.time()) + 3600
            }
            raw = json.dumps(data).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(raw)
            return

        return super().do_GET()

    def log_message(self, format, *args):
        pass

def start_ui_server():
    server = HTTPServer(("127.0.0.1", DEV_UI_PORT), DevUIHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    return server

def lock_command_poller():
    """Serverə gələn kilid əmrlərini dinləyir və kompüteri kilidləyir."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    while True:
        try:
            row = conn.execute("SELECT command_id, action FROM device_commands WHERE device_id = 'dev_local_pc' AND status = 'PENDING'").fetchone()
            if row:
                cmd_id = row["command_id"]
                action = row["action"]
                print(f"\n[MOBİL ƏMR GƏLDİ] Hərəkət: {action.upper()} (Command ID: {cmd_id})")
                if action == "lock":
                    print("[ACTION] Windows Ekranı Kilidlənir...")
                    os.system("rundll32.exe user32.dll,LockWorkStation")
                elif action == "unlock":
                    print("[ACTION] Kilidi aç əmri qəbul edildi!")
                
                conn.execute("UPDATE device_commands SET status = 'EXECUTED' WHERE command_id = ?", (cmd_id,))
                conn.commit()
        except Exception:
            pass
        time.sleep(1)

def main():
    global GATEWAY_PORT
    if '--help' in sys.argv or '-h' in sys.argv:
        print('python run.py             — native dev proqramını başlat')
        print('python run.py --check     — asılılıqları yoxla, heç nə başlatma')
        print('python run.py --browser-only — yalnız brauzer önizləməsi')
        return 0
    if not check_run_dependencies():
        return 1
    if '--check' in sys.argv:
        return 0
    print("==================================================================")

    # Always compile the current UI/Rust sources before launching native dev.
    if "--browser-only" not in sys.argv:
        manifest = os.path.join(ROOT_DIR, "apps", "desktop_tauri", "src-tauri", "Cargo.toml")
        debug_exe = os.path.join(ROOT_DIR, "apps", "desktop_tauri", "src-tauri", "target", "debug", "winkey_desktop.exe")
        stop_env = os.environ.copy()
        stop_env["WINKEY_DEV_EXE_TO_REBUILD"] = os.path.abspath(debug_exe)
        stop_script = r"""
$ErrorActionPreference = 'Stop'
$targetExe = [System.IO.Path]::GetFullPath($env:WINKEY_DEV_EXE_TO_REBUILD)
foreach ($devProcess in @(Get-Process -Name winkey_desktop -ErrorAction SilentlyContinue)) {
    if ($devProcess.Path -and [string]::Equals([System.IO.Path]::GetFullPath($devProcess.Path), $targetExe, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Host ('[DEV] Əvvəlki debug pəncərəsi bağlanır (PID ' + $devProcess.Id + ')')
        try {
            $devProcess.Kill()
            if (-not $devProcess.WaitForExit(10000)) { throw 'Dev prosesi vaxtinda baglanmadi.' }
        } catch {
            if (-not $devProcess.HasExited) { Write-Error $_; exit 1 }
        }
    }
}
exit 0
"""
        try:
            stopped = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", stop_script],
                cwd=ROOT_DIR, env=stop_env, timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            print("[XƏTA] Əvvəlki dev prosesini bağlamaq alınmadı.")
            return 1
        if stopped.returncode != 0:
            print("[XƏTA] Əvvəlki dev prosesini bağlamaq alınmadı.")
            return stopped.returncode
        print("[BUILD] Tauri dev rejimi compile olunur...", flush=True)
        try:
            result = subprocess.run(
                ["cargo", "build", "--manifest-path", manifest, "--no-default-features"],
                cwd=ROOT_DIR,
            )
        except FileNotFoundError:
            print("[XƏTA] Cargo tapılmadı. Rust alətlərinin PATH-də olduğunu yoxlayın.")
            return 1
        if result.returncode != 0:
            print("[XƏTA] Compile alınmadı. Açıq WinKey varsa tray-dən Çıxış edin və yenidən Run basın.")
            return result.returncode
    print("      WinKey Pro — Sürətli Dev Sınaq Rejimi (Canlı Mobil Cütləşmə) ")
    print("==================================================================")
    
    lan_ip = get_lan_ip()
    if is_port_in_use(GATEWAY_PORT):
        # Never silently reuse an orphan server whose logs/code are unknown.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("0.0.0.0", 0))
            GATEWAY_PORT = probe.getsockname()[1]
        print(f"[DEV] Köhnə gateway portu məşğuldur; yeni loglanan gateway portu: {GATEWAY_PORT}")
    pairing_url, pair_code = "Native proqramda yaradılır", "Server təsdiqindən sonra"

    # 1. Gateway Serveri Başlat
    gw_proc = start_gateway_server()

    # 2. Əmr Dinləyicisini Arxa Planda Başlat (Lock üçün)
    # Native service owns commands; do not use the old demo DB lock poller.

    # 3. Dev UI Veb Serverini Başlat (Köməkçi Veb fallback üçün)
    ui_server = start_ui_server()
    print(f"[PASS] Dev HTTP Server aktivdir: http://127.0.0.1:{DEV_UI_PORT}")

    # 4. Əsas: Native Tauri Masaüstü Pəncərəsini Açmaq
    debug_exe = os.path.join(ROOT_DIR, "apps", "desktop_tauri", "src-tauri", "target", "debug", "winkey_desktop.exe")
    tauri_exe = debug_exe

    tauri_proc = None
    worker_proc = None
    if tauri_exe and "--browser-only" not in sys.argv:
        print(f"[...] Yeni compile olunmuş Tauri dev pəncərəsi açılır: {os.path.basename(tauri_exe)}")

        env = dev_client_environment(lan_ip, GATEWAY_PORT)
        if not is_ipc_pipe_active():
            worker_exe = os.path.join(ROOT_DIR, "apps", "winkey_service", "target", "release", "winkey_service.exe")
            if os.path.isfile(worker_exe):
                dev_data = os.path.join(ROOT_DIR, ".dev-runtime")
                os.makedirs(dev_data, exist_ok=True)
                sid = subprocess.check_output([
                    "powershell.exe", "-NoProfile", "-Command",
                    "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"
                ], text=True).strip()
                with open(os.path.join(dev_data, "owner.sid"), "w", encoding="utf-8") as f:
                    f.write(sid)
                env["WINKEY_DATA_DIR"] = dev_data
                worker_proc = subprocess.Popen([worker_exe, "--worker", "--data-dir", dev_data], cwd=ROOT_DIR, env=env)
                env["WINKEY_TRUSTED_SERVICE_PID"] = str(worker_proc.pid)
                time.sleep(0.6)
                print(f"[DEV_WORKER] PID={worker_proc.pid}. Sistem xidməti qurulmayıb; dev worker başladıldı. Secure Desktop unlock üçün SYSTEM xidməti tələb olunur.")
            else:
                print("[E_WORKER_MISSING] PC əmrlərini qəbul edən xidmət binarı yoxdur.")
        else:
            print("[INFO] WinKeyService fon xidməti artıq aktivdir (IPC pipe mövcuddur). Əlavə dev worker başladılmadı.")
        tauri_proc = subprocess.Popen([tauri_exe], cwd=ROOT_DIR, env=env)
        print(f"[PASS] Native Tauri Masaüstü Pəncərəsi uğurla başladıldı (PID: {tauri_proc.pid})!")
    else:
        # Fallback: Yalnız binar tapılmadıqda və ya --browser-only göstərildikdə brauzer açılır
        ui_url = f"http://127.0.0.1:{DEV_UI_PORT}"
        print(f"[...] Brauzer açılır: {ui_url}")
        webbrowser.open(ui_url)

    print("\n------------------------------------------------------------------")
    print("✓ WinKey Pro Tauri Masaüstü Pəncərəsi aktivdir!")
    print(f"  - Kompüter: {socket.gethostname()} ({lan_ip})")
    print(f"  - Mobil Cütləşmə Kodu: {pair_code}")
    print(f"  - Mobil URL: {pairing_url}")
    print("  - Telefonda açılan səhifədən 'Kompüteri Kilidlə' basanda kompüter dərhal kilidlənəcək.")
    print("Dayandırmaq üçün bu pəncərədə Ctrl+C sıxın və ya Tauri-ni bağlayın.")
    print("------------------------------------------------------------------")

    watch_native = '--browser-only' not in sys.argv
    watched = tauri_source_snapshot()
    changed_at = None
    if watch_native:
        print('[WATCH] UI/Rust dəyişiklikləri avtomatik compile ediləcək. Dayandırmaq: Ctrl+C.', flush=True)
    try:
        while True:
            if watch_native:
                current = tauri_source_snapshot()
                if current != watched:
                    watched = current
                    changed_at = time.monotonic()
                if changed_at is not None and time.monotonic() - changed_at >= 0.7:
                    changed_at = None
                    print('[WATCH] Dəyişiklik tapıldı. Tauri yenidən compile olunur; gateway/admin açıq qalır.', flush=True)
                    stop_owned_dev_process(tauri_proc)
                    tauri_proc = None
                    try:
                        result = subprocess.run(
                            ['cargo', 'build', '--manifest-path', manifest, '--no-default-features'],
                            cwd=ROOT_DIR,
                        )
                        if result.returncode == 0:
                            tauri_proc = subprocess.Popen([tauri_exe], cwd=ROOT_DIR, env=env)
                            print(f'[WATCH] Yeni Tauri açıldı: PID={tauri_proc.pid}', flush=True)
                        else:
                            print('[WATCH] Compile xətası. Faylı düzəldib saxla; avtomatik yenidən cəhd ediləcək.', flush=True)
                    except OSError as error:
                        print(f'[WATCH] Build/start xətası: {error}', flush=True)
                    # Do not reset the snapshot here: edits during compilation must trigger another build.
            if tauri_proc and tauri_proc.poll() is not None:
                code = tauri_proc.returncode
                if code == 0:
                    print("[DEV] UI prosesi çıxdı və ya açıq pəncərəyə ötürdü. Gateway/admin işləməyə davam edir; dayandırmaq üçün Ctrl+C.")
                    tauri_proc = None
                else:
                    print(f"[DEV] UI xətayla dayandı: exit={code}. Gateway/admin diaqnostika üçün açıq qalır.")
                    tauri_proc = None
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nDev server dayandırıldı.")
    finally:
        stop_owned_dev_process(tauri_proc)
        ui_server.shutdown()
        if worker_proc and worker_proc.poll() is None:
            worker_proc.terminate()
            try:
                worker_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                worker_proc.kill()
                worker_proc.wait()
        if gw_proc and gw_proc.poll() is None:
            gw_proc.terminate()
            try:
                gw_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                gw_proc.kill()
                gw_proc.wait()

if __name__ == "__main__":
    sys.exit(main())
