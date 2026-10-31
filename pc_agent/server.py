"""
WinKey Server - PC Agent & Mobile Unlock Gateway
Powered by RustDesk SAS Engine & FastAPI
"""
import os
import json
import socket
import qrcode
from pathlib import Path
from collections import deque
import hashlib
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import sys
import io

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "server.log"

# Fix Windows console encoding & prevent headless service pipe hang
try:
    if not sys.stdout or not hasattr(sys.stdout, 'isatty') or not sys.stdout.isatty():
        log_stream = open(LOG_FILE, "a", encoding="utf-8", buffering=1)
        sys.stdout = log_stream
        sys.stderr = log_stream
    else:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

try:
    from . import unlock_engine
except ImportError:
    import unlock_engine

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

# Load Configuration
def load_config():
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "port": 8888,
        "security_token": "winkey_secret_2026",
        "pin": "",
        "auto_type_pin": False,
        "vibration": True
    }

def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)

config = load_config()

# Helper: Detect LAN IP addresses
def get_ip_addresses():
    ips = []
    try:
        hostname = socket.gethostname()
        for _, _, addrs in [socket.gethostbyname_ex(hostname)]:
            for ip in addrs:
                if not ip.startswith("127.") and not ip.startswith("169.254."):
                    ips.append(ip)
    except Exception:
        pass
    
    # Prioritize 192.168.x.x
    ips.sort(key=lambda x: (not x.startswith("192.168."), x))
    return ips if ips else ["127.0.0.1"]

app = FastAPI(title="WinKey Mobile Gateway")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

class ActionRequest(BaseModel):
    token: str = ""
    pin: str = ""

class ConfigRequest(BaseModel):
    token: str = ""
    pin: str = ""
    auto_type_pin: bool = True

def verify_token(req_token: str):
    server_token = config.get("security_token", "winkey_secret_2026")
    if server_token and req_token != server_token:
        raise HTTPException(status_code=403, detail="Yanlış təhlükəsizlik tokeni")

@app.get("/", response_class=HTMLResponse)
async def serve_mobile_app():
    index_file = TEMPLATES_DIR / "index.html"
    if index_file.exists():
        with open(index_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>WinKey UI Tapılmadı</h1>")

@app.get("/api/status")
async def get_status(token: str = ""):
    verify_token(token)
    lock_evidence = unlock_engine.get_lock_state()
    locked = lock_evidence["locked"]
    hostname = socket.gethostname()
    saved_pin = config.get("pin", "")
    return {
        "online": True,
        "locked": locked,
        "lock_evidence": lock_evidence,
        "hostname": hostname,
        "has_pin": bool(saved_pin),
        "diagnostic_build": unlock_engine.VERSION,
        "server_pid": os.getpid(),
        "engine_sha256": hashlib.sha256(Path(unlock_engine.__file__).read_bytes()).hexdigest()[:12],
        "pin": saved_pin
    }

@app.post("/api/unlock")
def trigger_unlock(req: ActionRequest, request: Request):
    verify_token(req.token)
    
    # Priority: req.pin > config["pin"]
    pin_to_use = req.pin if req.pin else config.get("pin", "")
    res = unlock_engine.unlock_workstation(pin_or_password=pin_to_use, request_info={
        "client": request.client.host if request.client else "unknown",
        "pin_source": "request" if req.pin else ("saved_config" if pin_to_use else "missing"),
        "credential_present": bool(pin_to_use), "server_pid": os.getpid(),
    })
    res["pin_source"] = "request" if req.pin else ("saved_config" if pin_to_use else "missing")
    return res

@app.post("/api/lock")
async def trigger_lock(req: ActionRequest):
    verify_token(req.token)
    res = unlock_engine.lock_workstation()
    return {"success": res, "locked": True}

@app.post("/api/wake")
async def trigger_wake(req: ActionRequest):
    verify_token(req.token)
    res = unlock_engine.wake_screen()
    return {"success": res}

@app.post("/api/config")
async def update_settings(req: ConfigRequest):
    verify_token(req.token)
    config["pin"] = req.pin
    config["auto_type_pin"] = bool(req.pin)
    save_config(config)
    return {"success": True, "has_pin": bool(config.get("pin"))}

@app.get("/api/logs")
async def get_unlock_logs(token: str = "", attempt_id: str = ""):
    verify_token(token)
    log_file = unlock_engine.LOG_FILE
    if attempt_id:
        import re
        if not re.fullmatch(r"[a-f0-9]{12}", attempt_id):
            raise HTTPException(status_code=400, detail="Yanlış cəhd nömrəsi")
        log_file = BASE_DIR / "diagnostic_logs" / (attempt_id + ".log")
    if os.path.exists(log_file):
        try:
            with open(log_file, "r", encoding="utf-8") as f:
                lines = list(deque(f, maxlen=500))
                return {"logs": lines, "build": unlock_engine.VERSION, "attempt_id": attempt_id}
        except Exception as e:
            return {"logs": [f"Loq oxuma xətası: {e}"]}
    return {"logs": ["Hələ heç bir loq qeyd edilməyib."]}

@app.get("/api/qr")
async def get_qr_image():
    qr_path = STATIC_DIR / "qr_code.png"
    if qr_path.exists():
        return FileResponse(str(qr_path))
    raise HTTPException(status_code=404, detail="QR kod tapılmadı")

def generate_qr_assets(primary_url: str):
    """Telefonda skan etmək üçün həm PNG, həm də terminal ASCII QR yaradır."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=2,
    )
    qr.add_data(primary_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(str(STATIC_DIR / "qr_code.png"))

def print_banner(primary_url: str, all_ips: list, port: int):
    token = config.get("security_token", "winkey_secret_2026")
    print("\n" + "="*60)
    print("        [***] WINKEY // MOBIL KILID ACMA SERVERI [***]")
    print("="*60)
    print(f"[*] Port: {port}")
    print(f"[*] Tehlukesizlik Tokeni: {token}")
    print("\n[+] TELEFONUNUZDAN BU UNVANI ACIN (Eyni Wi-Fi sebekesinde):")
    print(f"    --> {primary_url}")
    if len(all_ips) > 1:
        print("\n[+] Diger sebeke unvanlari:")
        for ip in all_ips[1:]:
            print(f"    - http://{ip}:{port}")
    print("\n[+] Telefonda brauzerde acdiqdan sonra 'Ana ekrana elave et'")
    print("    duymesine basaraq mobil tetbiq kimi qurasdira bilersiniz!")
    print("="*60 + "\n")

    # Display terminal QR code only if running in an interactive terminal
    try:
        if sys.stdout and hasattr(sys.stdout, 'isatty') and sys.stdout.isatty():
            qr = qrcode.QRCode()
            qr.add_data(primary_url)
            qr.print_ascii(invert=True)
    except Exception:
        pass

if __name__ == "__main__":
    import uvicorn
    ips = get_ip_addresses()
    primary_ip = ips[0]
    port = config.get("port", 8888)
    primary_url = f"http://{primary_ip}:{port}"

    generate_qr_assets(primary_url)
    print_banner(primary_url, ips, port)

    # Windows-da asan giriş üçün 0.0.0.0 üzərində dinləyirik
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
