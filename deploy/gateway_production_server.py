"""
WinKey Pro — Production Gateway & Multi-Tenant Backend Server
Spesifikasiya: plan/GEMINI_FINAL_ALL_REMAINING.md və plan/GEMINI_FINAL_BATCH_REVISION.md

Təhlükəsizlik Zəmanətləri:
1. Strict Public Key & Cryptographic Nonce/Proof Verification (/agent/register)
2. One-Use Atomic Pairing with Anti-Replay (/pair) — Naməlum kod qətiyyən qəbul olunmur!
3. Authenticated Agent Polling & State Ownership (/agent/poll, /agent/result)
4. Multi-Tenant IDOR Qoruması & Zero-PIN Şəbəkə Qadağası
5. Dinamik / Mühit Əsaslı Admin Secret (No Hardcoded Secrets)
6. Zəngin Avant-Garde Dark/Emerald Mobil PWA İnterfeysi
"""

import os
import sys
import json
import time
import sqlite3
import secrets
import hashlib
from typing import Dict, Any, Optional
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.primitives.asymmetric import ed25519

# Dinamik Admin Secret — heç vaxt hardcode edilmir!
_RUNTIME_ADMIN_SECRET = secrets.token_hex(32)
ADMIN_SECRET = _RUNTIME_ADMIN_SECRET

def get_admin_secret() -> str:
    return os.environ.get("WINKEY_ADMIN_SECRET") or ADMIN_SECRET

# Real Update Delivery Repository Qovluğu
UPDATES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "pre_signed_slot_a"))

def get_updates_dir() -> str:
    return os.environ.get("WINKEY_UPDATES_DIR") or UPDATES_DIR

class ProductionDatabase:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self.get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    device_id TEXT PRIMARY KEY,
                    computer_name TEXT NOT NULL,
                    public_key_hex TEXT NOT NULL,
                    device_secret_hash TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    created_at REAL NOT NULL,
                    last_seen_at REAL NOT NULL,
                    locked INTEGER DEFAULT 0,
                    pin_ready INTEGER DEFAULT 0,
                    owner_approved INTEGER DEFAULT 1
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS challenges (
                    nonce TEXT PRIMARY KEY,
                    purpose TEXT NOT NULL,
                    device_id TEXT,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    used INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS pairing_requests (
                    pair_code TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    challenge_hex TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    expires_at REAL NOT NULL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS mobile_sessions (
                    session_token TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    scope TEXT NOT NULL DEFAULT 'mobile_remote',
                    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS commands (
                    command_id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at REAL NOT NULL,
                    completed_at REAL,
                    result_status TEXT,
                    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS telemetry_events (
                    event_id TEXT PRIMARY KEY,
                    install_run_id TEXT,
                    device_id TEXT,
                    component TEXT NOT NULL,
                    version TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    error_code TEXT,
                    duration_ms INTEGER,
                    local_time REAL,
                    received_at REAL NOT NULL
                )
            """)
            conn.commit()

class GatewayHandler(BaseHTTPRequestHandler):
    db: ProductionDatabase = None

    def log_message(self, format, *args):
        # Do not print raw request URLs: QR secrets can be in the query.
        pass

    def _set_security_headers(self, content_type="application/json"):
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Owner-Admin-Secret")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def do_OPTIONS(self):
        self.send_response(204)
        self._set_security_headers()
        self.end_headers()

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def _send_json(self, status: int, data: Dict[str, Any]):
        print(f"[GATEWAY] {self.command if hasattr(self, 'command') else 'REQUEST'} "
              f"{urlparse(self.path).path} HTTP={status} "
              f"code={data.get('error', 'OK')}", flush=True)
        if status >= 400:
            self._record_incident(urlparse(self.path).path, data.get('error', f'HTTP_{status}'))
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self._set_security_headers("application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _record_incident(self, stage, code, device_id=None):
        # Server-owned allowlisted event. Never store request bodies/QRs/tokens/PINs.
        if not self.db:
            return
        try:
            with self.db.get_conn() as conn:
                conn.execute(
                    "INSERT INTO telemetry_events (event_id, device_id, component, version, stage, event_type, severity, error_code, local_time, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    ('evt_' + secrets.token_hex(12), device_id, 'gateway', '0.1.0', stage,
                     'incident', 'ERROR', str(code)[:120], time.time(), time.time()))
                conn.commit()
        except Exception:
            print('[DIAGNOSTICS] E_INCIDENT_PERSIST_FAILED', flush=True)

    def _get_bearer_token(self) -> Optional[str]:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        return None

    def _authenticate_agent(self, conn, device_id: str) -> bool:
        """Agent Bearer token vasitəsilə cihazın həqiqi sahibi olduğunu təsdiqləyir."""
        token = self._get_bearer_token()
        if not token:
            return False
        sec_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        row = conn.execute("SELECT device_id FROM devices WHERE device_secret_hash = ? AND status = 'ACTIVE'", (sec_hash,)).fetchone()
        return bool(row and row["device_id"] == device_id)

    def do_GET(self):
        if urlparse(self.path).path in ('/remote', '/mobile'):
            print(f"[GATEWAY] phone opened {urlparse(self.path).path} (QR query redacted)", flush=True)
        url = urlparse(self.path)
        path = url.path.rstrip("/")

        # 1. Zəngin Avant-Garde Mobil Web Remote və PWA İnterfeysi
        if path in ("/mobile", "/remote", ""):
            self.send_response(200)
            self._set_security_headers("text/html; charset=utf-8")
            html = """<!DOCTYPE html>
<html lang="az">
<head>
    <meta charset="utf-8">
    <title>WinKey Pro — Mobil İdarəetmə</title>
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: #0f1211; color: #e6ede8; display: flex; justify-content: center; min-height: 100vh; padding: 20px; }
        .app-container { width: 100%; max-width: 420px; display: flex; flex-direction: column; gap: 16px; }
        .header { display: flex; justify-content: space-between; align-items: center; padding: 12px 0; border-bottom: 1px solid #1f2723; }
        .logo { font-size: 1.2rem; font-weight: 700; color: #c8f279; letter-spacing: -0.5px; }
        .badge { font-size: 0.75rem; padding: 4px 8px; border-radius: 6px; font-weight: 600; text-transform: uppercase; }
        .badge-online { background: rgba(200, 242, 121, 0.15); color: #c8f279; border: 1px solid rgba(200, 242, 121, 0.3); }
        .badge-offline { background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); }
        .card { background: #161c19; border: 1px solid #222b26; border-radius: 14px; padding: 18px; display: flex; flex-direction: column; gap: 12px; }
        .device-info { display: flex; flex-direction: column; gap: 4px; }
        .device-name { font-size: 1.4rem; font-weight: 700; color: #fff; }
        .device-sub { font-size: 0.85rem; color: #8e9e95; }
        .btn-group { display: flex; flex-direction: column; gap: 10px; margin-top: 8px; }
        .btn { padding: 14px; border-radius: 10px; font-size: 1rem; font-weight: 600; cursor: pointer; border: none; transition: all 0.15s ease; text-align: center; }
        .btn-unlock { background: #c8f279; color: #0f1211; }
        .btn-unlock:active { background: #b2db63; transform: scale(0.98); }
        .btn-lock { background: #222c27; color: #e6ede8; border: 1px solid #33423b; }
        .btn-lock:active { background: #2b3832; transform: scale(0.98); }
        .btn-revoke { background: transparent; color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); font-size: 0.85rem; padding: 10px; margin-top: 6px; }
        .btn:disabled { opacity: 0.4; cursor: not-allowed; }
        .status-box { font-size: 0.85rem; padding: 12px; border-radius: 8px; background: #101412; border: 1px solid #1c2420; color: #8e9e95; word-break: break-all; min-height: 44px; display: flex; align-items: center; }
        .notice { font-size: 0.75rem; color: #627269; text-align: center; line-height: 1.4; padding: 8px; }
        .spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid rgba(200,242,121,0.3); border-radius: 50%; border-top-color: #c8f279; animation: spin 0.8s linear infinite; margin-right: 8px; }
        @keyframes spin { to { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="app-container">
        <div class="header">
            <div class="logo">WinKey Mobile Remote</div>
            <div id="status-badge" class="badge badge-online">Onlayn</div>
        </div>

        <div class="card">
            <div class="device-info">
                <div id="dev-name" class="device-name">PC Qoşulur...</div>
                <div id="dev-id" class="device-sub">Cihaz ID: —</div>
            </div>

            <div class="btn-group">
                <button id="btn-unlock" class="btn btn-unlock" onclick="sendCommand('unlock')">Kilidi Aç</button>
                <button id="btn-lock" class="btn btn-lock" onclick="sendCommand('lock')">Kompüteri Kilidlə</button>
            </div>

            <div id="action-status" class="status-box">Sistem hazırdır. Əməliyyat gözlənilir.</div>
            <button id="btn-revoke" class="btn btn-revoke" onclick="revokeDevice()">Bağlantını Kəs (Revoke)</button>
        </div>

        <div class="notice">
            Qorunan Zəncir: Telefon yalnız kriptoqrafik əmr siqnalı göndərir. Windows PIN heç vaxt serverə və ya şəbəkəyə çıxmır; yalnız PC-nin təhlükəsiz DPAPI anbarında saxlanılır.
        </div>
    </div>

    <script>
        const urlParams = new URLSearchParams(window.location.search);
        let targetDevice = urlParams.get('device') || localStorage.getItem('winkey_dev_id') || '';
        let pairCode = urlParams.get('code') || '';
        let authToken = localStorage.getItem('winkey_token') || '';

        const devNameEl = document.getElementById('dev-name');
        const devIdEl = document.getElementById('dev-id');
        const badgeEl = document.getElementById('status-badge');
        const statusBox = document.getElementById('action-status');

        async function init() {
            if (pairCode) {
                statusBox.innerHTML = '<span class="spinner"></span>QR cütləşmə kodu göndərilir...';
                try {
                    const r = await fetch('/pair', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({pair_code: pairCode})
                    });
                    const res = await r.json();
                    if (r.ok && res.session_token) {
                        authToken = res.session_token;
                        targetDevice = res.device_id;
                        localStorage.setItem('winkey_token', authToken);
                        localStorage.setItem('winkey_dev_id', targetDevice);
                        if (window.history.replaceState) {
                            window.history.replaceState({}, document.title, window.location.pathname);
                        }
                        statusBox.textContent = 'Cütləşmə uğurla tamamlandı!';
                    } else {
                        statusBox.textContent = 'Cütləşmə xətası: ' + (res.message || res.error);
                    }
                } catch(e) {
                    statusBox.textContent = 'Şəbəkə xətası: ' + e;
                }
            }
            if (targetDevice) {
                devIdEl.textContent = 'Cihaz ID: ' + targetDevice;
                pollStatus();
                setInterval(pollStatus, 3000);
            }
        }

        async function pollStatus() {
            if (!authToken || !targetDevice) return;
            try {
                const r = await fetch('/devices/' + encodeURIComponent(targetDevice) + '/status', {
                    headers: {'Authorization': 'Bearer ' + authToken}
                });
                if (r.ok) {
                    const d = await r.json();
                    devNameEl.textContent = d.computer_name || targetDevice;
                    badgeEl.textContent = d.locked ? 'Kilidli' : 'Açıq';
                    badgeEl.className = 'badge badge-online';
                } else if (r.status === 403 || r.status === 401) {
                    badgeEl.textContent = 'İcazəsiz';
                    badgeEl.className = 'badge badge-offline';
                }
            } catch(e) {}
        }

        async function sendCommand(action) {
            if (!authToken || !targetDevice) return;
            statusBox.innerHTML = '<span class="spinner"></span>Əmr göndərilir (' + action + ')...';
            try {
                const r = await fetch('/devices/' + encodeURIComponent(targetDevice) + '/command', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + authToken},
                    body: JSON.stringify({action: action})
                });
                const res = await r.json();
                if (r.ok && res.command_id) {
                    statusBox.innerHTML = '<span class="spinner"></span>Əmr növbəyə alındı (' + action + '). PC-nin faktiki icrası gözlənilir...';
                    pollCommandResult(res.command_id, action);
                } else {
                    statusBox.textContent = 'Xəta: ' + (res.message || res.error);
                }
            } catch(e) {
                statusBox.textContent = 'Şəbəkə xətası: ' + e;
            }
        }

        async function pollCommandResult(cmdId, action) {
            let attempts = 0;
            const maxAttempts = 10;
            const timer = setInterval(async () => {
                attempts++;
                try {
                    const r = await fetch('/commands/' + encodeURIComponent(cmdId), {
                        headers: {'Authorization': 'Bearer ' + authToken}
                    });
                    if (r.ok) {
                        const cmd = await r.json();
                        if (cmd.status === 'executed' || cmd.status === 'completed') {
                            clearInterval(timer);
                            statusBox.textContent = 'İcra tamamlandı (' + action + '): ' + (cmd.result || 'Uğurlu');
                            pollStatus();
                            return;
                        } else if (cmd.status === 'failed') {
                            clearInterval(timer);
                            statusBox.textContent = 'İcra uğursuz oldu: ' + (cmd.result || 'Xəta');
                            return;
                        }
                    }
                } catch(e) {}

                if (attempts >= maxAttempts) {
                    clearInterval(timer);
                    statusBox.textContent = 'PC hələ cavab vermədi (Taymaut). Cihaz offline ola bilər.';
                    pollStatus();
                }
            }, 1000);
        }

        async function revokeDevice() {
            if (authToken) {
                try {
                    await fetch('/mobile/revoke', {
                        method: 'POST',
                        headers: {'Authorization': 'Bearer ' + authToken}
                    });
                } catch(e) {}
            }
            localStorage.clear();
            location.reload();
        }

        init();
    </script>
</body>
</html>"""
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
            return

        # 1b. Zəngin Avant-Garde Private Admin Dashboard İnterfeysi
        if path == "/admin":
            self.send_response(200)
            self._set_security_headers("text/html; charset=utf-8")
            admin_html = """<!DOCTYPE html>
<html lang="az">
<head>
    <meta charset="utf-8">
    <title>WinKey Pro — Şəxsi Sahib Paneli (Private Admin)</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: #0c0f0e; color: #e6ede8; display: flex; justify-content: center; min-height: 100vh; padding: 24px; }
        .admin-container { width: 100%; max-width: 900px; display: flex; flex-direction: column; gap: 20px; }
        .header { display: flex; justify-content: space-between; align-items: center; padding: 16px 0; border-bottom: 1px solid #1c2420; }
        .logo { font-size: 1.4rem; font-weight: 700; color: #c8f279; letter-spacing: -0.5px; }
        .badge { font-size: 0.75rem; padding: 4px 10px; border-radius: 6px; font-weight: 600; text-transform: uppercase; }
        .badge-admin { background: rgba(200, 242, 121, 0.15); color: #c8f279; border: 1px solid rgba(200, 242, 121, 0.3); }
        .card { background: #141a17; border: 1px solid #1f2723; border-radius: 12px; padding: 20px; display: flex; flex-direction: column; gap: 14px; }
        .card-title { font-size: 1.1rem; font-weight: 600; color: #fff; }
        .input-group { display: flex; gap: 10px; }
        input[type="password"], input[type="text"] { flex: 1; padding: 10px 14px; background: #0a0d0c; border: 1px solid #27332c; border-radius: 8px; color: #fff; font-size: 0.95rem; }
        .btn { padding: 10px 18px; border-radius: 8px; font-size: 0.9rem; font-weight: 600; cursor: pointer; border: none; transition: 0.15s; }
        .btn-primary { background: #c8f279; color: #0c0f0e; }
        .btn-primary:active { transform: scale(0.98); }
        .btn-danger { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.4); padding: 6px 12px; font-size: 0.8rem; }
        table { width: 100%; border-collapse: collapse; font-size: 0.85rem; margin-top: 8px; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid #1a221e; }
        th { color: #8e9e95; font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }
        .status-pill { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
        .status-active { background: rgba(200,242,121,0.15); color: #c8f279; }
        .status-revoked { background: rgba(239,68,68,0.15); color: #ef4444; }
        .err-msg { color: #ef4444; font-size: 0.85rem; }
    </style>
</head>
<body>
    <div class="admin-container">
        <div class="header">
            <div class="logo">WinKey Pro — Şəxsi Sahib Paneli</div>
            <div class="badge badge-admin">Private Surface</div>
        </div>

        <div class="card" id="auth-box">
            <div class="card-title">Sahib Autentifikasiyası</div>
            <div class="input-group">
                <input type="password" id="admin-sec-input" placeholder="X-Owner-Admin-Secret daxil edin...">
                <button class="btn btn-primary" onclick="loginAdmin()">Giriş</button>
            </div>
            <div id="auth-err" class="err-msg"></div>
        </div>

        <div id="dashboard-content" style="display: none; flex-direction: column; gap: 20px;">
            <div class="card">
                <div class="card-title">Qeydiyyatdan Keçmiş PC Cihazları</div>
                <div id="devices-container">Yüklənir...</div>
            </div>

            <div class="card">
                <div class="card-title">Canlı Telemetriya və İnsidentlər (Son 100 Hadisə)</div>
                <div id="telemetry-container">Yüklənir...</div>
            </div>
        </div>
    </div>

    <script>
        const localAccess = new URLSearchParams(location.hash.slice(1)).get('dev-admin');
        if (localAccess) {
            sessionStorage.setItem('winkey_admin_secret', localAccess);
            history.replaceState(null, '', location.pathname);
        }
        let adminSecret = sessionStorage.getItem('winkey_admin_secret') || '';

        function loginAdmin() {
            const val = document.getElementById('admin-sec-input').value.trim();
            if (!val) return;
            adminSecret = val;
            sessionStorage.setItem('winkey_admin_secret', adminSecret);
            loadDashboard();
        }

        async function loadDashboard() {
            document.getElementById('auth-err').textContent = '';
            try {
                const resDev = await fetch('/admin/devices', {
                    headers: { 'X-Owner-Admin-Secret': adminSecret }
                });
                if (resDev.status === 403) {
                    document.getElementById('auth-err').textContent = 'XƏTA 403: Admin Secret yanlışdır!';
                    document.getElementById('dashboard-content').style.display = 'none';
                    return;
                }
                const dataDev = await resDev.json();
                renderDevices(dataDev.devices || []);

                const resTel = await fetch('/admin/telemetry', {
                    headers: { 'X-Owner-Admin-Secret': adminSecret }
                });
                const dataTel = await resTel.json();
                renderTelemetry(dataTel.telemetry || []);

                document.getElementById('auth-box').style.display = 'none';
                document.getElementById('dashboard-content').style.display = 'flex';
            } catch(e) {
                document.getElementById('auth-err').textContent = 'Şəbəkə xətası: ' + e;
            }
        }

        function escapeHtml(value) {
            return String(value ?? '').replace(/[&<>"']/g, ch => ({
                '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
            }[ch]));
        }

        function renderDevices(list) {
            if (list.length === 0) {
                document.getElementById('devices-container').innerHTML = '<div style="color:#8e9e95;">Heç bir cihaz qeydiyyatdan keçməyib.</div>';
                return;
            }
            let html = '<table><tr><th>Cihaz ID</th><th>Ad</th><th>Status</th><th>Kilid</th><th>PIN</th><th>Son Görülmə</th><th>Əməliyyat</th></tr>';
            for (const d of list) {
                const stClass = d.status === 'ACTIVE' ? 'status-active' : 'status-revoked';
                html += `<tr>
                    <td><code>${escapeHtml(d.device_id.substring(0, 16))}...</code></td>
                    <td><strong>${escapeHtml(d.computer_name)}</strong></td>
                    <td><span class="status-pill ${stClass}">${escapeHtml(d.status)}</span></td>
                    <td>${d.locked ? '🔒 Bəli' : '🔓 Xeyr'}</td>
                    <td>${d.pin_ready ? '✅ Hazır' : '⏳ Yoxdur'}</td>
                    <td>${new Date(d.last_seen_at * 1000).toLocaleTimeString()}</td>
                    <td><button class="btn btn-danger" data-device-id="${escapeHtml(d.device_id)}" data-action="${d.status === 'ACTIVE' ? 'revoke' : 'activate'}">${d.status === 'ACTIVE' ? 'Ləğv Et' : 'Yenidən aktivləşdir'}</button></td>
                </tr>`;
            }
            html += '</table>';
            document.getElementById('devices-container').innerHTML = html;
            document.querySelectorAll('#devices-container button[data-device-id]').forEach(button => {
                button.addEventListener('click', () => revokeDev(button.dataset.deviceId, button.dataset.action));
            });
        }

        function renderTelemetry(events) {
            if (events.length === 0) {
                document.getElementById('telemetry-container').innerHTML = '<div style="color:#8e9e95;">Hadisə qeydə alınmayıb.</div>';
                return;
            }
            let html = '<table><tr><th>Vaxt</th><th>Komponent</th><th>Mərhələ</th><th>Hadisə</th><th>Dərəcə</th><th>Xəta Kodu</th></tr>';
            for (const ev of events.slice(0, 25)) {
                html += `<tr>
                    <td>${new Date(ev.received_at * 1000).toLocaleTimeString()}</td>
                    <td>${escapeHtml(ev.component)}</td>
                    <td>${escapeHtml(ev.stage)}</td>
                    <td>${escapeHtml(ev.event_type)}</td>
                    <td><strong>${escapeHtml(ev.severity)}</strong></td>
                    <td>${escapeHtml(ev.error_code || '—')}</td>
                </tr>`;
            }
            html += '</table>';
            document.getElementById('telemetry-container').innerHTML = html;
        }

        async function revokeDev(devId, action = 'revoke') {
            if (!confirm(action === 'activate' ? 'PC-ni yenidən aktivləşdirək? Köhnə telefon sessiyaları bərpa edilmir; yeni QR lazımdır.' : 'Cihazı ləğv etmək istədiyinizə əminsiniz?')) return;
            await fetch(action === 'activate' ? '/admin/activate' : '/admin/revoke', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Owner-Admin-Secret': adminSecret
                },
                body: JSON.stringify({ device_id: devId })
            });
            loadDashboard();
        }

        if (adminSecret) {
            loadDashboard();
        }
        setInterval(() => { if (adminSecret) loadDashboard(); }, 5000);
    </script>
</body>
</html>"""
            self.end_headers()
            self.wfile.write(admin_html.encode("utf-8"))
            return

        # 2. Owner-Only Admin Devices
        if path == "/admin/devices":
            admin_sec = self.headers.get("X-Owner-Admin-Secret")
            if not admin_sec or admin_sec != get_admin_secret():
                self._send_json(403, {"error": "E_ADMIN_UNAUTHORIZED", "message": "Yalnız sahib admin icazəlidir"})
                return
            with self.db.get_conn() as conn:
                rows = conn.execute("SELECT device_id, computer_name, status, locked, pin_ready, last_seen_at FROM devices").fetchall()
                devices = [dict(r) for r in rows]
            self._send_json(200, {"devices": devices})
            return

        # 3. Owner-Only Admin Telemetry
        if path == "/admin/telemetry":
            admin_sec = self.headers.get("X-Owner-Admin-Secret")
            if not admin_sec or admin_sec != get_admin_secret():
                self._send_json(403, {"error": "E_ADMIN_UNAUTHORIZED", "message": "Yalnız sahib admin icazəlidir"})
                return
            with self.db.get_conn() as conn:
                rows = conn.execute("SELECT * FROM telemetry_events ORDER BY received_at DESC LIMIT 100").fetchall()
                events = [dict(r) for r in rows]
            self._send_json(200, {"telemetry": events})
            return

        # 4. Device Status (Device-Scoped Token ilə, Multi-Tenant IDOR qorumalı)
        if path.startswith("/devices/") and path.endswith("/status"):
            parts = path.split("/")
            req_device_id = parts[2]
            token = self._get_bearer_token()
            if not token:
                self._send_json(401, {"error": "E_MISSING_TOKEN"})
                return

            with self.db.get_conn() as conn:
                sess = conn.execute("SELECT device_id FROM mobile_sessions WHERE session_token = ? AND expires_at > ?", (token, time.time())).fetchone()
                if not sess:
                    self._send_json(401, {"error": "E_INVALID_SESSION"})
                    return

                # MULTI-TENANT IDOR GUARD
                if sess["device_id"] != req_device_id:
                    self._send_json(403, {"error": "E_TENANT_IDOR_FORBIDDEN", "message": "Başqa cihazın statusuna giriş qadağandır!"})
                    return

                dev = conn.execute("SELECT device_id, computer_name, status, locked, pin_ready FROM devices WHERE device_id = ?", (req_device_id,)).fetchone()
                if not dev:
                    self._send_json(404, {"error": "E_DEVICE_NOT_FOUND"})
                    return
                if dev["status"] != "ACTIVE":
                    self._send_json(403, {"error": "E_DEVICE_NOT_ACTIVE", "message": "Cihaz deaktiv edilib və ya aktiv deyil"})
                    return
                self._send_json(200, dict(dev))
            return

        # 5. Command Status Polling (Mobil üçün — komandanın real icra nəticəsini izləmək)
        if path.startswith("/commands/"):
            parts = path.split("/")
            if len(parts) >= 3:
                cmd_id = parts[2]
                token = self._get_bearer_token()
                if not token:
                    self._send_json(401, {"error": "E_MISSING_TOKEN"})
                    return

                with self.db.get_conn() as conn:
                    sess = conn.execute("SELECT device_id FROM mobile_sessions WHERE session_token = ? AND expires_at > ?", (token, time.time())).fetchone()
                    if not sess:
                        self._send_json(401, {"error": "E_INVALID_SESSION"})
                        return

                    cmd = conn.execute("SELECT command_id, device_id, action, status, result_status AS result, created_at, completed_at AS executed_at FROM commands WHERE command_id = ?", (cmd_id,)).fetchone()
                    if not cmd:
                        self._send_json(404, {"error": "E_COMMAND_NOT_FOUND"})
                        return

                    # Multi-Tenant guard
                    if cmd["device_id"] != sess["device_id"]:
                        self._send_json(403, {"error": "E_TENANT_IDOR_FORBIDDEN", "message": "Başqa cihazın əmrinə giriş qadağandır"})
                        return

                    self._send_json(200, dict(cmd))
                return

        # 6. Real Update Delivery — Manifest və İmza Sorğusu (/updates/latest)
        if path == "/updates/latest":
            u_dir = get_updates_dir()
            manifest_path = os.path.join(u_dir, "manifest.json")
            sig_path = os.path.join(u_dir, "manifest.sig")
            if not os.path.isfile(manifest_path) or not os.path.isfile(sig_path):
                self._send_json(404, {"error": "E_NO_UPDATES_AVAILABLE", "message": "Serverdə aktiv buraxılış paketi tapılmadı"})
                return

            with open(manifest_path, "rb") as mf:
                manifest_raw_bytes = mf.read()
            manifest_json = json.loads(manifest_raw_bytes.decode("utf-8"))
            with open(sig_path, "rb") as sf:
                sig_hex = sf.read().hex()

            self._send_json(200, {
                "version": manifest_json.get("version", "0.1.0"),
                "manifest": manifest_json,
                "manifest_raw": manifest_raw_bytes.decode("utf-8"),
                "manifest_sig_hex": sig_hex,
                "download_url_prefix": "/updates/download"
            })
            return

        # 7. Real Update Delivery — İmzalı Fayl Endirilməsi (/updates/download/<filename>)
        if path.startswith("/updates/download/"):
            fname = path[len("/updates/download/"):].strip()
            # Path traversal qoruması (Zip-Slip / Traversal guard)
            if not fname or ".." in fname or "/" in fname or "\\" in fname or ":" in fname:
                self._send_json(400, {"error": "E_INVALID_FILENAME", "message": "Təhlükəli və ya etibarsız fayl adı"})
                return

            u_dir = get_updates_dir()
            fpath = os.path.join(u_dir, fname)
            if not os.path.isfile(fpath):
                self._send_json(404, {"error": "E_FILE_NOT_FOUND", "message": f"Tələb olunan fayl tapılmadı: {fname}"})
                return

            with open(fpath, "rb") as f:
                content = f.read()

            self.send_response(200)
            self._set_security_headers("application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        self._send_json(404, {"error": "E_NOT_FOUND"})

    def do_POST(self):
        url = urlparse(self.path)
        path = url.path.rstrip("/")
        data = self._read_json()

        # 1. Challenge yaradılması (/agent/challenge)
        if path == "/agent/challenge":
            purpose = data.get("purpose", "register")
            device_id = data.get("device_id", "")
            nonce = secrets.token_hex(16)
            with self.db.get_conn() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO challenges (nonce, purpose, device_id, created_at, expires_at, used) VALUES (?, ?, ?, ?, ?, 0)",
                    (nonce, purpose, device_id, time.time(), time.time() + 120)
                )
                conn.commit()
            self._send_json(200, {"nonce": nonce, "device_id": device_id, "purpose": purpose})
            return

        # 2. Cihaz Qeydiyyatı (Agent Registration) — STRICT VALIDATION & OWNERSHIP
        if path == "/agent/register":
            device_id = data.get("device_id")
            computer_name = data.get("computer_name", "PC")
            pub_hex = data.get("public_key_hex", "")
            proof_sig = data.get("proof_signature_hex")
            nonce = data.get("nonce")

            if not device_id or not isinstance(device_id, str):
                self._send_json(400, {"error": "E_INVALID_DEVICE_ID", "message": "device_id məcburidir"})
                return

            # YOXLANILIŞ 1: Public Key Hex və Ed25519 formatı
            if not pub_hex or not isinstance(pub_hex, str) or len(pub_hex) != 64:
                self._send_json(400, {"error": "E_INVALID_PUBLIC_KEY", "message": "public_key_hex 64 simvollu hex olmalıdır"})
                return

            try:
                pub_bytes = bytes.fromhex(pub_hex)
                if len(pub_bytes) != 32:
                    self._send_json(400, {"error": "E_INVALID_PUBLIC_KEY", "message": "Açar uzunluğu 32 bayt olmalıdır"})
                    return
                verifier = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            except Exception as e:
                self._send_json(400, {"error": "E_INVALID_PUBLIC_KEY", "message": f"Ed25519 açar formatı xətası: {e}"})
                return

            # YOXLANILIŞ 2: Nonce və Cryptographic Proof MƏCBURİDİR
            if not nonce or not proof_sig:
                self._send_json(400, {
                    "error": "E_MISSING_PROOF",
                    "message": "Qeydiyyat üçün nonce və cryptographic proof_signature_hex məcburidir"
                })
                return

            with self.db.get_conn() as conn:
                chal = conn.execute(
                    "SELECT * FROM challenges WHERE nonce = ? AND used = 0 AND expires_at > ? AND purpose = 'register'",
                    (nonce, time.time())
                ).fetchone()
                if not chal:
                    self._send_json(400, {"error": "E_INVALID_NONCE", "message": "Nonce tapılmadı, istifadə olunub və ya vaxtı bitib"})
                    return

                if chal["device_id"] and chal["device_id"] != device_id:
                    self._send_json(400, {"error": "E_CHALLENGE_DEVICE_MISMATCH", "message": "Nonce başqa cihaz üçün yaradılıb"})
                    return

                # Atomik One-Use istehlakı
                upd = conn.execute("UPDATE challenges SET used = 1 WHERE nonce = ? AND used = 0", (nonce,)).rowcount
                if upd != 1:
                    self._send_json(409, {"error": "E_NONCE_REPLAY", "message": "Nonce artıq istifadə olunub"})
                    return

                bound_msg = f"WINKEY_REGISTER:{nonce}:{device_id}".encode("utf-8")
                try:
                    sig_bytes = bytes.fromhex(proof_sig)
                    verifier.verify(sig_bytes, bound_msg)
                except Exception as e:
                    self._send_json(400, {"error": "E_INVALID_PROOF", "message": f"Kriptoqrafik imza təsdiqlənmədi: {e}"})
                    return

                # YOXLANILIŞ 3: Re-registration Ownership Guard
                existing = conn.execute("SELECT public_key_hex, device_secret_hash, status FROM devices WHERE device_id = ?", (device_id,)).fetchone()
                if existing:
                    if existing["public_key_hex"] != pub_hex:
                        self._send_json(409, {
                            "error": "E_DEVICE_ALREADY_EXISTS_OWNERSHIP_VIOLATION",
                            "message": "Bu cihaz ID başqa ictimai açarla qeydiyyatdan keçib. Cihaz oğurlana bilməz!"
                        })
                        return

                    # İctimai açarla imzasız təkrar secret rotasiyası QADAĞANDIR!
                    token = self._get_bearer_token()
                    can_rotate = False
                    if token:
                        sec_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
                        if sec_hash == existing["device_secret_hash"]:
                            can_rotate = True
                    if not can_rotate:
                        self._send_json(409, {
                            "error": "E_DEVICE_ALREADY_REGISTERED",
                            "message": "Cihaz artıq qeydiyyatdan keçib. Açıq ictimai açarla icazəsiz secret rotasiyası qadağandır!"
                        })
                        return

                    # Səlahiyyətli rotasiya
                    new_secret = secrets.token_hex(32)
                    new_sec_hash = hashlib.sha256(new_secret.encode("utf-8")).hexdigest()
                    conn.execute("UPDATE devices SET device_secret_hash = ?, last_seen_at = ? WHERE device_id = ?", (new_sec_hash, time.time(), device_id))
                    conn.commit()
                    self._send_json(200, {"device_id": device_id, "device_secret": new_secret, "status": "ROTATED"})
                    return

                # Yeni cihaz qeydiyyatı (INSERT OR REPLACE deyil, təmiz INSERT)
                secret = secrets.token_hex(32)
                sec_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest()

                conn.execute(
                    "INSERT INTO devices (device_id, computer_name, public_key_hex, device_secret_hash, status, created_at, last_seen_at) VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?)",
                    (device_id, computer_name, pub_hex, sec_hash, time.time(), time.time())
                )
                conn.commit()

            self._send_json(200, {"device_id": device_id, "device_secret": secret, "status": "REGISTERED"})
            return

        # 3. Pair sorğusunun təsdiqi və Sessiya yaradılması (One-Use Atomic Claim)
        if path == "/pair":
            pair_code = data.get("pair_code") or data.get("code")
            if not pair_code:
                self._send_json(400, {"error": "E_MISSING_PAIR_CODE", "message": "pair_code tələb olunur"})
                return

            with self.db.get_conn() as conn:
                req = conn.execute("SELECT * FROM pairing_requests WHERE pair_code = ?", (pair_code,)).fetchone()
                # YOXLANILIŞ: Server tərəfindən heç yaradılmamış naməlum kod dərhal rədd edilir!
                if not req:
                    self._send_json(404, {"error": "E_PAIR_CODE_NOT_FOUND", "message": "Cütləşmə kodu tapılmadı və ya etibarsızdır"})
                    return

                # Strict status check: yalnız və yalnız PENDING qəbul edilir!
                if req["status"] != "PENDING":
                    if req["status"] == "CLAIMED":
                        self._send_json(409, {"error": "E_REPLAY_REJECTED", "message": "Bu cütləşmə kodu artıq istifadə olunub!"})
                    elif req["status"] == "REJECTED":
                        self._send_json(403, {"error": "E_PAIR_CODE_REJECTED", "message": "Bu cütləşmə kodu rədd edilib!"})
                    else:
                        self._send_json(400, {"error": "E_INVALID_PAIR_STATUS", "message": f"Cütləşmə statusu etibarsızdır: {req['status']}"})
                    return

                if req["expires_at"] < time.time():
                    self._send_json(410, {"error": "E_EXPIRED_CODE", "message": "Cütləşmə kodunun vaxtı bitib"})
                    return

                # Cihazın özünün aktiv olması məcburidir!
                device_id = req["device_id"]
                dev = conn.execute("SELECT status FROM devices WHERE device_id = ?", (device_id,)).fetchone()
                if not dev or dev["status"] != "ACTIVE":
                    self._send_json(403, {"error": "E_DEVICE_NOT_ACTIVE", "message": "Cihaz aktiv deyil və ya ləğv edilib"})
                    return

                # Atomik Status Dəyişdirilməsi və rowcount == 1 yoxlanışı (Paralel yarışlara qarşı!)
                cur = conn.execute(
                    "UPDATE pairing_requests SET status = 'CLAIMED' WHERE pair_code = ? AND status = 'PENDING' AND expires_at > ?",
                    (pair_code, time.time())
                )
                if cur.rowcount != 1:
                    self._send_json(409, {"error": "E_PAIR_CLAIM_CONFLICT", "message": "Cütləşmə kodu artıq başqa sorğu tərəfindən istifadə edilib"})
                    return

                session_token = "sess_" + secrets.token_hex(24)
                conn.execute(
                    "INSERT INTO mobile_sessions (session_token, device_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                    (session_token, device_id, time.time(), time.time() + 86400)
                )
                conn.commit()

            self._send_json(200, {
                "success": True,
                "session_token": session_token,
                "device_id": device_id,
                "expires_in": 86400
            })
            return

        # 4. Pair Request Yaradılması (PC Desktop tərəfindən)
        if path == "/devices/pair-request":
            device_id = data.get("device_id")
            with self.db.get_conn() as conn:
                if not self._authenticate_agent(conn, device_id):
                    self._send_json(401, {"error": "E_UNAUTHORIZED_AGENT", "message": "Cihaz autentifikasiyası tələb olunur"})
                    return

                pair_code = "PAIR_" + secrets.token_hex(6).upper()
                expires_at = time.time() + 120
                conn.execute(
                    "INSERT OR REPLACE INTO pairing_requests (pair_code, device_id, challenge_hex, status, expires_at, created_at) VALUES (?, ?, 'chal', 'PENDING', ?, ?)",
                    (pair_code, device_id, expires_at, time.time())
                )
                conn.commit()

            self._send_json(200, {"pair_code": pair_code, "expires_at": expires_at, "device_id": device_id})
            return

        # 5. Mobil Sessiyanın Serverdə Ləğv Edilməsi (/mobile/revoke)
        if path in ("/mobile/revoke", "/devices/revoke"):
            token = self._get_bearer_token()
            if not token:
                self._send_json(401, {"error": "E_MISSING_TOKEN", "message": "Sessiya tokeni tələb olunur"})
                return

            with self.db.get_conn() as conn:
                sess = conn.execute("SELECT session_token, device_id FROM mobile_sessions WHERE session_token = ?", (token,)).fetchone()
                if not sess:
                    self._send_json(401, {"error": "E_INVALID_SESSION", "message": "Sessiya tapılmadı və ya artıq ləğv edilib"})
                    return
                # Sessiyanı ləğv edirik
                conn.execute("DELETE FROM mobile_sessions WHERE session_token = ?", (token,))
                conn.commit()

            self._send_json(200, {"success": True, "message": "Mobil sessiya serverdə uğurla ləğv edildi"})
            return

        # 6. Mobil Komanda Göndərişi (Multi-Tenant IDOR + Zero-PIN Guard)
        if (path.startswith("/devices/") and path.endswith("/command")) or path == "/commands":
            parts = path.split("/")
            req_device_id = data.get("device_id") if path == "/commands" else parts[2]
            token = self._get_bearer_token()

            # ZERO-PIN ENFORCEMENT: Şəbəkədə heç vaxt PIN ola bilməz!
            for forbidden in ["pin", "credential", "password", "secret"]:
                if forbidden in data:
                    self._send_json(400, {
                        "error": "E_CREDENTIAL_NOT_PERMITTED",
                        "message": "Mobil şəbəkə üzərindən PIN göndərilməsi qəti qadağandır! PIN yalnız PC daxilində DPAPI anbarında saxlanır."
                    })
                    return

            with self.db.get_conn() as conn:
                sess = conn.execute("SELECT device_id FROM mobile_sessions WHERE session_token = ? AND expires_at > ?", (token, time.time())).fetchone()
                if not sess:
                    self._send_json(401, {"error": "E_INVALID_SESSION"})
                    return

                # MULTI-TENANT IDOR GUARD
                if sess["device_id"] != req_device_id:
                    self._send_json(403, {"error": "E_TENANT_IDOR_FORBIDDEN", "message": "Başqa istifadəçinin cihazına komanda göndərə bilməzsiniz!"})
                    return

                dev = conn.execute("SELECT status FROM devices WHERE device_id = ?", (req_device_id,)).fetchone()
                if not dev or dev["status"] != "ACTIVE":
                    self._send_json(403, {"error": "E_DEVICE_NOT_ACTIVE", "message": "Cihaz deaktiv edilib və ya aktiv deyil"})
                    return

                action = data.get("action")
                if action not in ("lock", "unlock", "mock"):
                    self._send_json(400, {"error": "E_INVALID_ACTION"})
                    return

                cmd_id = "cmd_" + secrets.token_hex(12)
                conn.execute(
                    "INSERT INTO commands (command_id, device_id, action, status, created_at) VALUES (?, ?, ?, 'pending', ?)",
                    (cmd_id, req_device_id, action, time.time())
                )
                conn.commit()

            self._send_json(200, {"success": True, "command_id": cmd_id, "action": action, "status": "queued"})
            print(f"[COMMAND_QUEUED] device={req_device_id} action={action} id={cmd_id}", flush=True)
            return

        # 7. Authenticated Agent Polling (/agent/poll)
        if path == "/agent/poll":
            device_id = data.get("device_id")
            server = getattr(self, 'server', None)
            if server is not None and getattr(server, '_last_logged_device', None) != device_id:
                print(f"[WORKER_POLL_DEVICE] device={device_id}", flush=True)
                server._last_logged_device = device_id
            if not device_id:
                self._send_json(400, {"error": "E_MISSING_DEVICE_ID"})
                return

            with self.db.get_conn() as conn:
                # STRICT AGENT AUTHENTICATION
                if not self._authenticate_agent(conn, device_id):
                    self._send_json(401, {"error": "E_UNAUTHORIZED_AGENT", "message": "Agent autentifikasiyası (Bearer device_secret) uğursuz oldu"})
                    return

                dev = conn.execute("SELECT status FROM devices WHERE device_id = ?", (device_id,)).fetchone()
                if not dev or dev["status"] != "ACTIVE":
                    self._send_json(403, {"error": "E_DEVICE_NOT_ACTIVE", "message": "Cihaz deaktiv edilib"})
                    return

                locked = data.get("locked", False)
                pin_ready = data.get("pin_ready", False)

                conn.execute(
                    "UPDATE devices SET last_seen_at = ?, locked = ?, pin_ready = ? WHERE device_id = ?",
                    (time.time(), 1 if locked else 0, 1 if pin_ready else 0, device_id)
                )
                cmd = conn.execute(
                    "SELECT command_id, action FROM commands WHERE device_id = ? AND status = 'pending' ORDER BY created_at ASC LIMIT 1",
                    (device_id,)
                ).fetchone()

                if cmd:
                    print(f"[COMMAND_DELIVERED] device={device_id} action={cmd['action']} id={cmd['command_id']}", flush=True)
                    conn.execute("UPDATE commands SET status = 'delivered' WHERE command_id = ?", (cmd["command_id"],))
                    conn.commit()
                    self._send_json(200, {"command": {"id": cmd["command_id"], "action": cmd["action"]}})
                else:
                    conn.commit()
                    self._send_json(200, {"command": None})
            return

        # 7. Authenticated Agent Result (/agent/result) — WITH OBJECT OWNERSHIP CHECK
        if path == "/agent/result":
            cmd_id = data.get("command_id")
            device_id = data.get("device_id")
            success = data.get("success", False)
            status_str = data.get("status", "")

            with self.db.get_conn() as conn:
                if not device_id or not self._authenticate_agent(conn, device_id):
                    self._send_json(401, {"error": "E_UNAUTHORIZED_AGENT", "message": "Etibarlı agent secret tələb olunur"})
                    return

                cmd = conn.execute("SELECT device_id FROM commands WHERE command_id = ?", (cmd_id,)).fetchone()
                if not cmd:
                    self._send_json(404, {"error": "E_COMMAND_NOT_FOUND"})
                    return

                # OBJECT OWNERSHIP GUARD: Başqa cihazın komandasına nəticə yazmaq qadağandır!
                if cmd["device_id"] != device_id:
                    self._send_json(403, {"error": "E_COMMAND_NOT_OWNED", "message": "Bu komanda sizin cihaza aid deyil!"})
                    return

                conn.execute(
                    "UPDATE commands SET status = ?, completed_at = ?, result_status = ? WHERE command_id = ?",
                    ("completed" if success else "failed", time.time(), status_str, cmd_id)
                )
                conn.commit()
            self._send_json(200, {"acknowledged": True})
            if not success:
                # Only the stable result code, never exception bodies or credentials.
                safe_code = status_str.split(':', 1)[0].split(' ', 1)[0]
                self._record_incident('/agent/result', safe_code, device_id)
            return

        # 8. Telemetriya (/agent/telemetry)
        if path == "/agent/telemetry":
            event_id = data.get("event_id") or secrets.token_hex(12)
            dev_id = data.get("device_id")

            with self.db.get_conn() as conn:
                # Əgər device_id qeyd olunubsa, agent auth yoxlanılır
                if dev_id and not self._authenticate_agent(conn, dev_id):
                    self._send_json(401, {"error": "E_TELEMETRY_AUTH_MISMATCH", "message": "device_id üçün etibarlı token tələb olunur"})
                    return

                conn.execute(
                    "INSERT OR REPLACE INTO telemetry_events (event_id, install_run_id, device_id, component, version, stage, event_type, severity, error_code, duration_ms, local_time, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        event_id,
                        data.get("install_run_id"),
                        dev_id,
                        data.get("component", "agent"),
                        data.get("version", "0.1.0"),
                        data.get("stage", ""),
                        data.get("event_type", "info"),
                        data.get("severity", "INFO"),
                        data.get("error_code"),
                        data.get("duration_ms"),
                        data.get("local_time", time.time()),
                        time.time()
                    )
                )
                conn.commit()
            self._send_json(200, {"status": "RECORDED", "event_id": event_id})
            return

        # 9. Owner-Only Admin Cihaz Revoke (/admin/revoke)
        if path in ("/admin/revoke", "/admin/activate"):
            admin_sec = self.headers.get("X-Owner-Admin-Secret")
            if not admin_sec or admin_sec != get_admin_secret():
                self._send_json(403, {"error": "E_ADMIN_UNAUTHORIZED", "message": "Yalnız sahib admin icazəlidir"})
                return

            target_dev = data.get("device_id")
            if not target_dev:
                self._send_json(400, {"error": "E_MISSING_DEVICE_ID"})
                return

            target_status = 'ACTIVE' if path == '/admin/activate' else 'REVOKED'
            with self.db.get_conn() as conn:
                if not conn.execute('SELECT 1 FROM devices WHERE device_id = ?', (target_dev,)).fetchone():
                    self._send_json(404, {'error': 'E_DEVICE_NOT_FOUND'})
                    return
                conn.execute("UPDATE devices SET status = ? WHERE device_id = ?", (target_status, target_dev))
                conn.execute("DELETE FROM mobile_sessions WHERE device_id = ?", (target_dev,))
                conn.commit()

            self._send_json(200, {"success": True, "device_id": target_dev, "status": target_status})
            return

        self._send_json(404, {"error": "E_NOT_FOUND"})

def run_server(port: int, db_path: str) -> HTTPServer:
    db = ProductionDatabase(db_path)
    GatewayHandler.db = db
    host = os.environ.get("GATEWAY_HOST", "0.0.0.0")
    server = HTTPServer((host, port), GatewayHandler)
    return server

if __name__ == "__main__":
    p = int(sys.argv[1]) if len(sys.argv) > 1 else 8788
    d = sys.argv[2] if len(sys.argv) > 2 else "winkey_prod.db"
    srv = run_server(p, d)
    print(f"Production Gateway running on http://0.0.0.0:{p}")
    srv.serve_forever()
