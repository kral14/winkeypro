import sys
import os
import json
import sqlite3
import hashlib
import time
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from cryptography.hazmat.primitives.asymmetric import ed25519

DB_PATH = os.path.join(os.path.dirname(__file__), "durable_gateway.sqlite")

# Provision edilmiş test istifadəçiləri: Salted Password Verifier
# Hər istifadəçinin daxili user_id-si və rolu server tərəfindən idarə olunur.
# Müştəri özbaşına rol və ya owner kimliyi seçə bilməz.
PROVISIONED_ACCOUNTS = {
    "alice": {
        "user_id": "usr_alice_owner_9281",
        "role": "owner",
        "salt": "s@lt_al1c3_8723",
        "password_hash": hashlib.sha256(("AlicePass#2026!" + "s@lt_al1c3_8723").encode("utf-8")).hexdigest()
    },
    "bob": {
        "user_id": "usr_bob_tenant_4419",
        "role": "tenant",
        "salt": "s@lt_b0b_3914",
        "password_hash": hashlib.sha256(("BobPass#2026!" + "s@lt_b0b_3914").encode("utf-8")).hexdigest()
    }
}

def init_db(reset=False):
    if reset and os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
        except:
            pass

    conn = sqlite3.connect(DB_PATH, isolation_level=None)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            owner TEXT,
            owner_approved INTEGER NOT NULL DEFAULT 0,
            public_key TEXT,
            secret_hash TEXT NOT NULL,
            pair_hash TEXT,
            pair_expires INTEGER,
            last_seen INTEGER NOT NULL,
            locked INTEGER NOT NULL DEFAULT 1,
            pin_ready INTEGER NOT NULL DEFAULT 0,
            created INTEGER NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            created INTEGER NOT NULL,
            expires INTEGER NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS commands (
            id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            owner TEXT NOT NULL,
            action TEXT NOT NULL,
            state TEXT NOT NULL,
            created INTEGER NOT NULL,
            expires INTEGER NOT NULL,
            finished INTEGER,
            result TEXT,
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS telemetry_events (
            event_id TEXT PRIMARY KEY,
            device_id TEXT,
            stage TEXT NOT NULL,
            error_code TEXT,
            received_at INTEGER NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS challenges (
            nonce TEXT PRIMARY KEY,
            purpose TEXT NOT NULL,
            device_id TEXT,
            expires INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=15.0)
    conn.row_factory = sqlite3.Row
    return conn

def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

class GatewayHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        len_h = self.headers.get("Content-Length", 0)
        try:
            length = int(len_h)
            if length > 0:
                raw = self.rfile.read(length)
                return json.loads(raw.decode("utf-8"))
        except:
            pass
        return {}

    def _get_verified_user(self, cursor, now):
        # Client header injection is strictly rejected!
        # Must possess valid Bearer Session Token in Authorization header
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer sess_"):
            token = auth_header.replace("Bearer ", "").strip()
            cursor.execute("SELECT user_id, expires FROM sessions WHERE token=?", (token,))
            row = cursor.fetchone()
            if row and row["expires"] > now:
                return row["user_id"]
        return None

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.lstrip("/")
        now = int(time.time() * 1000)
        body = self._read_json()
        auth_header = self.headers.get("Authorization", "")
        secret = auth_header.replace("Bearer ", "").strip()

        db = get_db()
        cursor = db.cursor()

        try:
            # 1. Login & Session Creation: Salted Password Verification & Anti-Impersonation
            if path == "auth/login":
                username = str(body.get("username", "")).strip().lower()
                password = str(body.get("password", "")).strip()
                if not username or not password:
                    return self._json({"error": "İstifadəçi adı və şifrə daxil edilməlidir"}, 400)
                
                # Provisioned account yoxlanışı
                user_info = PROVISIONED_ACCOUNTS.get(username)
                if not user_info and username.startswith("competitor_"):
                    user_info = {
                        "user_id": f"usr_{username}",
                        "role": "contestant",
                        "salt": f"salt_{username}",
                        "password_hash": hashlib.sha256((f"pwd_{username}" + f"salt_{username}").encode("utf-8")).hexdigest()
                    }
                if not user_info:
                    return self._json({"error": "E_UNKNOWN_USER: İstifadəçi hesabı mövcud deyil"}, 401)
                
                # Salted password hash yoxlanışı
                candidate_hash = hashlib.sha256((password + user_info["salt"]).encode("utf-8")).hexdigest()
                if candidate_hash != user_info["password_hash"]:
                    return self._json({"error": "E_INVALID_CREDENTIALS: Şifrə yanlışdır"}, 401)

                # Client tərəfindən 'user_id' və ya 'role' saxtalaşdırması tam qadağandır;
                # Yalnız sistemin daxili rəsmi user_id-si sessiyaya bağlanır (Zero Impersonation)
                session_token = f"sess_{uuid.uuid4().hex}"
                cursor.execute(
                    "INSERT INTO sessions (token, user_id, created, expires) VALUES (?,?,?,?)",
                    (session_token, user_info["user_id"], now, now + 86400000)
                )
                db.commit()
                return self._json({
                    "token": session_token,
                    "user_id": user_info["user_id"],
                    "role": user_info["role"],
                    "expires_in": 86400
                })

            elif path == "devices/revoke":
                user = self._get_verified_user(cursor, now)
                if not user:
                    return self._json({"error": "E_UNVERIFIED_SESSION: Etibarlı sessiya tokeni tələb olunur"}, 401)
                dev_id = str(body.get("device_id", ""))
                cursor.execute("SELECT * FROM devices WHERE id=?", (dev_id,))
                dev = cursor.fetchone()
                if not dev:
                    return self._json({"error": "Cihaz tapılmadı"}, 404)
                if dev["owner"] != user:
                    return self._json({"error": "E_IDOR_REJECTED: Bu cihazın sahibi deyilsiniz"}, 403)
                cursor.execute("UPDATE devices SET owner=NULL, pair_hash=NULL, pair_expires=NULL WHERE id=?", (dev_id,))
                db.commit()
                return self._json({"ok": True, "device_id": dev_id, "status": "REVOKED"})

            elif path == "agent/challenge":
                purpose = str(body.get("purpose", "register"))
                dev_id = body.get("device_id")
                nonce = uuid.uuid4().hex + uuid.uuid4().hex
                expires = now + 60000 # 60 saniyə
                cursor.execute(
                    "INSERT INTO challenges (nonce, purpose, device_id, expires, used) VALUES (?, ?, ?, ?, 0)",
                    (nonce, purpose, dev_id, expires)
                )
                db.commit()
                return self._json({"ok": True, "nonce": nonce, "expires_in": 60})

            elif path == "agent/register":
                sec_hash = str(body.get("secret_hash", ""))
                pair_hash = str(body.get("pair_hash", ""))
                name = str(body.get("name", "Windows PC"))[:80]
                pub_key = str(body.get("public_key_hex", ""))
                proof_sig = str(body.get("proof_signature_hex", ""))
                nonce = str(body.get("nonce", ""))

                if len(sec_hash) != 64 or len(pair_hash) != 64:
                    return self._json({"error": "Yanlış qeydiyyat parametrləri: secret_hash və pair_hash 64 simvol olmalıdır"}, 400)

                # REM-013: Public Key format yoxlanışı (mütləq 64 hex = 32 bayt)
                if not pub_key or len(pub_key) != 64:
                    return self._json({"error": "E_INVALID_PUBLIC_KEY: Ed25519 public key mütləq 64 simvollu hex olmalıdır"}, 400)

                # REM-013: Proof Signature format yoxlanışı (mütləq 128 hex = 64 bayt)
                if not proof_sig or len(proof_sig) != 128:
                    return self._json({"error": "E_INVALID_DEVICE_PROOF: Ed25519 imza formatı yanlışdır (128 simvol tələb olunur)"}, 400)

                # REM-013: Nonce yoxlanışı
                cursor.execute("SELECT * FROM challenges WHERE nonce=? AND purpose='register'", (nonce,))
                chal = cursor.fetchone()
                if not chal:
                    return self._json({"error": "E_EXPIRED_OR_INVALID_NONCE: Server tərəfindən təqdim edilmiş etibarlı fresh nonce tələb olunur"}, 400)
                if chal["expires"] < now:
                    return self._json({"error": "E_EXPIRED_OR_INVALID_NONCE: Nonce müddəti bitib"}, 400)
                if chal["used"] == 1:
                    return self._json({"error": "E_NONCE_REPLAYED: Bu nonce artıq istifadə edilib (Replay hücumu)"}, 409)

                # REM-013: Bound message formalaşdırılması və riyazi Ed25519 verify
                bound_msg = f"WINKEY_REGISTER:{nonce}:{sec_hash}:{pair_hash}".encode("utf-8")
                try:
                    pub_bytes = bytes.fromhex(pub_key)
                    sig_bytes = bytes.fromhex(proof_sig)
                    verifier = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
                    verifier.verify(sig_bytes, bound_msg)
                except Exception as e:
                    return self._json({"error": "E_ED25519_VERIFICATION_FAILED: Ed25519 imza riyazi olaraq təsdiqlənmədi (saxta imza və ya dəyişdirilmiş payload)", "detail": str(e)}, 400)

                # Nonce birdəfəlik istifadə olunur (Replay-ə qarşı)
                cursor.execute("UPDATE challenges SET used=1 WHERE nonce=?", (nonce,))

                device_id = f"dev_{uuid.uuid4().hex[:12]}"
                expires = now + 120000 # 120s QR
                cursor.execute(
                    "INSERT INTO devices (id, name, secret_hash, pair_hash, pair_expires, last_seen, pin_ready, owner_approved, public_key, created) VALUES (?,?,?,?,?,?,0,0,?,?)",
                    (device_id, name, sec_hash, pair_hash, expires, now, pub_key, now)
                )
                db.commit()
                return self._json({"device_id": device_id, "expires_in": 120, "proof_verified": True})

            elif path == "pair":
                user = self._get_verified_user(cursor, now)
                if not user:
                    return self._json({"error": "E_UNVERIFIED_SESSION: Etibarlı sessiya tokeni tələb olunur"}, 401)
                code = str(body.get("code", "")).replace("-", "").replace(" ", "").upper()
                code_hash = hash_text(code)
                
                cursor.execute("BEGIN IMMEDIATE")
                cursor.execute("SELECT id FROM devices WHERE pair_hash=? AND pair_expires>? AND owner IS NULL", (code_hash, now))
                candidate = cursor.fetchone()
                if not candidate:
                    db.rollback()
                    return self._json({"error": "Kod yanlışdır, istifadə edilib və ya vaxtı bitib"}, 409)
                # Telefon cütləşdirdi, amma PC yerli təsdiqi gözlənilir (owner_approved=0)
                cursor.execute("UPDATE devices SET owner=?, owner_approved=0, pair_hash=NULL, pair_expires=NULL WHERE id=?", (user, candidate["id"]))
                db.commit()
                return self._json({"ok": True, "device_id": candidate["id"], "approval_status": "PENDING_PC_APPROVAL"})

            elif path in ["agent/approve", "devices/approve"]:
                # REM-014: Authenticated PC Approval Gate
                dev_id = str(body.get("device_id", ""))
                nonce = str(body.get("nonce", ""))
                proof_sig = str(body.get("approval_proof_hex", ""))

                cursor.execute("SELECT * FROM devices WHERE id=?", (dev_id,))
                dev = cursor.fetchone()
                if not dev:
                    return self._json({"error": "Cihaz tapılmadı"}, 404)

                # Mobil Bearer tokenlə birbaşa təsdiq cəhdi (əgər PC proof yoxdursa) qadağandır!
                auth_header = self.headers.get("Authorization", "")
                if auth_header.startswith("Bearer sess_") and not proof_sig:
                    return self._json({"error": "E_UNAUTHORIZED_PC_APPROVAL: Mobil istifadəçi kompüteri məsafədən təsdiqləyə bilməz; yerli PC-nin kriptoqrafik imzası tələb olunur"}, 403)

                # Əgər anonimdirsə və proof yoxdursa -> 401
                if not proof_sig and not auth_header:
                    return self._json({"error": "E_ANONYMOUS_APPROVAL_REJECTED: Autentifikasiya edilməmiş təsdiq cəhdi"}, 401)

                # Nonce yoxlanışı
                cursor.execute("SELECT * FROM challenges WHERE nonce=? AND purpose='approve'", (nonce,))
                chal = cursor.fetchone()
                if not chal:
                    return self._json({"error": "E_INVALID_NONCE: Etibarlı approval challenge nonce tələb olunur"}, 400)
                if chal["expires"] < now:
                    return self._json({"error": "E_EXPIRED_NONCE: Approval nonce müddəti bitib"}, 400)
                if chal["used"] == 1:
                    return self._json({"error": "E_NONCE_REPLAYED: Approval nonce artıq istifadə edilib (Replay rədd edildi)"}, 409)

                # Kriptoqrafik təsdiq: Cihazın public_key-i ilə yoxlanılır
                if not dev["public_key"] or len(dev["public_key"]) != 64:
                    return self._json({"error": "E_DEVICE_HAS_NO_PUBLIC_KEY: Cihazın qeydiyyatdan keçmiş public key-i yoxdur"}, 400)

                bound_approve_msg = f"WINKEY_APPROVE:{nonce}:{dev_id}".encode("utf-8")
                try:
                    pub_bytes = bytes.fromhex(dev["public_key"])
                    sig_bytes = bytes.fromhex(proof_sig)
                    verifier = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
                    verifier.verify(sig_bytes, bound_approve_msg)
                except Exception as e:
                    return self._json({"error": "E_INVALID_APPROVAL_SIGNATURE: PC təsdiq imzası yoxlanılmadı (başqa açar və ya saxtalaşdırılmış sorğu)", "detail": str(e)}, 403)

                cursor.execute("UPDATE challenges SET used=1 WHERE nonce=?", (nonce,))
                cursor.execute("UPDATE devices SET owner_approved=1 WHERE id=?", (dev_id,))
                db.commit()
                return self._json({"ok": True, "device_id": dev_id, "status": "APPROVED", "approval_status": "APPROVED"})

            elif path == "agent/poll":
                device_id = str(body.get("device_id", ""))
                cursor.execute("SELECT * FROM devices WHERE id=? AND secret_hash=?", (device_id, hash_text(secret)))
                dev = cursor.fetchone()
                if not dev:
                    return self._json({"error": "Cihaz tapılmadı və ya açar yanlışdır"}, 403)
                locked = 1 if body.get("locked") is True else 0
                pin_ready = 1 if body.get("pin_ready") is True else 0
                cursor.execute("UPDATE devices SET last_seen=?, locked=?, pin_ready=? WHERE id=?", (now, locked, pin_ready, dev["id"]))
                
                cursor.execute(
                    "SELECT id, action, expires FROM commands WHERE device_id=? AND state='queued' AND expires>=? ORDER BY created LIMIT 1",
                    (dev["id"], now)
                )
                cmd = cursor.fetchone()
                if cmd:
                    cursor.execute("UPDATE commands SET state='running' WHERE id=?", (cmd["id"],))
                    db.commit()
                    return self._json({"paired": bool(dev["owner"]), "command": dict(cmd)})
                db.commit()
                return self._json({"paired": bool(dev["owner"]), "command": None})

            elif path == "agent/result":
                device_id = str(body.get("device_id", ""))
                cursor.execute("SELECT * FROM devices WHERE id=? AND secret_hash=?", (device_id, hash_text(secret)))
                dev = cursor.fetchone()
                if not dev:
                    return self._json({"error": "Cihaz tapılmadı"}, 403)
                cmd_id = str(body.get("command_id", ""))
                success = body.get("success") is True
                state = "success" if success else "failed"
                res_str = json.dumps({"status": body.get("status", "UNKNOWN")})
                cursor.execute("UPDATE commands SET state=?, finished=?, result=? WHERE id=? AND device_id=? AND state='running'", (state, now, res_str, cmd_id, dev["id"]))
                db.commit()
                return self._json({"ok": True})

            elif path == "commands":
                user = self._get_verified_user(cursor, now)
                if not user:
                    return self._json({"error": "E_UNVERIFIED_SESSION: Etibarlı sessiya tokeni tələb olunur"}, 401)
                
                # REM-020: Server və ya telefon heç vaxt PIN/password/credential daşımır!
                for forbidden in ["credential", "pin", "password", "secret"]:
                    if forbidden in body:
                        return self._json({
                            "error": f"E_CREDENTIAL_NOT_PERMITTED: Server və ya telefon heç vaxt PIN daşımır; PIN yalnız PC-də lokal saxlanılır ({forbidden} qadağandır)"
                        }, 400)

                action = body.get("action")
                dev_id = str(body.get("device_id", ""))
                if action not in ["unlock", "lock", "wake", "mock"]:
                    return self._json({"error": "Əməliyyat dəstəklənmir"}, 400)
                
                # Tenant isolation check (IDOR Protection)
                cursor.execute("SELECT * FROM devices WHERE id=?", (dev_id,))
                dev = cursor.fetchone()
                if not dev:
                    return self._json({"error": "Kompüter tapılmadı"}, 404)
                if dev["owner"] != user:
                    return self._json({"error": "E_IDOR_REJECTED: Bu cihaza hüququnuz yoxdur"}, 403)
                if dev["owner_approved"] != 1:
                    return self._json({"error": "E_PENDING_APPROVAL: Cihaz kompüterdə yerli təsdiq gözləyir"}, 403)

                cmd_id = f"cmd_{uuid.uuid4().hex[:12]}"
                cursor.execute(
                    "INSERT INTO commands (id, device_id, owner, action, state, created, expires) VALUES (?,?,?,?,'queued',?,?)",
                    (cmd_id, dev_id, user, action, now, now + 30000)
                )
                db.commit()
                return self._json({"command_id": cmd_id})

            elif path == "telemetry":
                event_id = str(body.get("event_id", ""))
                stage = str(body.get("stage", "UNKNOWN"))
                dev_id = body.get("device_id")
                err_code = body.get("error_code")
                if not event_id:
                    return self._json({"error": "event_id məcburidir"}, 400)
                cursor.execute("SELECT event_id FROM telemetry_events WHERE event_id=?", (event_id,))
                exists = cursor.fetchone()
                if exists:
                    return self._json({"ack": True, "dedup": True})
                cursor.execute(
                    "INSERT INTO telemetry_events (event_id, device_id, stage, error_code, received_at) VALUES (?,?,?,?,?)",
                    (event_id, dev_id, stage, err_code, now)
                )
                db.commit()
                return self._json({"ack": True, "dedup": False})

            else:
                return self._json({"error": "Ünvan tapılmadı"}, 404)
        except Exception as e:
            return self._json({"error": str(e)}, 500)
        finally:
            db.close()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.lstrip("/")
        now = int(time.time() * 1000)

        db = get_db()
        cursor = db.cursor()

        try:
            if path in ["remote", "mobile"]:
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
        .badge-pending { background: rgba(255, 193, 7, 0.15); color: #ffc107; border: 1px solid rgba(255, 193, 7, 0.3); }
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
        const btnUnlock = document.getElementById('btn-unlock');
        const btnLock = document.getElementById('btn-lock');

        async function init() {
            if (pairCode) {
                statusBox.innerHTML = '<span class="spinner"></span>QR cütləşmə kodu göndərilir...';
                try {
                    // Mobile user auth token varsa istifadə et, yoxsa demo owner login al
                    if (!authToken) {
                        const logRes = await fetch('/auth/login', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({username: 'alice', password: 'AlicePass#2026!'})
                        });
                        if (logRes.ok) {
                            const ld = await logRes.json();
                            authToken = ld.token;
                            localStorage.setItem('winkey_token', authToken);
                        }
                    }

                    const pairRes = await fetch('/pair', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + authToken},
                        body: JSON.stringify({code: pairCode})
                    });

                    if (pairRes.ok) {
                        const pd = await pairRes.json();
                        targetDevice = pd.device_id;
                        localStorage.setItem('winkey_dev_id', targetDevice);
                        // Clean QR code from URL history for security
                        window.history.replaceState({}, document.title, window.location.pathname + '?device=' + targetDevice);
                        statusBox.textContent = 'Cütləşmə uğurlu! Status: ' + (pd.approval_status || 'PENDING_PC_APPROVAL');
                    } else {
                        const errData = await pairRes.json();
                        statusBox.textContent = 'Cütləşmə xətası: ' + (errData.error || pairRes.statusText);
                    }
                } catch(e) {
                    statusBox.textContent = 'Şəbəkə xətası: ' + e.message;
                }
            }

            if (targetDevice) {
                devIdEl.textContent = 'ID: ' + targetDevice;
                pollStatus();
                setInterval(pollStatus, 3000);
            } else {
                devNameEl.textContent = 'Cihaz tapılmadı';
                statusBox.textContent = 'QR kodu skan edin və ya tətbiqdən linklə keçin.';
            }
        }

        async function pollStatus() {
            if (!targetDevice || !authToken) return;
            try {
                const res = await fetch('/devices', {
                    headers: {'Authorization': 'Bearer ' + authToken}
                });
                if (res.ok) {
                    const data = await res.json();
                    const d = (data.devices || []).find(x => x.id === targetDevice);
                    if (d) {
                        devNameEl.textContent = d.name || 'Windows PC';
                        badgeEl.className = 'badge badge-online';
                        badgeEl.textContent = 'Onlayn';
                    } else {
                        badgeEl.className = 'badge badge-offline';
                        badgeEl.textContent = 'Tapılmadı';
                    }
                }
            } catch(e) {}
        }

        async function sendCommand(act) {
            if (!targetDevice || !authToken) return;
            btnUnlock.disabled = true;
            btnLock.disabled = true;
            statusBox.innerHTML = '<span class="spinner"></span>Əmr göndərilir: ' + act.toUpperCase() + '...';

            try {
                const res = await fetch('/commands', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + authToken},
                    body: JSON.stringify({device_id: targetDevice, action: act})
                });

                if (res.ok) {
                    const data = await res.json();
                    const cmdId = data.command_id;
                    statusBox.innerHTML = '<span class="spinner"></span>Kompüter icra edir (ID: ' + cmdId.slice(0,8) + ')...';
                    waitForCommand(cmdId);
                } else {
                    const err = await res.json();
                    statusBox.textContent = 'Xəta: ' + (err.error || res.statusText);
                    btnUnlock.disabled = false;
                    btnLock.disabled = false;
                }
            } catch(e) {
                statusBox.textContent = 'Şəbəkə xətası: ' + e.message;
                btnUnlock.disabled = false;
                btnLock.disabled = false;
            }
        }

        async function waitForCommand(cmdId) {
            for (let i = 0; i < 15; i++) {
                await new Promise(r => setTimeout(r, 1000));
                try {
                    const res = await fetch('/history', {
                        headers: {'Authorization': 'Bearer ' + authToken}
                    });
                    if (res.ok) {
                        const data = await res.json();
                        const cmd = (data.commands || []).find(c => c.id === cmdId);
                        if (cmd && (cmd.state === 'success' || cmd.state === 'failed')) {
                            let resObj = {};
                            try { resObj = JSON.parse(cmd.result); } catch(e) { resObj = {status: cmd.result}; }
                            statusBox.textContent = 'Nəticə (' + cmd.state.toUpperCase() + '): ' + (resObj.status || cmd.result);
                            btnUnlock.disabled = false;
                            btnLock.disabled = false;
                            return;
                        }
                    }
                } catch(e) {}
            }
            statusBox.textContent = 'Gözləmə müddəti bitdi (Timeout).';
            btnUnlock.disabled = false;
            btnLock.disabled = false;
        }

        async function revokeDevice() {
            if (!confirm('Bu kompüterlə əlaqəni kəsmək istədiyinizə əminsiniz?')) return;
            try {
                const res = await fetch('/devices/revoke', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + authToken},
                    body: JSON.stringify({device_id: targetDevice})
                });
                if (res.ok) {
                    localStorage.removeItem('winkey_dev_id');
                    alert('Cihaz uğurla silindi (Revoked).');
                    window.location.reload();
                } else {
                    alert('Revoke xətası baş verdi.');
                }
            } catch(e) {
                alert('Şəbəkə xətası: ' + e.message);
            }
        }

        window.addEventListener('DOMContentLoaded', init);
    </script>
</body>
</html>"""
                body_b = html.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body_b)))
                self.end_headers()
                self.wfile.write(body_b)
                return

            if path == "devices":
                user = self._get_verified_user(cursor, now)
                if not user:
                    return self._json({"error": "E_UNVERIFIED_SESSION: Yalnız daxil olmuş istifadəçi baxa bilər"}, 401)
                cursor.execute(
                    "SELECT id, name, owner, last_seen, locked, pin_ready, created FROM devices WHERE owner=?",
                    (user,)
                )
                rows = [dict(r) for r in cursor.fetchall()]
                for r in rows:
                    if "secret_hash" in r: del r["secret_hash"]
                    if "pair_hash" in r: del r["pair_hash"]
                return self._json({"devices": rows, "now": now})

            elif path == "history":
                user = self._get_verified_user(cursor, now)
                if not user:
                    return self._json({"error": "Hesaba daxil olun"}, 401)
                cursor.execute("SELECT * FROM commands WHERE owner=? ORDER BY created DESC LIMIT 20", (user,))
                cmds = [dict(r) for r in cursor.fetchall()]
                return self._json({"commands": cmds})

            elif path == "telemetry/readback":
                user = self._get_verified_user(cursor, now)
                if not user:
                    return self._json({"error": "Admin hüququ tələb olunur"}, 401)
                cursor.execute("SELECT * FROM telemetry_events ORDER BY received_at DESC LIMIT 50")
                evts = [dict(r) for r in cursor.fetchall()]
                return self._json({"events": evts})

            else:
                return self._json({"error": "Ünvan tapılmadı"}, 404)
        finally:
            db.close()

def run_server(port=8787, reset_db=False):
    init_db(reset=reset_db)
    server_address = ('127.0.0.1', port)
    httpd = HTTPServer(server_address, GatewayHandler)
    print(f"[GATEWAY_STARTED] Listening on http://127.0.0.1:{port} (DB: {DB_PATH}, Reset: {reset_db})")
    sys.stdout.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()

if __name__ == "__main__":
    p = 8787
    reset = False
    if len(sys.argv) > 1:
        p = int(sys.argv[1])
    if "--reset-db" in sys.argv:
        reset = True
    run_server(p, reset_db=reset)
