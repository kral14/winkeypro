"""
WinKey Pro — Shared Multi-Tenant Gateway Service Layer
Spesifikasiya: plan/GEMINI_WEBSOCKET_BATCH.md (Paket A, B, D)

Bu modul HTTP və WebSocket sorğuları üçün vahid biznes və autentifikasiya
məntiqini təmin edir. Bütün verilənlər bazası əməliyyatları həm SQLite,
həm də PostgreSQL ilə 100% uyğundur.
"""

import time
import secrets
import hashlib
from typing import Dict, Any, Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519

class GatewayService:
    def __init__(self, db, admin_secret_fn):
        self.db = db
        self.admin_secret_fn = admin_secret_fn
        self.dispatch_gate_hook = None

    def get_admin_secret(self) -> str:
        if callable(self.admin_secret_fn):
            return str(self.admin_secret_fn() or "")
        return str(self.admin_secret_fn or "")

    def record_incident(self, stage: str, code: str, device_id: Optional[str] = None):
        """Təhlükəsiz insident loqu: heç vaxt PIN, token və ya məxfi body saxlamır."""
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
            pass

    def authenticate_agent(self, conn, device_id: str, bearer_token: Optional[str]) -> bool:
        if not bearer_token or not device_id:
            return False
        sec_hash = hashlib.sha256(bearer_token.encode("utf-8")).hexdigest()
        row = conn.execute(
            "SELECT device_id FROM devices WHERE device_secret_hash = ? AND status = 'ACTIVE'",
            (sec_hash,)
        ).fetchone()
        return bool(row and row["device_id"] == device_id)

    def authenticate_mobile_session(self, conn, token: Optional[str]) -> Optional[Dict[str, Any]]:
        if not token:
            return None
        sess = conn.execute(
            "SELECT session_token, device_id, expires_at FROM mobile_sessions WHERE session_token = ? AND (expires_at = 0 OR expires_at > ?)",
            (token, time.time())
        ).fetchone()
        return dict(sess) if sess else None

    # --- AGENT REGISTRATION & CHALLENGE ---

    def create_challenge(self, purpose: str, device_id: str) -> Dict[str, Any]:
        nonce = secrets.token_hex(16)
        with self.db.get_conn() as conn:
            conn.execute(
                "INSERT INTO challenges (nonce, purpose, device_id, created_at, expires_at, used) VALUES (?, ?, ?, ?, ?, 0) "
                "ON CONFLICT (nonce) DO UPDATE SET purpose=excluded.purpose, device_id=excluded.device_id, created_at=excluded.created_at, expires_at=excluded.expires_at, used=excluded.used",
                (nonce, purpose, device_id, time.time(), time.time() + 120)
            )
            conn.commit()
        return {"nonce": nonce, "device_id": device_id, "purpose": purpose}

    def register_device(self, data: Dict[str, Any], bearer_token: Optional[str]) -> Tuple[int, Dict[str, Any]]:
        device_id = data.get("device_id")
        computer_name = data.get("computer_name", "PC")
        pub_hex = data.get("public_key_hex", "")
        proof_sig = data.get("proof_signature_hex")
        nonce = data.get("nonce")

        if not device_id or not isinstance(device_id, str):
            return 400, {"error": "E_INVALID_DEVICE_ID", "message": "device_id məcburidir"}

        if not pub_hex or not isinstance(pub_hex, str) or len(pub_hex) != 64:
            return 400, {"error": "E_INVALID_PUBLIC_KEY", "message": "public_key_hex 64 simvollu hex olmalıdır"}

        try:
            pub_bytes = bytes.fromhex(pub_hex)
            if len(pub_bytes) != 32:
                return 400, {"error": "E_INVALID_PUBLIC_KEY", "message": "Açar uzunluğu 32 bayt olmalıdır"}
            verifier = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        except Exception as e:
            return 400, {"error": "E_INVALID_PUBLIC_KEY", "message": f"Ed25519 açar formatı xətası: {e}"}

        if not nonce or not proof_sig:
            return 400, {
                "error": "E_MISSING_PROOF",
                "message": "Qeydiyyat üçün nonce və cryptographic proof_signature_hex məcburidir"
            }

        with self.db.get_conn() as conn:
            chal = conn.execute(
                "SELECT * FROM challenges WHERE nonce = ? AND used = 0 AND expires_at > ? AND purpose = 'register'",
                (nonce, time.time())
            ).fetchone()
            if not chal:
                return 400, {"error": "E_INVALID_NONCE", "message": "Nonce tapılmadı, istifadə olunub və ya vaxtı bitib"}

            if chal["device_id"] and chal["device_id"] != device_id:
                return 400, {"error": "E_CHALLENGE_DEVICE_MISMATCH", "message": "Nonce başqa cihaz üçün yaradılıb"}

            # Atomik One-Use istehlakı
            upd = conn.execute("UPDATE challenges SET used = 1 WHERE nonce = ? AND used = 0", (nonce,)).rowcount
            if upd != 1:
                return 409, {"error": "E_NONCE_REPLAY", "message": "Nonce artıq istifadə olunub"}

            bound_msg = f"WINKEY_REGISTER:{nonce}:{device_id}".encode("utf-8")
            try:
                sig_bytes = bytes.fromhex(proof_sig)
                verifier.verify(sig_bytes, bound_msg)
            except Exception as e:
                return 400, {"error": "E_INVALID_PROOF", "message": f"Kriptoqrafik imza təsdiqlənmədi: {e}"}

            existing = conn.execute("SELECT public_key_hex, device_secret_hash, status FROM devices WHERE device_id = ?", (device_id,)).fetchone()
            if existing:
                if existing["public_key_hex"] != pub_hex:
                    return 409, {
                        "error": "E_DEVICE_ALREADY_EXISTS_OWNERSHIP_VIOLATION",
                        "message": "Bu cihaz ID başqa ictimai açarla qeydiyyatdan keçib. Cihaz oğurlana bilməz!"
                    }

                can_rotate = False
                if bearer_token:
                    sec_hash = hashlib.sha256(bearer_token.encode("utf-8")).hexdigest()
                    if sec_hash == existing["device_secret_hash"]:
                        can_rotate = True
                if not can_rotate:
                    return 409, {
                        "error": "E_DEVICE_ALREADY_REGISTERED",
                        "message": "Cihaz artıq qeydiyyatdan keçib. Açıq ictimai açarla icazəsiz secret rotasiyası qadağandır!"
                    }

                new_secret = secrets.token_hex(32)
                new_sec_hash = hashlib.sha256(new_secret.encode("utf-8")).hexdigest()
                conn.execute("UPDATE devices SET device_secret_hash = ?, last_seen_at = ? WHERE device_id = ?", (new_sec_hash, time.time(), device_id))
                conn.commit()
                return 200, {"device_id": device_id, "device_secret": new_secret, "status": "ROTATED"}

            secret = secrets.token_hex(32)
            sec_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest()

            conn.execute(
                "INSERT INTO devices (device_id, computer_name, public_key_hex, device_secret_hash, status, created_at, last_seen_at) VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?)",
                (device_id, computer_name, pub_hex, sec_hash, time.time(), time.time())
            )
            conn.commit()

        return 200, {"device_id": device_id, "device_secret": secret, "status": "REGISTERED"}

    # --- PAIRING & MOBILE SESSIONS ---

    def create_pair_request(self, device_id: str, bearer_token: Optional[str]) -> Tuple[int, Dict[str, Any]]:
        with self.db.get_conn() as conn:
            if not self.authenticate_agent(conn, device_id, bearer_token):
                return 401, {"error": "E_UNAUTHORIZED_AGENT", "message": "Cihaz autentifikasiyası tələb olunur"}

            pair_code = "PAIR_" + secrets.token_hex(6).upper()
            expires_at = time.time() + 120
            conn.execute(
                "INSERT INTO pairing_requests (pair_code, device_id, challenge_hex, status, expires_at, created_at) VALUES (?, ?, 'chal', 'PENDING', ?, ?) "
                "ON CONFLICT (pair_code) DO UPDATE SET device_id=excluded.device_id, challenge_hex=excluded.challenge_hex, status=excluded.status, expires_at=excluded.expires_at, created_at=excluded.created_at",
                (pair_code, device_id, expires_at, time.time())
            )
            conn.commit()

        return 200, {"pair_code": pair_code, "expires_at": expires_at, "device_id": device_id}

    def claim_pair(self, pair_code: str) -> Tuple[int, Dict[str, Any]]:
        if not pair_code:
            return 400, {"error": "E_MISSING_PAIR_CODE", "message": "pair_code tələb olunur"}

        with self.db.get_conn() as conn:
            req = conn.execute("SELECT * FROM pairing_requests WHERE pair_code = ?", (pair_code,)).fetchone()
            if not req:
                return 404, {"error": "E_PAIR_CODE_NOT_FOUND", "message": "Cütləşmə kodu tapılmadı və ya etibarsızdır"}

            if req["status"] != "PENDING":
                if req["status"] == "CLAIMED":
                    return 409, {"error": "E_REPLAY_REJECTED", "message": "Bu kod artıq istifadə edilib və birdəfəlikdir!"}
                return 400, {"error": "E_INVALID_PAIR_STATUS", "message": f"Kodun statusu etibarsızdır: {req['status']}"}

            if req["expires_at"] < time.time():
                return 410, {"error": "E_PAIR_CODE_EXPIRED", "message": "Cütləşmə kodunun vaxtı bitib"}

            device_id = req["device_id"]
            dev = conn.execute("SELECT status FROM devices WHERE device_id = ?", (device_id,)).fetchone()
            if not dev or dev["status"] != "ACTIVE":
                return 403, {"error": "E_DEVICE_NOT_ACTIVE", "message": "Cihaz aktiv deyil və ya ləğv edilib"}

            cur = conn.execute(
                "UPDATE pairing_requests SET status = 'CLAIMED' WHERE pair_code = ? AND status = 'PENDING' AND expires_at > ?",
                (pair_code, time.time())
            )
            if cur.rowcount != 1:
                return 409, {"error": "E_PAIR_CLAIM_CONFLICT", "message": "Cütləşmə kodu artıq başqa sorğu tərəfindən istifadə edilib"}

            session_token = "sess_" + secrets.token_hex(24)
            conn.execute(
                "INSERT INTO mobile_sessions (session_token, device_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (session_token, device_id, time.time(), 0)
            )
            conn.commit()

        return 200, {
            "success": True,
            "session_token": session_token,
            "device_id": device_id,
            "expires_in": None,
            "persistent": True
        }

    def revoke_mobile_session(self, token: Optional[str]) -> Tuple[int, Dict[str, Any], Optional[str]]:
        """Sessiyanı ləğv edir və WebSocket bağlantılarını kəsmək üçün device_id qaytarır."""
        if not token:
            return 401, {"error": "E_MISSING_TOKEN", "message": "Sessiya tokeni tələb olunur"}, None

        with self.db.get_conn() as conn:
            sess = conn.execute("SELECT session_token, device_id FROM mobile_sessions WHERE session_token = ?", (token,)).fetchone()
            if not sess:
                return 401, {"error": "E_INVALID_SESSION", "message": "Sessiya tapılmadı və ya artıq ləğv edilib"}, None
            device_id = sess["device_id"]
            conn.execute("DELETE FROM mobile_sessions WHERE session_token = ?", (token,))
            conn.commit()

        return 200, {"success": True, "message": "Mobil sessiya serverdə uğurla ləğv edildi"}, device_id

    # --- COMMANDS ---

    def enqueue_command(self, req_device_id: str, action: str, request_id: Optional[str], token: Optional[str], raw_data: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        # ZERO-PIN ENFORCEMENT
        for forbidden in ["pin", "credential", "password", "secret"]:
            if forbidden in raw_data:
                return 400, {
                    "error": "E_CREDENTIAL_NOT_PERMITTED",
                    "message": "Mobil şəbəkə üzərindən PIN göndərilməsi qəti qadağandır! PIN yalnız PC daxilində DPAPI anbarında saxlanır."
                }

        with self.db.get_conn() as conn:
            sess = conn.execute("SELECT device_id FROM mobile_sessions WHERE session_token = ? AND (expires_at = 0 OR expires_at > ?)", (token, time.time())).fetchone()
            if not sess:
                return 401, {"error": "E_INVALID_SESSION"}

            if sess["device_id"] != req_device_id:
                return 403, {"error": "E_TENANT_IDOR_FORBIDDEN", "message": "Başqa istifadəçinin cihazına komanda göndərə bilməzsiniz!"}

            dev = conn.execute("SELECT status FROM devices WHERE device_id = ?", (req_device_id,)).fetchone()
            if not dev or dev["status"] != "ACTIVE":
                return 403, {"error": "E_DEVICE_NOT_ACTIVE", "message": "Cihaz deaktiv edilib və ya aktiv deyil"}

            if action not in ("lock", "unlock", "mock"):
                return 400, {"error": "E_INVALID_ACTION"}

            if request_id is not None and (not isinstance(request_id, str) or len(request_id) != 32 or any(c not in '0123456789abcdef' for c in request_id)):
                return 400, {'error': 'E_INVALID_REQUEST_ID'}

            cmd_id = 'cmd_' + (hashlib.sha256((token + ':' + request_id).encode()).hexdigest()[:24]
                              if request_id else secrets.token_hex(12))

            conn.execute('UPDATE devices SET status = status WHERE device_id = ?', (req_device_id,))
            inserted = conn.execute(
                "INSERT INTO commands (command_id, device_id, action, status, created_at) VALUES (?, ?, ?, 'pending', ?) ON CONFLICT (command_id) DO NOTHING",
                (cmd_id, req_device_id, action, time.time())
            )
            # Yalnız icraya verilməmiş köhnə pending lock/unlock əmrləri superseded edilir
            if inserted.rowcount == 1 and action in ('lock', 'unlock'):
                conn.execute(
                    "UPDATE commands SET status = 'superseded', completed_at = ?, result_status = 'SUPERSEDED_BY_LATEST' WHERE device_id = ? AND status = 'pending' AND command_id <> ? AND action IN ('lock', 'unlock')",
                    (time.time(), req_device_id, cmd_id)
                )
            existing = conn.execute('SELECT device_id, action, status, result_status FROM commands WHERE command_id = ?', (cmd_id,)).fetchone()
            conn.commit()

            if existing['device_id'] != req_device_id or existing['action'] != action:
                return 409, {'error': 'E_REQUEST_ID_CONFLICT'}

            is_new = (inserted.rowcount == 1)
            cmd_status = "queued" if is_new else existing['status']
            return 200, {
                "success": True,
                "command_id": cmd_id,
                "action": action,
                "status": cmd_status,
                "is_new": is_new,
                "result": existing['result_status']
            }

    def claim_command_for_ws(self, device_id: str, command_id: str, claim_owner: str, lease_sec: float = 15.0) -> bool:
        now = time.time()
        expires_at = now + 60.0
        with self.db.get_conn() as conn:
            res = conn.execute(
                """UPDATE commands
                   SET status = 'claimed', claim_owner = ?, claim_expires_at = ?
                   WHERE command_id = ? AND device_id = ?
                     AND status = 'pending'""",
                (claim_owner, expires_at, command_id, device_id)
            )
            conn.commit()
            return (res.rowcount == 1)

    def expire_uncertain_commands(self):
        """One dispatch attempt per command ID. Never replay an ambiguous physical effect."""
        expired = []
        now = time.time()
        with self.db.get_conn() as conn:
            rows = conn.execute("SELECT command_id, device_id FROM commands WHERE status IN ('claimed', 'delivered') AND (claim_expires_at < ? OR (claim_expires_at IS NULL AND created_at < ?))", (now, now - 60)).fetchall()
            for row in rows:
                changed = conn.execute("UPDATE commands SET status='failed', result_status='INDETERMINATE_DELIVERY_TIMEOUT', completed_at=? WHERE command_id=? AND status IN ('claimed', 'delivered')", (now, row['command_id']))
                if changed.rowcount == 1:
                    expired.append(dict(row))
            conn.commit()
        for row in expired:
            self.record_incident('/commands/recovery', 'INDETERMINATE_DELIVERY_TIMEOUT', row['device_id'])
        return expired

    def fail_uncertain_delivery(self, command_id):
        with self.db.get_conn() as conn:
            row = conn.execute("SELECT device_id FROM commands WHERE command_id=?", (command_id,)).fetchone()
            changed = conn.execute("UPDATE commands SET status='failed', result_status='INDETERMINATE_DELIVERY', completed_at=? WHERE command_id=? AND status='claimed'", (time.time(), command_id))
            conn.commit()
        if row and changed.rowcount == 1:
            self.record_incident('/commands/dispatch', 'INDETERMINATE_DELIVERY', row['device_id'])

    def mark_command_delivered(self, command_id: str, claim_owner: str) -> bool:
        with self.db.get_conn() as conn:
            res = conn.execute(
                "UPDATE commands SET status = 'delivered' WHERE command_id = ? AND status = 'claimed' AND claim_owner = ?",
                (command_id, claim_owner)
            )
            conn.commit()
            return (res.rowcount == 1)

    def release_command_claim(self, command_id: str, claim_owner: str) -> bool:
        with self.db.get_conn() as conn:
            res = conn.execute(
                "UPDATE commands SET status = 'pending', claim_owner = NULL, claim_expires_at = NULL WHERE command_id = ? AND claim_owner = ? AND status = 'claimed'",
                (command_id, claim_owner)
            )
            conn.commit()
            return (res.rowcount == 1)

    def poll_agent(self, device_id: str, locked: bool, pin_ready: bool, bearer_token: Optional[str]) -> Tuple[int, Dict[str, Any]]:
        if not device_id:
            return 400, {"error": "E_MISSING_DEVICE_ID"}

        now = time.time()
        claim_owner = f"http:{secrets.token_hex(8)}"
        expires_at = now + 60.0

        with self.db.get_conn() as conn:
            if not self.authenticate_agent(conn, device_id, bearer_token):
                return 401, {"error": "E_UNAUTHORIZED_AGENT", "message": "Agent autentifikasiyası (Bearer device_secret) uğursuz oldu"}

            dev = conn.execute("SELECT status FROM devices WHERE device_id = ?", (device_id,)).fetchone()
            if not dev or dev["status"] != "ACTIVE":
                return 403, {"error": "E_DEVICE_NOT_ACTIVE", "message": "Cihaz deaktiv edilib"}

            conn.execute(
                "UPDATE devices SET last_seen_at = ?, locked = ?, pin_ready = ? WHERE device_id = ?",
                (now, 1 if locked else 0, 1 if pin_ready else 0, device_id)
            )
            cmd = conn.execute(
                """SELECT command_id, action FROM commands
                   WHERE device_id = ? AND status = 'pending'
                   ORDER BY created_at ASC LIMIT 1""",
                (device_id,)
            ).fetchone()

            if cmd:
                cid = cmd["command_id"]
                res = conn.execute(
                    """UPDATE commands
                       SET status = 'delivered', claim_owner = ?, claim_expires_at = ?
                       WHERE command_id = ? AND status = 'pending'""",
                    (claim_owner, expires_at, cid)
                )
                conn.commit()
                if res.rowcount == 1:
                    return 200, {"command": {"id": cid, "action": cmd["action"]}}

            conn.commit()
            return 200, {"command": None}

    def submit_agent_result(self, cmd_id: str, device_id: str, success: bool, status_str: str, bearer_token: Optional[str]) -> Tuple[int, Dict[str, Any]]:
        with self.db.get_conn() as conn:
            if not device_id or not self.authenticate_agent(conn, device_id, bearer_token):
                return 401, {"error": "E_UNAUTHORIZED_AGENT", "message": "Etibarlı agent secret tələb olunur"}

            cmd = conn.execute("SELECT command_id, device_id, status, result_status FROM commands WHERE command_id = ?", (cmd_id,)).fetchone()
            if not cmd:
                return 404, {"error": "E_COMMAND_NOT_FOUND"}

            if cmd["device_id"] != device_id:
                return 403, {"error": "E_COMMAND_NOT_OWNED", "message": "Bu komanda sizin cihaza aid deyil!"}

            # If already terminal (completed, failed, superseded), do not mutate historical timestamp/state
            if cmd["status"] in ("completed", "failed", "superseded"):
                return 200, {"acknowledged": True, "already_terminal": True, "status": cmd["status"], "result": cmd['result_status']}

            new_status = "completed" if success else "failed"
            updated = conn.execute(
                "UPDATE commands SET status = ?, completed_at = ?, result_status = ?, claim_owner = NULL, claim_expires_at = NULL WHERE command_id = ? AND status IN ('claimed', 'delivered')",
                (new_status, time.time(), status_str[:128], cmd_id)
            )
            conn.commit()
            if updated.rowcount != 1:
                actual = conn.execute("SELECT status, result_status FROM commands WHERE command_id=?", (cmd_id,)).fetchone()
                if actual and actual['status'] in ('completed', 'failed', 'superseded'):
                    return 200, {"acknowledged": True, "already_terminal": True, "status": actual['status'], "result": actual['result_status']}
                return 409, {"error": "E_COMMAND_NOT_DISPATCHED"}

        if not success:
            safe_code = status_str.split(':', 1)[0].split(' ', 1)[0]
            self.record_incident('/agent/result', safe_code, device_id)

        return 200, {"acknowledged": True}

    def get_device_status(self, device_id: str, bearer_token: Optional[str]) -> Tuple[int, Dict[str, Any]]:
        with self.db.get_conn() as conn:
            sess = conn.execute("SELECT device_id FROM mobile_sessions WHERE session_token = ? AND (expires_at = 0 OR expires_at > ?)", (bearer_token, time.time())).fetchone()
            if not sess:
                return 401, {"error": "E_INVALID_SESSION"}

            if sess["device_id"] != device_id:
                return 403, {"error": "E_TENANT_IDOR_FORBIDDEN", "message": "Bu cihazın statusuna baxmaq icazəniz yoxdur"}

            dev = conn.execute("SELECT device_id, computer_name, status, last_seen_at, locked, pin_ready FROM devices WHERE device_id = ?", (device_id,)).fetchone()
            if not dev:
                return 404, {"error": "E_DEVICE_NOT_FOUND"}

            return 200, {
                "device_id": dev["device_id"],
                "computer_name": dev["computer_name"],
                "status": dev["status"],
                "last_seen_at": dev["last_seen_at"],
                "locked": bool(dev["locked"]),
                "pin_ready": bool(dev["pin_ready"])
            }

    def get_command_status(self, cmd_id: str, bearer_token: Optional[str]) -> Tuple[int, Dict[str, Any]]:
        if not bearer_token:
            return 401, {"error": "E_MISSING_TOKEN"}

        with self.db.get_conn() as conn:
            sess = conn.execute("SELECT device_id FROM mobile_sessions WHERE session_token = ? AND (expires_at = 0 OR expires_at > ?)", (bearer_token, time.time())).fetchone()
            if not sess:
                return 401, {"error": "E_INVALID_SESSION"}

            cmd = conn.execute("SELECT command_id, device_id, action, status, result_status AS result, created_at, completed_at AS executed_at FROM commands WHERE command_id = ?", (cmd_id,)).fetchone()
            if not cmd:
                return 404, {"error": "E_COMMAND_NOT_FOUND"}

            if cmd["device_id"] != sess["device_id"]:
                return 403, {"error": "E_TENANT_IDOR_FORBIDDEN", "message": "Başqa cihazın əmrinə giriş qadağandır"}

            return 200, dict(cmd)

    # --- ADMIN ENDPOINTS ---

    def admin_get_devices(self, admin_sec: Optional[str]) -> Tuple[int, Dict[str, Any]]:
        if not admin_sec or admin_sec != self.get_admin_secret():
            return 403, {"error": "E_ADMIN_UNAUTHORIZED", "message": "Admin icazəsi tələb olunur"}

        with self.db.get_conn() as conn:
            rows = conn.execute("SELECT device_id, computer_name, status, created_at, last_seen_at, locked, pin_ready FROM devices ORDER BY created_at DESC").fetchall()
            return 200, {"devices": [dict(r) for r in rows]}

    def admin_get_telemetry(self, admin_sec: Optional[str]) -> Tuple[int, Dict[str, Any]]:
        if not admin_sec or admin_sec != self.get_admin_secret():
            return 403, {"error": "E_ADMIN_UNAUTHORIZED", "message": "Admin icazəsi tələb olunur"}

        with self.db.get_conn() as conn:
            rows = conn.execute("SELECT * FROM telemetry_events ORDER BY received_at DESC LIMIT 100").fetchall()
            return 200, {"telemetry": [dict(r) for r in rows]}

    def admin_set_device_status(self, device_id: str, target_status: str, admin_sec: Optional[str]) -> Tuple[int, Dict[str, Any]]:
        if not admin_sec or admin_sec != self.get_admin_secret():
            return 403, {"error": "E_ADMIN_UNAUTHORIZED"}

        with self.db.get_conn() as conn:
            conn.execute("UPDATE devices SET status = ? WHERE device_id = ?", (target_status, device_id))
            if target_status == 'REVOKED':
                conn.execute("DELETE FROM mobile_sessions WHERE device_id = ?", (device_id,))
            conn.commit()

        return 200, {'device_id': device_id, 'status': target_status}
