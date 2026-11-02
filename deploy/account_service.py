"""PC account authentication. Remote control continues using QR device sessions."""
import hashlib
import hmac
import re
import secrets
import time


def initialize_accounts(conn):
    for sql in (
        '''CREATE TABLE IF NOT EXISTS user_accounts (
            account_id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL,
            password_salt TEXT NOT NULL, password_hash TEXT NOT NULL,
            created_at DOUBLE PRECISION NOT NULL)''',
        '''CREATE TABLE IF NOT EXISTS account_sessions (
            token_hash TEXT PRIMARY KEY, account_id TEXT NOT NULL,
            expires_at DOUBLE PRECISION NOT NULL)''',
        '''CREATE TABLE IF NOT EXISTS account_login_limits (
            email TEXT PRIMARY KEY, attempts INTEGER NOT NULL,
            window_start DOUBLE PRECISION NOT NULL)''',
        '''CREATE TABLE IF NOT EXISTS account_devices (
            device_id TEXT PRIMARY KEY, account_id TEXT NOT NULL)''',
        '''CREATE TABLE IF NOT EXISTS mobile_install_handoffs (
            ticket_hash TEXT PRIMARY KEY, payload TEXT NOT NULL,
            expires_at DOUBLE PRECISION NOT NULL, consumed INTEGER NOT NULL DEFAULT 0)''',
    ):
        conn.execute(sql)


class AccountService:
    def __init__(self, db):
        self.db = db

    @staticmethod
    def digest(value):
        return hashlib.sha256(value.encode('utf-8')).hexdigest()

    def session(self, token):
        if not isinstance(token, str) or not token:
            return None
        with self.db.get_conn() as conn:
            row = conn.execute('''SELECT a.account_id, a.email FROM account_sessions s
                JOIN user_accounts a ON a.account_id=s.account_id
                WHERE s.token_hash=? AND s.expires_at>?''', (self.digest(token), time.time())).fetchone()
            if not row:
                return None
            res = dict(row)
            try:
                device_rows = conn.execute('''SELECT d.device_id, d.computer_name, d.status, d.last_seen, d.locked
                    FROM account_devices ad
                    JOIN devices d ON d.device_id = ad.device_id
                    WHERE ad.account_id = ?
                    ORDER BY d.created_at ASC''', (row['account_id'],)).fetchall()
                res['devices'] = [dict(d) for d in device_rows]
            except Exception:
                res['devices'] = []
            return res

    def authenticate(self, action, body):
        email, password = body.get('email'), body.get('password')
        if not isinstance(email, str) or not isinstance(password, str):
            return 400, {'error': 'E_ACCOUNT_INPUT'}
        email = email.strip().lower()
        if len(email) > 254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email) or not 10 <= len(password) <= 256:
            return 400, {'error': 'E_ACCOUNT_INPUT', 'message': 'E-poçtu və ən azı 10 simvollu şifrəni daxil edin.'}
        now = time.time()
        with self.db.get_conn() as conn:
            # Atomic per-account rate limit; identical error for unknown accounts.
            conn.execute('''INSERT INTO account_login_limits (email, attempts, window_start)
                VALUES (?, 1, ?) ON CONFLICT (email) DO UPDATE SET
                attempts=CASE WHEN account_login_limits.window_start < ? THEN 1 ELSE account_login_limits.attempts+1 END,
                window_start=CASE WHEN account_login_limits.window_start < ? THEN ? ELSE account_login_limits.window_start END''',
                (email, now, now-900, now-900, now))
            limit = conn.execute('SELECT attempts FROM account_login_limits WHERE email=?', (email,)).fetchone()
            conn.commit()
            if limit['attempts'] > 15:
                return 429, {'error': 'E_LOGIN_LIMIT', 'message': 'Çox cəhd edildi. 15 dəqiqə sonra yoxlayın.'}
            row = conn.execute('SELECT * FROM user_accounts WHERE email=?', (email,)).fetchone()
            salt = bytes.fromhex(row['password_salt']) if row else secrets.token_bytes(16)
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 600_000).hex()
            if action == 'register':
                if row:
                    return 409, {'error': 'E_ACCOUNT_EXISTS', 'message': 'Bu hesab mövcuddur. Daxil olun.'}
                account_id = 'acct_' + secrets.token_hex(16)
                created = conn.execute('''INSERT INTO user_accounts
                    (account_id,email,password_salt,password_hash,created_at) VALUES (?,?,?,?,?)
                    ON CONFLICT (email) DO NOTHING''', (account_id,email,salt.hex(),password_hash,now)).rowcount
                if created != 1:
                    return 409, {'error': 'E_ACCOUNT_EXISTS'}
            elif action == 'login':
                if not row or not hmac.compare_digest(row['password_hash'], password_hash):
                    return 401, {'error': 'E_LOGIN_FAILED', 'message': 'E-poçt və ya şifrə yanlışdır.'}
                account_id = row['account_id']
            else:
                return 404, {'error': 'E_ACCOUNT_ACTION'}
            token = 'acctsess_' + secrets.token_hex(32)
            expires_at = now + 30*86400
            conn.execute('INSERT INTO account_sessions (token_hash,account_id,expires_at) VALUES (?,?,?)',
                         (self.digest(token), account_id, expires_at))
            conn.commit()
        return 200, {'account_id': account_id, 'email': email, 'account_token': token, 'expires_at': expires_at}

    def bind_device(self, body, token):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        account = self.session(token)
        if not account: return 401, {'error': 'E_ACCOUNT_REQUIRED'}
        device_id, nonce = body.get('device_id'), body.get('nonce')
        with self.db.get_conn() as conn:
            device = conn.execute('SELECT public_key_hex FROM devices WHERE device_id=? AND status=\'ACTIVE\'', (device_id,)).fetchone()
            challenge = conn.execute('SELECT nonce FROM challenges WHERE nonce=? AND device_id=? AND purpose=\'account-bind\' AND used=0 AND expires_at>?', (nonce,device_id,time.time())).fetchone()
            if not device or not challenge: return 400, {'error': 'E_BIND_PROOF'}
            message = f"WINKEY_ACCOUNT_BIND:{nonce}:{device_id}:{account['account_id']}".encode()
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(device['public_key_hex'])).verify(bytes.fromhex(body.get('proof', '')), message)
            except Exception:
                return 403, {'error': 'E_BIND_PROOF'}
            if conn.execute('UPDATE challenges SET used=1 WHERE nonce=? AND used=0', (nonce,)).rowcount != 1:
                return 409, {'error': 'E_NONCE_REPLAY'}
            conn.execute('INSERT INTO account_devices (device_id,account_id) VALUES (?,?) ON CONFLICT (device_id) DO NOTHING', (device_id,account['account_id']))
            owner = conn.execute('SELECT account_id FROM account_devices WHERE device_id=?', (device_id,)).fetchone()
            if owner['account_id'] != account['account_id']: return 403, {'error': 'E_DIFFERENT_ACCOUNT', 'message': 'Kompüter başqa hesaba bağlıdır.'}
            conn.commit()
        return 200, {'success': True}
