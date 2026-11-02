"""One-use, expiring handoff from Safari storage to an installed web app."""
import hashlib
import json
import re
import secrets
import time


def manifest(ticket=''):
    suffix = '#install=' + ticket if re.fullmatch('[0-9a-f]{64}', ticket or '') else ''
    return {'id': '/mobile', 'name': 'WinKey Pro', 'short_name': 'WinKey',
            'start_url': '/mobile' + suffix, 'scope': '/', 'display': 'standalone',
            'background_color': '#0c0f0d', 'theme_color': '#0c0f0d',
            'icons': [{'src': '/mobile-assets/icon.png', 'sizes': '128x128', 'type': 'image/png', 'purpose': 'any'}]}


class MobileInstall:
    def __init__(self, service):
        self.service = service

    def validated(self, body):
        devices = body.get('devices')
        if not isinstance(devices, list) or not 1 <= len(devices) <= 50:
            return None
        clean, ids = [], set()
        with self.service.db.get_conn() as conn:
            for device in devices:
                if not isinstance(device, dict): return None
                token, name, device_id = device.get('token'), device.get('name'), device.get('id')
                if not isinstance(token, str) or not isinstance(device_id, str) or len(token) > 256 or len(device_id) > 256:
                    return None
                session = self.service.authenticate_mobile_session(conn, token)
                if not session or session['device_id'] != device_id or device_id in ids:
                    return None
                if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80:
                    return None
                ids.add(device_id)
                clean.append({'id': device_id, 'token': token, 'name': name.strip()})
        selected = body.get('selected')
        if not isinstance(selected, str) or selected not in ids: return None
        return {'devices': clean, 'selected': selected}

    def create(self, body):
        payload = self.validated(body)
        if payload is None: return 401, {'error': 'E_INSTALL_SESSIONS'}
        ticket = secrets.token_hex(32)
        with self.service.db.get_conn() as conn:
            conn.execute('DELETE FROM mobile_install_handoffs WHERE expires_at < ? OR consumed=1', (time.time(),))
            conn.execute('INSERT INTO mobile_install_handoffs (ticket_hash,payload,expires_at,consumed) VALUES (?,?,?,0)',
                         (hashlib.sha256(ticket.encode()).hexdigest(), json.dumps(payload), time.time()+86400))
            conn.commit()
        return 200, {'ticket': ticket, 'expires_in': 86400}

    def restore(self, body):
        ticket = body.get('ticket')
        if not isinstance(ticket, str) or not re.fullmatch('[0-9a-f]{64}', ticket):
            return 400, {'error': 'E_INSTALL_TICKET'}
        digest = hashlib.sha256(ticket.encode()).hexdigest()
        with self.service.db.get_conn() as conn:
            row = conn.execute('SELECT payload FROM mobile_install_handoffs WHERE ticket_hash=? AND consumed=0 AND expires_at>?',
                               (digest,time.time())).fetchone()
            if not row: return 410, {'error': 'E_INSTALL_EXPIRED'}
            changed = conn.execute('UPDATE mobile_install_handoffs SET consumed=1 WHERE ticket_hash=? AND consumed=0 AND expires_at>?',
                                   (digest,time.time())).rowcount
            conn.commit()
            if changed != 1: return 410, {'error': 'E_INSTALL_EXPIRED'}
        payload = self.validated(json.loads(row['payload']))
        if payload is None: return 401, {'error': 'E_INSTALL_SESSIONS'}
        return 200, payload


def feature_request(service, path, body, token):
    from deploy.account_service import AccountService
    accounts = AccountService(service.db)
    if path in ('/accounts/register', '/accounts/login'):
        return accounts.authenticate(path.rsplit('/', 1)[1], body)
    if path == '/accounts/session':
        session = accounts.session(token)
        return (200, session) if session else (401, {'error': 'E_ACCOUNT_REQUIRED'})
    if path == '/accounts/device': return accounts.bind_device(body, token)
    if path == '/mobile/pair':
        name, code = body.get('name'), body.get('pair_code')
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80:
            return 400, {'error': 'E_DEVICE_NAME'}
        status, result = service.claim_pair(code, token)
        if status == 200: result['name'] = name.strip()
        return status, result
    if path == '/pair': return service.claim_pair(body.get('pair_code') or body.get('code'), token)
    if path == '/mobile/install': return MobileInstall(service).create(body)
    if path == '/mobile/restore': return MobileInstall(service).restore(body)
    return 404, {'error': 'E_NOT_FOUND'}
