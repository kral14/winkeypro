import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from deploy.gateway_production_server import ProductionDatabase
from deploy.account_service import AccountService
from deploy.gateway_service import GatewayService
from deploy.mobile_install import MobileInstall, feature_request, manifest


class AccountTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1] / 'build')
        self.db = ProductionDatabase(str(Path(self.tmp.name) / 'gateway.db'))
        self.accounts = AccountService(self.db)

    def tearDown(self):
        import gc
        gc.collect()
        self.tmp.cleanup()

    def test_register_login_expiry_and_no_plaintext_password(self):
        status, first = self.accounts.authenticate('register', {'email': 'Arif@Example.com', 'password': 'a long test password'})
        self.assertEqual(status, 200)
        self.assertEqual(self.accounts.authenticate('register', {'email': 'arif@example.com', 'password': 'a long test password'})[0], 409)
        self.assertEqual(self.accounts.authenticate('login', {'email': 'arif@example.com', 'password': 'wrong password'})[0], 401)
        self.assertEqual(self.accounts.authenticate('login', {'email': 'arif@example.com', 'password': 'a long test password'})[0], 200)
        self.assertIsNotNone(self.accounts.session(first['account_token']))
        with self.db.get_conn() as conn:
            row = dict(conn.execute('SELECT * FROM user_accounts').fetchone())
            self.assertNotIn('a long test password', str(row))
            conn.execute('UPDATE account_sessions SET expires_at = ?', (time.time() - 1,))
            conn.commit()
        self.assertIsNone(self.accounts.session(first['account_token']))

    def test_invalid_inputs(self):
        self.assertEqual(self.accounts.authenticate('register', {'email': 'bad', 'password': '123'})[0], 400)

    def seed_device(self, device_id, token, owner='account1'):
        import hashlib
        with self.db.get_conn() as conn:
            conn.execute('INSERT INTO devices (device_id,computer_name,public_key_hex,device_secret_hash,created_at,last_seen_at) VALUES (?,?,?,?,?,?)',
                         (device_id, device_id, '00'*32, hashlib.sha256(b'agent').hexdigest(), time.time(),time.time()))
            conn.execute('INSERT INTO mobile_sessions (session_token,device_id,created_at,expires_at) VALUES (?,?,?,0)', (token,device_id,time.time()))
            conn.execute('INSERT INTO account_devices (device_id,account_id) VALUES (?,?)', (device_id,owner))
            conn.commit()

    def test_install_transfer_is_one_use_and_bound_to_actual_sessions(self):
        self.seed_device('pc1','token1')
        self.seed_device('pc2','token2')
        service = GatewayService(self.db, '')
        install = MobileInstall(service)
        payload = {'devices':[{'id':'pc1','token':'token1','name':'Ofis 1'},
                              {'id':'pc2','token':'token2','name':'PC 2'}], 'selected':'pc1'}
        status, data = install.create(payload)
        self.assertEqual(status,200)
        self.assertEqual(install.restore({'ticket':data['ticket']}), (200,payload))
        self.assertEqual(install.restore({'ticket':data['ticket']})[0],410)
        payload['devices'][0]['token'] = 'token2'
        self.assertEqual(install.create(payload)[0],401)
        self.assertNotIn('token1',str(manifest(data['ticket'])))

    def test_expired_and_revoked_install_handoffs(self):
        self.seed_device('pc1','token1')
        install = MobileInstall(GatewayService(self.db,''))
        body = {'devices':[{'id':'pc1','token':'token1','name':'Ofis'}],'selected':'pc1'}
        _, first = install.create(body)
        with self.db.get_conn() as conn:
            conn.execute('UPDATE mobile_install_handoffs SET expires_at=?',(time.time()-1,)); conn.commit()
        self.assertEqual(install.restore(first)[0],410)
        _, second = install.create(body)
        with self.db.get_conn() as conn:
            conn.execute('DELETE FROM mobile_sessions'); conn.commit()
        self.assertEqual(install.restore(second)[0],401)

    def test_pairing_other_account_is_rejected_without_consuming_qr(self):
        self.seed_device('pc1','token1','arif')
        self.seed_device('pc2','token2','other')
        service = GatewayService(self.db,'')
        with self.db.get_conn() as conn:
            conn.execute('INSERT INTO pairing_requests (pair_code,device_id,challenge_hex,expires_at,created_at) VALUES (?,?,?,?,?)',
                         ('PAIR_NEW','pc2','',time.time()+120,time.time())); conn.commit()
        self.assertEqual(feature_request(service,'/mobile/pair',{'pair_code':'PAIR_NEW','name':'Ofis 2'},'token1')[0],403)
        self.assertEqual(feature_request(service,'/pair',{'pair_code':'PAIR_NEW'},'token1')[0],403)
        with self.db.get_conn() as conn:
            self.assertEqual(conn.execute('SELECT status FROM pairing_requests').fetchone()['status'],'PENDING')
            conn.execute('UPDATE account_devices SET account_id=? WHERE device_id=?',('arif','pc2')); conn.commit()
        status, paired = feature_request(service,'/mobile/pair',{'pair_code':'PAIR_NEW','name':'Ofis 2'},'token1')
        self.assertEqual(status,200)
        self.assertEqual(paired['device_id'],'pc2')
        self.assertEqual(paired['name'],'Ofis 2')
        self.assertNotEqual(paired['session_token'],'token1')
        self.assertNotEqual(feature_request(service,'/mobile/pair',{'pair_code':'PAIR_NEW','name':'x'},'token1')[0],200)

    def test_install_input_types_are_rejected(self):
        install = MobileInstall(GatewayService(self.db,''))
        for invalid in ({}, {'devices':[]}, {'devices':[{'id':[], 'token':{}, 'name':'x'}],'selected':[]}):
            self.assertEqual(install.create(invalid)[0],401)

    def test_device_binding_requires_signed_proof_and_cannot_move_owners(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.generate()
        self.seed_device('pc1','token1','original')
        with self.db.get_conn() as conn:
            conn.execute('UPDATE devices SET public_key_hex=?',(key.public_key().public_bytes_raw().hex(),)); conn.commit()
        _, account = self.accounts.authenticate('register',{'email':'arif@example.com','password':'long valid password'})
        service = GatewayService(self.db,'')
        nonce = service.create_challenge('account-bind','pc1')['nonce']
        body = {'device_id':'pc1','nonce':nonce,'proof':'00'*64}
        self.assertEqual(self.accounts.bind_device(body,account['account_token'])[0],403)
        body['proof'] = key.sign(f"WINKEY_ACCOUNT_BIND:{nonce}:pc1:{account['account_id']}".encode()).hex()
        self.assertEqual(self.accounts.bind_device(body,account['account_token'])[0],403)
        with self.db.get_conn() as conn:
            conn.execute('DELETE FROM account_devices'); conn.commit()
        nonce = service.create_challenge('account-bind','pc1')['nonce']
        body.update(nonce=nonce,proof=key.sign(f"WINKEY_ACCOUNT_BIND:{nonce}:pc1:{account['account_id']}".encode()).hex())
        self.assertEqual(self.accounts.bind_device(body,account['account_token'])[0],200)
        self.assertEqual(self.accounts.bind_device(body,account['account_token'])[0],400)

    def test_http_account_install_and_assets(self):
        from starlette.testclient import TestClient
        from deploy.asgi_app import build_asgi_app
        self.seed_device('pc1','token1')
        with TestClient(build_asgi_app(GatewayService(self.db,''))) as client:
            response = client.post('/accounts/register',json={'email':'arif@example.com','password':'long valid password'})
            self.assertEqual(response.status_code,200,response.text)
            token = response.json()['account_token']
            response = client.post('/accounts/session',json={},headers={'Authorization':'Bearer '+token})
            self.assertEqual(response.json()['email'],'arif@example.com')
            self.assertEqual(client.post('/accounts/session',json={}).status_code,401)
            self.assertEqual(client.post('/accounts/login',json=[]).status_code,400)
            for asset in ('devices.js','jsQR.js','icon.png','manifest.webmanifest'):
                response = client.get('/mobile-assets/'+asset)
                self.assertEqual(response.status_code,200,(asset,response.text[:100] if asset!='icon.png' else 'image'))
                self.assertTrue(response.content)
            payload = {'devices':[{'id':'pc1','token':'token1','name':'Ofis 1'}],'selected':'pc1'}
            install = client.post('/mobile/install',json=payload).json()
            app_manifest = client.get('/mobile-assets/manifest.webmanifest?install='+install['ticket']).json()
            self.assertEqual(app_manifest['start_url'],'/mobile#install='+install['ticket'])
            self.assertEqual(client.post('/mobile/restore',json=install).json(),payload)
            self.assertEqual(client.post('/mobile/restore',json=install).status_code,410)
            html = client.get('/mobile').text
            self.assertIn('deviceSelect',html)
            self.assertIn('/mobile-assets/devices.js',html)


if __name__ == '__main__':
    unittest.main()
