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

    def test_install_manifest_has_android_icons(self):
        data=manifest()
        self.assertTrue({'192x192','512x512'} <= {icon['sizes'] for icon in data['icons']})
        self.assertEqual(data['display'],'standalone')

    def test_lost_install_response_can_retry_only_from_same_installation(self):
        self.seed_device('pc1','token1')
        install=MobileInstall(GatewayService(self.db,''))
        payload={'devices':[{'id':'pc1','token':'token1','name':'Ofis'}],'selected':'pc1'}
        _, ticket=install.create(payload)
        body={'ticket':ticket['ticket'],'client_nonce':'a'*64}
        self.assertEqual(install.restore(body),(200,payload))
        self.assertEqual(install.restore(body),(200,payload),'A lost response must be recoverable by the same installed app')
        self.assertEqual(install.restore({'ticket':ticket['ticket'],'client_nonce':'b'*64})[0],410)
        self.assertEqual(install.restore({'ticket':ticket['ticket']})[0],410)

    def test_account_lists_online_devices_using_real_schema(self):
        _, account = self.accounts.authenticate('register', {'email':'arif@example.com','password':'long valid password'})
        self.seed_device('pc1','phone1',account['account_id'])
        devices = self.accounts.session(account['account_token'])['devices']
        self.assertEqual(len(devices),1)
        self.assertEqual(devices[0]['device_id'],'pc1')
        self.assertTrue(devices[0]['online'])

    def test_pause_logout_and_delete_preserve_or_revoke_correct_credentials(self):
        _, account = self.accounts.authenticate('register', {'email':'arif@example.com','password':'long valid password'})
        token = account['account_token']
        self.seed_device('pc1','phone1',account['account_id'])
        service = GatewayService(self.db,'')
        self.assertEqual(self.accounts.device_action({'device_id':'pc1','action':'pause'},token)[0],200)
        self.assertEqual(service.enqueue_command('pc1','lock',None,'phone1',{})[0],409)
        self.assertEqual(self.accounts.device_action({'device_id':'pc1','action':'resume'},token)[0],200)
        self.assertEqual(service.enqueue_command('pc1','mock',None,'phone1',{})[0],200)
        self.assertEqual(self.accounts.logout({'device_id':'pc1'},token)[0],200)
        self.assertIsNone(self.accounts.session(token))
        self.assertEqual(service.enqueue_command('pc1','lock',None,'phone1',{})[0],409)
        # Agent transport and mobile pairing remain valid while signed out.
        self.assertEqual(service.poll_agent('pc1',False,True,'agent'),(200,{'command':None}))
        with self.db.get_conn() as conn:
            self.assertIsNotNone(service.authenticate_mobile_session(conn,'phone1'))
        _, again = self.accounts.authenticate('login',{'email':'arif@example.com','password':'long valid password'})
        self.assertEqual(self.accounts.device_action({'device_id':'pc1','action':'delete'},again['account_token'])[0],200)
        self.assertEqual(self.accounts.session(again['account_token'])['devices'],[])
        with self.db.get_conn() as conn:
            self.assertIsNone(service.authenticate_mobile_session(conn,'phone1'))

    def test_device_management_rejects_other_account(self):
        _, account = self.accounts.authenticate('register', {'email':'arif@example.com','password':'long valid password'})
        self.seed_device('pc1','phone1','different-account')
        for action in ('pause','resume','delete','rename'):
            self.assertEqual(self.accounts.device_action({'device_id':'pc1','action':action,'name':'Ev'},account['account_token'])[0],403)

    def test_second_qr_syncs_to_same_phone_group_and_no_other_phone(self):
        self.seed_device('office','phone1','arif')
        self.seed_device('home','independent-phone','arif')
        service=GatewayService(self.db,'')
        with self.db.get_conn() as conn:
            conn.execute('UPDATE devices SET computer_name=? WHERE device_id=?',('Ev','home'))
            conn.execute('INSERT INTO pairing_requests (pair_code,device_id,challenge_hex,expires_at,created_at) VALUES (?,?,?,?,?)',('PAIR_HOME','home','',time.time()+120,time.time()))
            conn.commit()
        status, paired=service.claim_pair('PAIR_HOME','phone1')
        self.assertEqual(status,200)
        result=feature_request(service,'/mobile/devices',{'devices':[{'id':'office','token':'phone1'}]},None)[1]['devices']
        self.assertEqual({d['device_id'] for d in result},{'office','home'})
        self.assertEqual(next(d for d in result if d['device_id']=='home')['computer_name'],'Ev')
        self.assertEqual(next(d for d in result if d['device_id']=='home')['token'],paired['session_token'])
        other=feature_request(service,'/mobile/devices',{'devices':[{'id':'home','token':'independent-phone'}]},None)[1]['devices']
        self.assertEqual([d['device_id'] for d in other],['home'])

    def test_logout_pushes_offline_but_keeps_agent_and_phone_connections(self):
        from starlette.testclient import TestClient
        from deploy.asgi_app import build_asgi_app
        from deploy.websocket_hub import hub
        _, account=self.accounts.authenticate('register',{'email':'arif@example.com','password':'long valid password'})
        self.seed_device('pc1','phone1',account['account_id'])
        with TestClient(build_asgi_app(GatewayService(self.db,''))) as client:
            with client.websocket_connect('/ws') as agent:
                agent.send_json({'type':'auth','role':'agent','device_id':'pc1','token':'agent'})
                self.assertEqual(agent.receive_json()['type'],'auth_ok')
                with client.websocket_connect('/ws') as phone:
                    phone.send_json({'type':'auth','role':'mobile','session_token':'phone1'})
                    self.assertEqual(phone.receive_json()['type'],'auth_ok')
                    self.assertTrue(phone.receive_json()['online'])
                    response=client.post('/accounts/logout',json={'device_id':'pc1'},headers={'Authorization':'Bearer '+account['account_token']})
                    self.assertEqual(response.status_code,200)
                    self.assertFalse(phone.receive_json()['online'])
                    self.assertTrue(hub.has_active_agent('pc1'))
                    agent.send_json({'type':'state','locked':True,'pin_ready':True})
                    self.assertFalse(phone.receive_json()['online'],'Agent heartbeats must not undo logout')
                    phone.send_json({'type':'command','action':'lock','request_id':'a'*32})
                    self.assertEqual(phone.receive_json()['error'],'E_REMOTE_OFFLINE')
                    phone.send_json({'type':'ping'})
                    self.assertEqual(phone.receive_json()['type'],'pong')

    def test_account_websocket_state_and_cross_account_rejection(self):
        from starlette.testclient import TestClient
        from starlette.websockets import WebSocketDisconnect
        from deploy.asgi_app import build_asgi_app
        _, account=self.accounts.authenticate('register',{'email':'live@example.com','password':'long valid password'})
        self.seed_device('pc1','phone1',account['account_id'])
        self.seed_device('other','phone2','another-account')
        with TestClient(build_asgi_app(GatewayService(self.db,''))) as client:
            with client.websocket_connect('/ws') as agent:
                agent.send_json({'type':'auth','role':'agent','device_id':'pc1','token':'agent'})
                self.assertEqual(agent.receive_json()['type'],'auth_ok')
                with client.websocket_connect('/ws') as phone:
                    phone.send_json({'type':'auth','role':'mobile','device_id':'pc1','session_token':account['account_token']})
                    self.assertEqual(phone.receive_json()['type'],'auth_ok')
                    self.assertTrue(phone.receive_json()['online'])
                    agent.send_json({'type':'state','locked':True,'pin_ready':True})
                    self.assertTrue(phone.receive_json()['locked'])
            with self.assertRaises(WebSocketDisconnect):
                with client.websocket_connect('/ws') as phone:
                    phone.send_json({'type':'auth','role':'mobile','device_id':'other','session_token':account['account_token']})
                    phone.receive_json()

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
            for asset in ('devices.js','install.js','jsQR.js','icon.png','icon-192.png','icon-512.png','apple-touch-icon.png','manifest.webmanifest'):
                response = client.get('/mobile-assets/'+asset)
                self.assertEqual(response.status_code,200,(asset,response.text[:100] if asset!='icon.png' else 'image'))
                self.assertTrue(response.content)
            worker=client.get('/mobile-sw.js')
            self.assertEqual(worker.status_code,200)
            self.assertEqual(worker.headers['Service-Worker-Allowed'],'/')
            self.assertIn('application/javascript',worker.headers['Content-Type'])
            import struct
            for name,size in [('icon-192.png',192),('icon-512.png',512),('apple-touch-icon.png',180)]:
                image=client.get('/mobile-assets/'+name).content
                self.assertEqual(struct.unpack('>II',image[16:24]),(size,size))
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
