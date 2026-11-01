"""Disposable signed releases and local WS; no production keys or native input."""
import asyncio
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.request
import urllib.error
import zipfile
import websockets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from test_ws_boundaries import WebSocketBoundaryTest
from deploy.update_repository import UpdateRepository


class UpdateTest(WebSocketBoundaryTest):
    async def asyncSetUp(self):
        self.release_temp=tempfile.TemporaryDirectory()
        self.signer=Ed25519PrivateKey.generate()
        public=self.signer.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.repository=UpdateRepository(self.release_temp.name,public)
        self.mock=patch('deploy.update_repository.UpdateRepository',lambda:self.repository)
        self.mock.start()
        await super().asyncSetUp()

    async def asyncTearDown(self):
        await super().asyncTearDown()
        self.mock.stop()
        self.release_temp.cleanup()

    def package(self,version='0.2.0',tamper=False):
        files={'winkey_service.exe':b'FAKE_NOT_EXECUTABLE','winkey_helper.exe':b'FAKE_HELPER',
               'helper_runtime/example.dll':b'FAKE_RUNTIME','winkey_desktop.exe':b'FAKE_DESKTOP'}
        manifest={'version':version,'files':[{'path':n,'size':len(v),'sha256':hashlib.sha256(v).hexdigest()} for n,v in files.items()]}
        raw=json.dumps(manifest).encode()
        output=io.BytesIO()
        with zipfile.ZipFile(output,'w') as z:
            z.writestr('manifest.json',raw)
            z.writestr('manifest.sig',self.signer.sign(raw))
            for name,data in files.items(): z.writestr(name,data+b'corrupt' if tamper else data)
        return output.getvalue()

    def publish(self,body,token=None):
        req=urllib.request.Request(self.http_origin+'/admin/updates/publish',data=body,
            headers={'Authorization':'Bearer '+(token or self.admin_secret),'Content-Type':'application/zip'})
        try:
            with urllib.request.urlopen(req,timeout=10) as response: return response.status,json.load(response)
        except urllib.error.HTTPError as error: return error.code,json.load(error)

    async def auth_agent(self,device,secret):
        ws=await websockets.connect(self.ws_origin+'/ws')
        await ws.send(json.dumps({'type':'auth','role':'agent','device_id':device,'token':secret}))
        self.assertEqual(json.loads(await ws.recv())['type'],'auth_ok')
        return ws

    async def check_publish_push_and_immutable_download(self):
        device,secret,_=self._setup_device('update')
        ws=await self.auth_agent(device,secret)
        try:
            status,release=await asyncio.to_thread(self.publish,self.package())
            self.assertEqual(status,200)
            async with asyncio.timeout(4):
                while True:
                    frame=json.loads(await ws.recv())
                    if frame.get('type')=='update_available':break
            self.assertEqual(frame['release_id'],release['release_id'])
            self.assertEqual(frame['version'],'0.2.0')
            latest=self._http_req('/updates/latest')[1]
            self.assertEqual(latest['version'],'0.2.0')
            with urllib.request.urlopen(self.http_origin+latest['download_url_prefix']+'/helper_runtime/example.dll') as response:
                self.assertEqual(response.read(),b'FAKE_RUNTIME')
        finally: await ws.close()

    async def check_offline_agent_receives_latest_on_reconnect(self):
        self.assertEqual(self.publish(self.package())[0],200)
        device,secret,_=self._setup_device('offline')
        ws=await self.auth_agent(device,secret)
        try:
            frame=json.loads(await asyncio.wait_for(ws.recv(),3))
            self.assertEqual(frame['type'],'update_available')
        finally:await ws.close()

    async def check_bad_package_and_downgrade_preserve_current(self):
        self.assertEqual(self.publish(self.package())[0],200)
        before=self.repository.current()['release_id']
        self.assertEqual(self.publish(self.package('0.3.0',True))[0],400)
        self.assertEqual(self.publish(self.package('0.1.0'))[0],400)
        self.assertEqual(self.publish(self.package('0.3.0'),'wrong-secret')[0],403)
        self.assertEqual(self.repository.current()['release_id'],before)
        self.assertIsNone(self.repository.download(before,'../current'))

    async def check_native_mock_receives_update_hint(self):
        import subprocess
        device,secret,_=self._setup_device('native_hint')
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            directory=Path(temporary)
            (directory/'config.json').write_text(json.dumps({'gateway_origin':self.http_origin,
                'device_id':device,'device_secret':secret,'server_confirmed':True}),encoding='utf-8')
            process=subprocess.Popen([str(ROOT/'apps/winkey_service/target/release/winkey_service.exe'),
                '--standalone','--mock','--data-dir',str(directory),'--timeout-sec','12'],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                from deploy.websocket_hub import hub
                async with asyncio.timeout(5):
                    while not hub.has_active_agent(device):await asyncio.sleep(.1)
                self.assertEqual(self.publish(self.package())[0],200)
                async with asyncio.timeout(5):
                    while not (directory/'update_requested').exists():await asyncio.sleep(.1)
                self.assertEqual(len((directory/'update_requested').read_text()),64)
            finally:
                process.terminate()
                await asyncio.to_thread(process.wait,timeout=3)

    async def check_native_rejects_wrong_signer_before_payload_download(self):
        import subprocess
        self.assertEqual(self.publish(self.package())[0],200)
        downloads=[]
        original=self.repository.download
        def counted(*args):
            downloads.append(args)
            return original(*args)
        self.repository.download=counted
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            result=await asyncio.to_thread(subprocess.run,
                [str(ROOT/'apps/winkey_service/target/release/winkey_service.exe'),
                 '--check-update',self.http_origin,'--data-dir',temporary,'--no-activate'],
                capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=10)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('E_RELEASE_SIGNATURE',result.stdout+result.stderr)
            self.assertEqual(downloads,[])


if __name__=='__main__':
    names=['check_publish_push_and_immutable_download','check_offline_agent_receives_latest_on_reconnect',
           'check_bad_package_and_downgrade_preserve_current','check_native_mock_receives_update_hint',
           'check_native_rejects_wrong_signer_before_payload_download']
    result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(UpdateTest(n) for n in names))
    sys.exit(not result.wasSuccessful())
