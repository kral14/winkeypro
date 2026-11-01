"""Real Linux gateway + disposable PostgreSQL. Mock commands only, no production I/O."""
import asyncio
import json
from pathlib import Path
import secrets
import subprocess
import time
import urllib.request
import websockets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'winkey-codex-load-' + secrets.token_hex(4)
OUT = ROOT / 'plan/reports/websocket/codex_linux_load.json'

def docker(*args):
    return subprocess.check_output(['docker', *args], text=True, cwd=ROOT).strip()

def quantiles(values):
    values = sorted(values)
    return {f'p{p}': round(values[min(len(values)-1, int((len(values)-1)*p/100))], 2) for p in (50,95,99)}

async def benchmark(origin, admin):
    def request(path, body=None, token=None):
        headers = {'Content-Type':'application/json'}
        if token: headers['Authorization'] = 'Bearer ' + token
        req = urllib.request.Request(origin+path, data=json.dumps(body).encode() if body is not None else None, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.load(response)

    devices=[]
    for i in range(100):
        did = 'load_' + secrets.token_hex(8)
        key = Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        nonce = request('/agent/challenge', {'device_id':did})['nonce']
        secret = request('/agent/register', {'device_id':did, 'computer_name':'Synthetic Load', 'public_key_hex':pub,
            'nonce':nonce, 'proof_signature_hex':key.sign(f'WINKEY_REGISTER:{nonce}:{did}'.encode()).hex()})['device_secret']
        code = request('/devices/pair-request', {'device_id':did}, secret)['pair_code']
        token = request('/pair', {'pair_code':code})['session_token']
        devices.append((did, secret, token))
    sockets=[]
    ws_origin=origin.replace('http://','ws://')
    async def next_type(ws, kind):
        async with asyncio.timeout(15):
            while True:
                frame=json.loads(await ws.recv())
                if frame.get('type') == kind: return frame
    async def connect(device):
        did,secret,token=device
        ag=await websockets.connect(ws_origin+'/ws')
        mob=await websockets.connect(ws_origin+'/ws', origin=origin)
        sockets.extend([ag,mob])
        await ag.send(json.dumps({'type':'auth','role':'agent','device_id':did,'token':secret}))
        await next_type(ag,'auth_ok')
        await mob.send(json.dumps({'type':'auth','role':'mobile','session_token':token}))
        await next_type(mob,'auth_ok')
        return ag,mob
    pairs=[]
    try:
        for i in range(0,100,20):
            pairs.extend(await asyncio.gather(*(connect(d) for d in devices[i:i+20])))
        await asyncio.sleep(2)
        rounds=[]
        for round_no in range(2):
            async def command(pair):
                ag,mob=pair
                started=time.perf_counter()
                await mob.send(json.dumps({'type':'command','action':'mock','request_id':secrets.token_hex(16)}))
                frame=await next_type(ag,'command')
                received=time.perf_counter()
                await asyncio.sleep(.005)
                await ag.send(json.dumps({'type':'result','command_id':frame['command_id'],'success':True,'status':'MOCK_OK'}))
                await next_type(ag,'result_ack')
                result=await next_type(mob,'command_result')
                assert result['command_id']==frame['command_id'] and result['status']=='completed'
                return (received-started)*1000,(time.perf_counter()-started)*1000
            timings=await asyncio.gather(*(command(pair) for pair in pairs))
            rounds.append({'round':round_no+1,'completed':len(timings),'dispatch_ms':quantiles([t[0] for t in timings]),
                'e2e_mock_ms':quantiles([t[1] for t in timings])})
        adm=await websockets.connect(ws_origin+'/ws')
        sockets.append(adm)
        await adm.send(json.dumps({'type':'auth','role':'admin','admin_secret':admin}))
        metrics=(await next_type(adm,'auth_ok'))['metrics']
        assert metrics['http_agent_polls']==0
        return {'gateway_os':'Linux Docker','database':'PostgreSQL 16 Docker','agent_mobile_sockets':200,
            'physical_unlock':'NOT_TESTED','rounds_same_backend':rounds,'gateway_metrics':metrics,
            'latency_clock':'client monotonic end-to-end; no cross-machine timestamp subtraction'}
    finally:
        await asyncio.gather(*(s.close() for s in sockets),return_exceptions=True)

def main():
    network=PREFIX+'-net'; pg=PREFIX+'-pg'; gateway=PREFIX+'-gw'
    created=[]
    try:
        docker('build','-t','winkey-codex-r3:local','.')
        docker('network','create',network)
        docker('run','-d','--name',pg,'--network',network,'--network-alias','pg',
            '-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_DB=winkey_test','postgres:16-alpine')
        created.append(pg)
        for _ in range(40):
            result=subprocess.run(['docker','exec',pg,'pg_isready','-U','postgres'],capture_output=True)
            if result.returncode==0: break
            time.sleep(.25)
        admin=secrets.token_hex(32)
        docker('run','-d','--name',gateway,'--network',network,'-p','127.0.0.1::8788',
            '-e','DATABASE_URL=postgresql://postgres@pg:5432/winkey_test','-e','WINKEY_ADMIN_SECRET='+admin,
            'winkey-codex-r3:local')
        created.append(gateway)
        port=docker('port',gateway,'8788/tcp').split(':')[-1]
        origin='http://127.0.0.1:'+port
        for _ in range(80):
            try:
                with urllib.request.urlopen(origin+'/healthz',timeout=1): break
            except Exception: time.sleep(.25)
        report=asyncio.run(benchmark(origin,admin))
        report['docker_stats']=json.loads(docker('stats','--no-stream','--format','{{json .}}',gateway))
        OUT.write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps(report,indent=2))
    finally:
        for name in reversed(created):
            subprocess.run(['docker','rm','-f','-v',name],capture_output=True)
        subprocess.run(['docker','network','rm',network],capture_output=True)

if __name__=='__main__': main()
