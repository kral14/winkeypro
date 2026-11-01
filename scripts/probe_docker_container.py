import asyncio
import json
import urllib.request
import websockets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# 1. Healthz check
res = urllib.request.urlopen('http://127.0.0.1:8792/healthz', timeout=3)
print('HEALTHZ HTTP STATUS:', res.status)
body = res.read().decode().strip()
print('HEALTHZ BODY:', body)
assert res.status == 200

# 2. Challenge & Register
req = urllib.request.Request(
    'http://127.0.0.1:8792/agent/challenge',
    data=json.dumps({'device_id': 'docker_pc'}).encode(),
    headers={'Content-Type': 'application/json'}
)
chal = json.loads(urllib.request.urlopen(req, timeout=3).read())
nonce = chal['nonce']

priv = Ed25519PrivateKey.generate()
pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
sig = priv.sign(f'WINKEY_REGISTER:{nonce}:docker_pc'.encode()).hex()

reg_req = urllib.request.Request(
    'http://127.0.0.1:8792/agent/register',
    data=json.dumps({
        'device_id': 'docker_pc',
        'computer_name': 'Docker PC',
        'public_key_hex': pub,
        'nonce': nonce,
        'proof_signature_hex': sig
    }).encode(),
    headers={'Content-Type': 'application/json'}
)
reg = json.loads(urllib.request.urlopen(reg_req, timeout=3).read())
dev_sec = reg['device_secret']
print('DOCKER AGENT REGISTERED:', reg['status'])
assert reg['status'] == 'REGISTERED'

# 3. Real WebSocket Auth Test inside Linux container
async def test_ws():
    async with websockets.connect('ws://127.0.0.1:8792/ws') as ws:
        await ws.send(json.dumps({
            'type': 'auth',
            'role': 'agent',
            'device_id': 'docker_pc',
            'token': dev_sec
        }))
        auth_ack = json.loads(await ws.recv())
        print('DOCKER CONTAINER WS AUTH RESPONSE:', auth_ack)
        assert auth_ack.get('type') == 'auth_ok', f'Unexpected: {auth_ack}'

asyncio.run(test_ws())
print('DOCKER CONTAINER E2E VERIFIED: PASS')
