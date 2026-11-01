"""Audit-only real local socket probes; mock actions, no Windows service/input."""
import asyncio
import json
from pathlib import Path
import sys
import unittest
import websockets

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT))
import test_websocket_transport as fixture


class Audit(fixture.WebSocketTransportContractTest):
    async def agent(self, device, secret):
        ws = await websockets.connect(self.ws_origin + '/ws')
        await ws.send(json.dumps({'type': 'auth', 'role': 'agent', 'device_id': device, 'token': secret}))
        self.assertEqual(json.loads(await ws.recv())['type'], 'auth_ok')
        return ws

    async def next_type(self, ws, kind):
        async with asyncio.timeout(2):
            while True:
                message = json.loads(await ws.recv())
                if message.get('type') == kind:
                    return message

    async def audit_one_command_one_agent(self):
        device, secret, mobile = self._setup_device_and_mobile()
        first, second = await self.agent(device, secret), await self.agent(device, secret)
        try:
            status, command = self._http_request('/commands', {'device_id': device, 'action': 'mock', 'request_id': 'a' * 32}, mobile)
            self.assertEqual(status, 200)
            async def received(socket):
                try:
                    return await asyncio.wait_for(self.next_type(socket, 'command'), .5)
                except (TimeoutError, websockets.exceptions.ConnectionClosed):
                    return None
            frames = [frame for frame in await asyncio.gather(received(first), received(second)) if frame]
            self.assertTrue(all(frame['command_id'] == command['command_id'] for frame in frames))
            print('Observed agent recipients for one command:', len(frames))
            self.assertEqual(len(frames), 1, 'Same command dispatched to TWO authenticated agent connections')
        finally:
            await first.close(); await second.close()

    async def audit_completed_retry_is_not_dispatched(self):
        device, secret, mobile = self._setup_device_and_mobile()
        ws = await self.agent(device, secret)
        body = {'device_id': device, 'action': 'mock', 'request_id': 'b' * 32}
        try:
            _, command = self._http_request('/commands', body, mobile)
            await self.next_type(ws, 'command')
            await asyncio.sleep(.05)
            self.assertEqual(self._http_request('/agent/result', {'device_id': device, 'command_id': command['command_id'], 'success': True, 'status': 'MOCK_ONLY'}, secret)[0], 200)
            await self.next_type(ws, 'result_ack')
            self.assertEqual(self._http_request('/commands/' + command['command_id'], token=mobile)[1]['status'], 'completed')
            self._http_request('/commands', body, mobile)
            try:
                repeated = await self.next_type(ws, 'command')
            except TimeoutError:
                return
            self.fail('Completed command dispatched AGAIN on idempotent retry: ' + repeated['command_id'])
        finally:
            await ws.close()

    async def audit_mobile_diagnostics_ack(self):
        import time
        device, _, mobile = self._setup_device_and_mobile()
        event = {'id': 'c' * 32, 'stage': 'request', 'code': 'HTTP_200', 'duration_ms': 123,
                 'local_time': time.time(), 'action': 'lock', 'request_id': 'a' * 32}
        status, data = self._http_request('/mobile/telemetry', {'device_id': device, 'events': [event]}, mobile)
        self.assertEqual(status, 200)
        self.assertEqual(data['accepted'], ['c' * 32], 'Mobile offline outbox requires acknowledged event IDs')


if __name__ == '__main__':
    suite = unittest.TestSuite(Audit(name) for name in (
        'audit_one_command_one_agent', 'audit_completed_retry_is_not_dispatched', 'audit_mobile_diagnostics_ack'))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
