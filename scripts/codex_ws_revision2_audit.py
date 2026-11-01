"""Disposable local probes only; no native input or production network."""
import asyncio
import json
from pathlib import Path
import sys
import unittest
import time
import websockets

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tests')]
from test_ws_boundaries import WebSocketBoundaryTest


class Audit(WebSocketBoundaryTest):
    async def audit_production_origin(self):
        device, secret, token = self._setup_device('prod_origin')
        async with websockets.connect(self.ws_origin + '/ws', origin='http://158.101.172.228:8080') as ws:
            try:
                await ws.send(json.dumps({'type': 'auth', 'role': 'mobile', 'session_token': token}))
                response = json.loads(await asyncio.wait_for(ws.recv(), 2))
                self.assertEqual(response.get('type'), 'auth_ok')
            except websockets.exceptions.ConnectionClosed as exc:
                self.fail(f'Configured production browser Origin rejected: close={exc.code}')

    async def audit_terminal_result_not_overwritten(self):
        device, secret, token = self._setup_device('terminal')
        status, command = self.service.enqueue_command(device, 'mock', 'f' * 32, token, {})
        self.assertEqual(status, 200)
        cid = command['command_id']
        owner = 'audit-owner'
        self.assertTrue(self.service.claim_command_for_ws(device, cid, owner))
        self.assertEqual(self.service.submit_agent_result(cid, device, True, 'SUCCESS', secret)[0], 200)
        self.service.mark_command_delivered(cid, owner)
        with self.db.get_conn() as conn:
            row = conn.execute('SELECT status FROM commands WHERE command_id = ?', (cid,)).fetchone()
        self.assertEqual(row['status'], 'completed', 'Late delivery marker overwrote terminal result')

    async def audit_expired_delivery_is_terminal_without_replay(self):
        device, secret, token = self._setup_device('expiry')
        _, command = self.service.enqueue_command(device, 'mock', 'e' * 32, token, {})
        cid = command['command_id']
        self.assertTrue(self.service.claim_command_for_ws(device, cid, 'owner'))
        self.service.mark_command_delivered(cid, 'owner')
        with self.db.get_conn() as conn:
            conn.execute('UPDATE commands SET claim_expires_at=? WHERE command_id=?', (time.time()-1, cid))
            conn.commit()
        expired = self.service.expire_uncertain_commands()
        self.assertEqual([r['command_id'] for r in expired], [cid])
        self.assertIsNone(self.service.poll_agent(device, False, True, secret)[1]['command'])
        late = self.service.submit_agent_result(cid, device, True, 'late-success', secret)[1]
        self.assertTrue(late['already_terminal'])
        self.assertEqual(late['status'], 'failed')
        self.assertEqual(late['result'], 'INDETERMINATE_DELIVERY_TIMEOUT')

    async def audit_writer_failure_is_not_delivery(self):
        from deploy.websocket_hub import ClientConnection
        class BrokenSocket:
            async def send_text(self, text):
                raise OSError('injected local writer failure')
            async def close(self, **kwargs):
                pass
        connection = ClientConnection(BrokenSocket(), 'agent', 'fake')
        await connection.start_writer()
        with self.assertRaisesRegex(RuntimeError, 'UNCERTAIN'):
            await connection.send_confirmed({'type': 'command', 'action': 'mock'})
        self.assertFalse(connection.is_active)

    async def audit_expiry_pushes_terminal_result_to_mobile(self):
        device, secret, token = self._setup_device('expiry_push')
        async with websockets.connect(self.ws_origin + '/ws', origin=self.http_origin) as ws:
            await ws.send(json.dumps({'type':'auth', 'role':'mobile', 'session_token':token}))
            self.assertEqual(json.loads(await ws.recv())['type'], 'auth_ok')
            _, command = self.service.enqueue_command(device, 'mock', 'd'*32, token, {})
            cid = command['command_id']
            self.assertTrue(self.service.claim_command_for_ws(device, cid, 'owner'))
            self.service.mark_command_delivered(cid, 'owner')
            with self.db.get_conn() as conn:
                conn.execute('UPDATE commands SET claim_expires_at=? WHERE command_id=?', (time.time()-1,cid))
                conn.commit()
            async with asyncio.timeout(5):
                while True:
                    frame=json.loads(await ws.recv())
                    if frame.get('type')=='command_result': break
            self.assertEqual(frame['command_id'],cid)
            self.assertEqual(frame['result'],'INDETERMINATE_DELIVERY_TIMEOUT')


if __name__ == '__main__':
    suite = unittest.TestSuite(Audit(name) for name in (
        'audit_production_origin', 'audit_terminal_result_not_overwritten',
        'audit_expired_delivery_is_terminal_without_replay', 'audit_writer_failure_is_not_delivery',
        'audit_expiry_pushes_terminal_result_to_mobile'))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
