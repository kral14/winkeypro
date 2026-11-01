"""Latency guards using fake OS calls only: no screen/input operations."""
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'pc_agent'))
import ipc_input_worker as worker


class CurtainLatency(unittest.TestCase):
    def test_wake_uses_bounded_call(self):
        with patch.object(worker.user32, 'SendMessageTimeoutW', return_value=0) as bounded, \
             patch.object(worker.user32, 'SendMessageW') as unbounded, \
             patch.object(worker.user32, 'mouse_event'):
            worker.Win32Adapter().wake_screen()
        self.assertEqual(bounded.call_args.args[4:6], (2, 200))
        unbounded.assert_not_called()

    def test_ready_desktop_skips_click_and_transition_wait(self):
        adapter = worker.MockWin32Adapter(desktop_name='Winlogon')
        logs = []
        with patch.object(adapter, 'send_input') as send, patch.object(adapter, 'sleep') as sleep:
            result = worker.dismiss_curtain_direct(adapter, logs)
        self.assertTrue(result['success'])
        send.assert_not_called()
        sleep.assert_not_called()
        self.assertIn('CURTAIN_WAKE_DONE', logs)

    def test_second_guarded_click_recovers_missed_first_click(self):
        adapter = worker.MockWin32Adapter(desktop_name='default', curtain_transition_desktop='default')
        def click():
            adapter._input_calls += 1
            if adapter._input_calls == 2:
                adapter.curtain_transition_desktop = 'Winlogon'
            return 2
        with patch.object(adapter, 'click_curtain', side_effect=click) as clicks:
            result = worker.dismiss_curtain_direct(adapter)
        self.assertEqual(result['status'], 'CURTAIN_READY')
        self.assertEqual(clicks.call_count, 2)

    def test_uac_transition_never_receives_second_click(self):
        adapter = worker.MockWin32Adapter(desktop_name='default', curtain_transition_desktop='uac')
        with self.assertRaisesRegex(RuntimeError, 'CURTAIN_ABORT'):
            worker.dismiss_curtain_direct(adapter)
        self.assertEqual(adapter._input_calls, 1)

    def test_bounded_failure_never_starts_credential_input(self):
        adapter = worker.MockWin32Adapter(desktop_name='default', curtain_transition_desktop='default')
        with self.assertRaisesRegex(RuntimeError, 'CURTAIN_NOT_DISMISSED'):
            worker.dismiss_curtain_direct(adapter)
        self.assertEqual(adapter._input_calls, 2)

    def test_already_unlocked_sends_no_input(self):
        adapter = worker.MockWin32Adapter(initial_locked=False, desktop_name='default')
        self.assertEqual(worker.dismiss_curtain_direct(adapter)['status'], 'ALREADY_UNLOCKED')
        self.assertEqual(adapter._input_calls, 0)


if __name__ == '__main__':
    unittest.main()
