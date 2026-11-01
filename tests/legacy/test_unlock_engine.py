import ctypes
import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from unittest.mock import patch
from pc_agent import unlock_engine as engine

class UnlockTests(unittest.TestCase):
    def test_single_pair(self):
        captured = []
        def send(count, events, size):
            captured.extend((e.ki.wVk, e.ki.dwFlags) for e in events)
            return count
        with patch.object(engine.user32, 'SendInput', side_effect=send):
            engine._send_pair(vk=49)
        self.assertEqual(captured, [(49, 0), (49, 2)])

    def test_blocked_input_is_error(self):
        with patch.object(engine.user32, 'SendInput', return_value=0):
            with self.assertRaises(RuntimeError):
                engine._send_pair(vk=49)

    def test_unicode_preserves_symbols(self):
        with patch.object(engine, '_send_pair') as send:
            for char in 'A@ə':
                engine.type_credential_char(char)
        self.assertEqual([c.kwargs['scan'] for c in send.call_args_list], [65, 64, 601])

    def test_open_desktop_is_not_enough(self):
        with patch.object(engine.user32, 'OpenInputDesktop', return_value=123), patch.object(engine, 'get_desktop_name', return_value='Winlogon'), patch.object(engine.user32, 'CloseDesktop') as close:
            self.assertTrue(engine.is_workstation_locked())
            close.assert_called_once_with(123)

    def test_already_unlocked_never_types(self):
        with patch.object(engine, 'is_workstation_locked', return_value=False), patch.object(engine, 'inject_credential_sequence') as inject:
            self.assertEqual(engine._unlock_once('example', []), 'ALREADY_UNLOCKED')
            inject.assert_not_called()

    def test_attach_failure_never_types_and_reverts(self):
        with patch.object(engine, 'log_input_context'), patch.object(engine.user32, 'SetCursorPos'), patch.object(engine.user32, 'mouse_event'), patch.dict(engine.os.environ, {'WINKEY_SECURE_WORKER': '1'}), patch.object(engine, 'is_workstation_locked', return_value=True), patch.object(engine, 'wake_screen'), patch.object(engine, 'attach_to_winlogon_desktop', return_value=(False, 'denied')), patch.object(engine.user32, 'GetThreadDesktop', return_value=123), patch.object(engine.user32, 'SetThreadDesktop', return_value=True), patch.object(engine.advapi32, 'RevertToSelf') as revert, patch.object(engine, 'inject_credential_sequence') as inject:
            with self.assertRaises(RuntimeError):
                engine._unlock_once('example', [])
            inject.assert_not_called()
            revert.assert_called_once()

    def test_missing_credential_never_attaches(self):
        with patch.object(engine, 'is_workstation_locked', return_value=True), patch.object(engine, 'attach_to_winlogon_desktop') as attach:
            with self.assertRaises(RuntimeError):
                engine._unlock_once('', [])
            attach.assert_not_called()

    def test_pin_digits_use_hardware_keys(self):
        with patch.object(engine, 'send_hardware_key') as hardware, patch.object(engine, '_send_pair') as unicode_input:
            for char in '0129':
                engine.type_credential_char(char)
            self.assertEqual([c.args[0] for c in hardware.call_args_list], [48, 49, 50, 57])
            unicode_input.assert_not_called()

    def test_locked_request_uses_system_worker(self):
        from pc_agent import secure_input_worker
        with patch.dict(engine.os.environ, {'WINKEY_SECURE_WORKER': ''}), patch.object(engine, 'is_workstation_locked', return_value=True), patch.object(secure_input_worker, 'launch', return_value='SUCCESS') as launch, patch.object(engine, 'inject_credential_sequence') as direct:
            self.assertEqual(engine._unlock_once('example', []), 'SUCCESS')
            launch.assert_called_once()
            self.assertEqual(launch.call_args.args[0], 'example')
            direct.assert_not_called()

    def test_focus_failure_stops_before_typing(self):
        with patch.object(engine, 'log_input_context'), patch.object(engine.user32, 'SetCursorPos'), patch.object(engine.user32, 'mouse_event'), patch.dict(engine.os.environ, {'WINKEY_SECURE_WORKER': '1'}), patch.object(engine, 'is_workstation_locked', return_value=True), patch.object(engine, 'wake_screen'), patch.object(engine, 'attach_to_winlogon_desktop', return_value=(True, 'Winlogon')), patch.object(engine.user32, 'GetThreadDesktop', return_value=123), patch.object(engine.user32, 'SetThreadDesktop', return_value=True), patch.object(engine.user32, 'CloseDesktop'), patch.object(engine.advapi32, 'RevertToSelf'), patch.object(engine, 'get_desktop_name', return_value='Winlogon'), patch.object(engine, 'send_hardware_key'), patch.object(engine.time, 'sleep'), patch.object(engine, 'focus_credential_field', side_effect=RuntimeError('no focus')), patch.object(engine, 'inject_credential_sequence') as inject:
            with self.assertRaises(RuntimeError):
                engine._unlock_once('example', [])
            inject.assert_not_called()

    def test_diagnostics_flush_and_share_attempt(self):
        import tempfile
        from pc_agent import diagnostics
        with tempfile.TemporaryDirectory(dir=str(engine.Path(__file__).resolve().parent)) as folder, patch.object(diagnostics, 'ROOT', engine.Path(folder)), patch.dict(engine.os.environ, {'WINKEY_ATTEMPT_ID': 'aabbccddeeff'}):
            parent = diagnostics.Trace()
            parent.append('parent stage')
            child = diagnostics.Trace()
            child.append('worker stage')
            lines = parent.snapshot()
            self.assertEqual(len(lines), 2)
            self.assertIn('worker stage', lines[1])
            self.assertTrue((engine.Path(folder) / 'unlock_debug.log').exists())

    def test_error_diagnostics_redact_credential(self):
        import tempfile
        from pc_agent import diagnostics
        with tempfile.TemporaryDirectory(dir=str(engine.Path(__file__).resolve().parent)) as folder, patch.object(diagnostics, 'ROOT', engine.Path(folder)), patch.object(engine, '_unlock_once', side_effect=RuntimeError('failed secret-example')):
            result = engine.unlock_workstation('secret-example')
            self.assertFalse(result['success'])
            self.assertNotIn('secret-example', '\n'.join(result['logs']))
            self.assertIn('RuntimeError', '\n'.join(result['logs']))
            self.assertEqual(len(result['attempt_id']), 12)

    def test_clear_selects_all_and_does_not_submit_after_auto_unlock(self):
        captured = []
        def send(count, events, size):
            captured.extend((event.ki.wVk, event.ki.dwFlags) for event in events)
            return count
        with patch.object(engine.user32, 'SendInput', side_effect=send), patch.object(engine, 'send_hardware_key') as key, patch.object(engine, 'type_credential_char'), patch.object(engine, 'is_workstation_locked', return_value=False), patch.object(engine.time, 'sleep'):
            engine.inject_credential_sequence('example', [])
            self.assertEqual(captured, [(17, 0), (65, 0), (65, 2), (17, 2)])
            key.assert_called_once_with(engine.VK_BACK)

    def test_clear_failure_stops_before_credential(self):
        with patch.object(engine.user32, 'SendInput', return_value=0), patch.object(engine, 'type_credential_char') as typing:
            with self.assertRaises(RuntimeError):
                engine.inject_credential_sequence('example', [])
            typing.assert_not_called()

    def test_default_desktop_does_not_override_locked_session(self):
        with patch.object(engine, 'query_session_state', return_value={'confirmed': True, 'locked': True, 'flags': 0}), patch.object(engine.user32, 'OpenInputDesktop', return_value=123), patch.object(engine, 'get_desktop_name', return_value='Default'), patch.object(engine.user32, 'CloseDesktop'):
            self.assertTrue(engine.is_workstation_locked())

    def test_unknown_session_never_reports_unlocked(self):
        with patch.object(engine, 'query_session_state', return_value={'confirmed': False, 'error': 5}), patch.object(engine.user32, 'OpenInputDesktop', return_value=123), patch.object(engine, 'get_desktop_name', return_value='Default'), patch.object(engine.user32, 'CloseDesktop'):
            self.assertTrue(engine.is_workstation_locked())

    def test_confirmed_session_and_default_desktop_report_unlocked(self):
        with patch.object(engine, 'query_session_state', return_value={'confirmed': True, 'locked': False, 'flags': 1}), patch.object(engine.user32, 'OpenInputDesktop', return_value=123), patch.object(engine, 'get_desktop_name', return_value='Default'), patch.object(engine.user32, 'CloseDesktop'):
            self.assertFalse(engine.is_workstation_locked())

    def test_rejected_input_logs_phase_without_character(self):
        records = []
        engine._input_stats.trace = records
        engine._input_stats.phase = 'credential_typing'
        try:
            with patch.object(engine.user32, 'SendInput', return_value=0):
                with self.assertRaises(RuntimeError):
                    engine._send_pair(vk=49)
            self.assertIn('credential_typing', records[0])
            self.assertIn('accepted=0', records[0])
            self.assertNotIn('vk=49', records[0])
        finally:
            engine._input_stats.trace = None

    def test_curtain_click_precedes_pin_worker(self):
        from pc_agent import secure_input_worker as worker
        logs = []
        with patch.object(engine, 'get_lock_state', return_value={'desktop': 'Default', 'locked': True}), patch.object(worker, '_launch_on_desktop', side_effect=['CURTAIN_READY', 'SUCCESS']) as launch:
            self.assertEqual(worker.launch('example', logs), 'SUCCESS')
            self.assertEqual(launch.call_args_list[0].args, ('', logs, 'Default', 'curtain'))
            self.assertEqual(launch.call_args_list[1].args, ('example', logs, 'Winlogon', 'unlock'))

    def test_failed_curtain_never_launches_pin_worker(self):
        from pc_agent import secure_input_worker as worker
        with patch.object(engine, 'get_lock_state', return_value={'desktop': 'Default', 'locked': True}), patch.object(worker, '_launch_on_desktop', side_effect=RuntimeError('click failed')) as launch:
            with self.assertRaises(RuntimeError):
                worker.launch('example', [])
            self.assertEqual(launch.call_count, 1)
            self.assertEqual(launch.call_args.args[0], '')

    def test_open_pin_screen_skips_default_click(self):
        from pc_agent import secure_input_worker as worker
        logs = []
        with patch.object(engine, 'get_lock_state', return_value={'desktop': 'Winlogon', 'locked': True}), patch.object(worker, '_launch_on_desktop', return_value='SUCCESS') as launch:
            worker.launch('example', logs)
            launch.assert_called_once_with('example', logs, 'Winlogon', 'unlock')

if __name__ == '__main__':
    unittest.main()
