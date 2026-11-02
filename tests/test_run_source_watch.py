"""Source watcher checks without starting servers, processes or screen input."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('winkey_run', ROOT / 'run.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SourceWatchTests(unittest.TestCase):
    def test_dev_clients_use_local_gateway_and_loopback_account_endpoint(self):
        env = module.dev_client_environment('192.168.1.20', 9876, {'KEEP': 'value'})
        self.assertEqual(env['WINKEY_GATEWAY_ORIGIN'], 'http://192.168.1.20:9876')
        self.assertEqual(env['WINKEY_DEV_GATEWAY_ORIGIN'], 'http://192.168.1.20:9876')
        self.assertEqual(env['WINKEY_DEV_ACCOUNT_ORIGIN'], 'http://127.0.0.1:9876')
        self.assertEqual(env['KEEP'], 'value')

    def test_check_does_not_start_processes_or_servers(self):
        with patch.object(module.sys, 'argv', ['run.py', '--check']), \
             patch.object(module.subprocess, 'run', side_effect=AssertionError('Unexpected process')):
            self.assertEqual(module.main(), 0)

    def test_sources_change_but_build_output_does_not(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'plan/reports/codex') as folder:
            base = Path(folder) / 'apps/desktop_tauri'
            ui = base / 'ui'
            ui.mkdir(parents=True)
            source = ui / 'app.js'
            source.write_text('one', encoding='utf-8')
            before = module.tauri_source_snapshot(folder)
            output = base / 'src-tauri/target/debug'
            output.mkdir(parents=True)
            (output / 'app.js').write_text('generated', encoding='utf-8')
            self.assertEqual(before, module.tauri_source_snapshot(folder))
            source.write_text('changed source', encoding='utf-8')
            after = module.tauri_source_snapshot(folder)
            self.assertNotEqual(before, after)
            source.unlink()
            self.assertNotEqual(after, module.tauri_source_snapshot(folder))


if __name__ == '__main__':
    unittest.main()
