"""Source watcher checks without starting servers, processes or screen input."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('winkey_run', ROOT / 'run.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SourceWatchTests(unittest.TestCase):
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
