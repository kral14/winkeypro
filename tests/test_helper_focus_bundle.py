"""Check the actual helper artifact; never starts its focus/input routines."""
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'apps/winkey_service/target/release/winkey_helper.exe'


@unittest.skipUnless(sys.platform == 'win32' and HELPER.is_file(), 'Build Windows helper first')
class HelperBundle(unittest.TestCase):
    def test_bundled_script_matches_source(self):
        from PyInstaller.archive.readers import CArchiveReader
        archive = CArchiveReader(str(HELPER))
        entries = [name for name in archive.toc if name.endswith('focus_credential.ps1')]
        self.assertEqual(len(entries), 1)
        self.assertEqual(archive.extract(entries[0]), (ROOT / 'pc_agent/focus_credential.ps1').read_bytes())

    def test_extracted_resource_probe(self):
        result = subprocess.run([str(HELPER), '--check-focus-resource'], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, 'Packaged resource probe failed')
        self.assertIn('FOCUS_RESOURCE_OK', result.stdout)


if __name__ == '__main__':
    unittest.main()
