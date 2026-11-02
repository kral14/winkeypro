"""Disposable signing fixture; does not read production private keys or push Git."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import build
from scripts import release_pipeline
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class TrustBoundaryTests(unittest.TestCase):
    def test_environment_cannot_authorize_different_signer(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            keys = root / 'deploy' / 'keys'
            keys.mkdir(parents=True)
            signer = Ed25519PrivateKey.generate()
            public = signer.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
            private_path = keys / 'fixture.bin'
            private_path.write_bytes(signer.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption()))
            (keys / 'prod_release_ed25519_pub.hex').write_text(public)
            with patch.object(build, 'ROOT_DIR', str(root)), \
                 patch.object(build, 'PROD_KEY_PATH', str(private_path)), \
                 patch.dict(os.environ, {'WINKEY_RELEASE_PUBKEY_HEX': public}):
                with self.assertRaisesRegex(RuntimeError, 'E_KEY_MISMATCH'):
                    build.check_signing_key_consistency()

    def test_git_export_keeps_attributes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / '.gitattributes').write_text('*.sig binary\n')
            exported = set(release_pipeline.source_files(root))
            self.assertIn(Path('.gitattributes'), exported)


if __name__ == '__main__':
    unittest.main()
