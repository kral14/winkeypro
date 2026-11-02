"""
Python signing and repository contract tests using synthetic payloads.
Exercises build.verify_release_dir and UpdateRepository with a test-created ZIP.
Does not invoke the production packager, NSIS, Rust staging or desktop selection.
"""

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile
import hashlib
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import build
from deploy.update_repository import UpdateRepository
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def sha256_of_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class TestSigningPublicationContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Disposable test keypairs: Primary Author (Signer A) and Foreign/Wrong Signer (Signer B)
        cls.signer_a = ed25519.Ed25519PrivateKey.generate()
        cls.pub_bytes_a = cls.signer_a.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        cls.pub_hex_a = cls.pub_bytes_a.hex()

        cls.signer_b = ed25519.Ed25519PrivateKey.generate()
        cls.pub_bytes_b = cls.signer_b.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        cls.pub_hex_b = cls.pub_bytes_b.hex()

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="winkey_test_contract_")
        self.root = Path(self.tmp_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _create_fixture_release(self, target_dir: Path, version: str, signer: ed25519.Ed25519PrivateKey) -> dict:
        target_dir.mkdir(parents=True, exist_ok=True)
        payloads = {
            "winkey_service.exe": b"MZ_SVC_BINARY_" + version.encode(),
            "winkey_helper.exe": b"MZ_HELPER_BINARY_" + version.encode(),
            "winkey_desktop.exe": b"MZ_DESKTOP_BINARY_" + version.encode(),
        }

        files_manifest = []
        for name, data in payloads.items():
            (target_dir / name).write_bytes(data)
            files_manifest.append({
                "path": name,
                "sha256": sha256_of_bytes(data),
                "size": len(data)
            })

        manifest_data = {
            "version": version,
            "timestamp": 1700000000.0,
            "min_host_protocol_version": 1,
            "files": sorted(files_manifest, key=lambda x: x["path"])
        }

        manifest_bytes = json.dumps(manifest_data, indent=2, sort_keys=True).encode("utf-8")
        # Ensure exact LF bytes
        manifest_bytes = manifest_bytes.replace(b"\r\n", b"\n")
        (target_dir / "manifest.json").write_bytes(manifest_bytes)

        sig_bytes = signer.sign(manifest_bytes)
        (target_dir / "manifest.sig").write_bytes(sig_bytes)

        return {
            "version": version,
            "manifest_data": manifest_data,
            "manifest_bytes": manifest_bytes,
            "sig_bytes": sig_bytes,
            "payloads": payloads,
            "dir": target_dir
        }

    def _package_to_zip(self, release_info: dict) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("manifest.json", release_info["manifest_bytes"])
            z.writestr("manifest.sig", release_info["sig_bytes"])
            for name, data in release_info["payloads"].items():
                z.writestr(name, data)
        return buf.getvalue()

    def test_01_full_publication_contract_happy_path(self):
        """
        Happy Path Contract:
        Build verification -> fixture file presence -> test-created ZIP -> server download.
        Python build verification and repository agree on signed bytes and a disposable key.
        """
        # 1. Staging Release Fixture
        release_dir = self.root / "stage_happy"
        fixture = self._create_fixture_release(release_dir, "2.1.0", self.signer_a)

        # 2. Build Verification Step
        ok, data, err = build.verify_release_dir(release_dir, pub_key_hex=self.pub_hex_a)
        self.assertTrue(ok, f"Build verification failed: {err}")
        self.assertEqual(data["version"], "2.1.0")

        # 3. Setup Inputs Contract
        self.assertTrue((release_dir / "manifest.json").is_file())
        self.assertTrue((release_dir / "manifest.sig").is_file())
        self.assertEqual(len((release_dir / "manifest.sig").read_bytes()), 64)
        for name in ["winkey_service.exe", "winkey_helper.exe", "winkey_desktop.exe"]:
            self.assertTrue((release_dir / name).is_file())

        # 4. ZIP Package Creation
        zip_bytes = self._package_to_zip(fixture)
        self.assertGreater(len(zip_bytes), 100)

        # 5. Server Ingestion Contract
        server_root = self.root / "server_repo"
        repo = UpdateRepository(root=server_root, public_key=self.pub_bytes_a)
        ingested = repo.publish(zip_bytes)
        self.assertIsNotNone(ingested)
        self.assertEqual(ingested["version"], "2.1.0")

        current = repo.current()
        self.assertIsNotNone(current)
        self.assertEqual(current["version"], "2.1.0")
        self.assertEqual(current["manifest_raw"], fixture["manifest_bytes"].decode("utf-8"))
        self.assertEqual(current["manifest_sig_hex"], fixture["sig_bytes"].hex())

        # 6. Server download integrity (native staging/desktop are not invoked).
        download_svc = repo.download(current["release_id"], "winkey_service.exe")
        self.assertIsNotNone(download_svc)
        self.assertTrue(download_svc.is_file())
        self.assertEqual(download_svc.read_bytes(), fixture["payloads"]["winkey_service.exe"])

    def test_02_negative_wrong_signer_rejected_by_all_layers(self):
        """
        Negative Contract:
        A release signed by Foreign Signer B is rejected by Python build verification
        and server ingestion configured with Signer A trust anchor.
        """
        release_dir = self.root / "stage_wrong_signer"
        fixture_b = self._create_fixture_release(release_dir, "2.2.0", self.signer_b)

        # 1. Build Verification with Trust Anchor A rejects Signer B
        ok, _, err = build.verify_release_dir(release_dir, pub_key_hex=self.pub_hex_a)
        self.assertFalse(ok)
        self.assertEqual(err, "INVALID_SIGNATURE")

        # 2. Server configured with Trust Anchor A rejects Signer B
        server_root = self.root / "server_repo_b"
        repo = UpdateRepository(root=server_root, public_key=self.pub_bytes_a)
        zip_bytes = self._package_to_zip(fixture_b)

        with self.assertRaises(Exception):
            repo.publish(zip_bytes)
        self.assertIsNone(repo.current())

    def test_03_negative_tampered_manifest_byte_rejected(self):
        """
        Negative Contract:
        Tampering with even 1 byte in manifest.json invalidates Ed25519 signature.
        """
        release_dir = self.root / "stage_tamper"
        fixture = self._create_fixture_release(release_dir, "2.3.0", self.signer_a)

        # Mutate manifest.json
        mf = release_dir / "manifest.json"
        raw = mf.read_bytes()
        tampered_raw = raw.replace(b"2.3.0", b"2.3.1")
        mf.write_bytes(tampered_raw)

        # Build verification fails
        ok, _, err = build.verify_release_dir(release_dir, pub_key_hex=self.pub_hex_a)
        self.assertFalse(ok)
        self.assertEqual(err, "INVALID_SIGNATURE")

    def test_04_negative_missing_payload_file_rejected(self):
        """
        Negative Contract:
        If any payload file declared in manifest is missing, publication fails closed.
        """
        release_dir = self.root / "stage_missing"
        fixture = self._create_fixture_release(release_dir, "2.4.0", self.signer_a)

        (release_dir / "winkey_desktop.exe").unlink()

        ok, _, err = build.verify_release_dir(release_dir, pub_key_hex=self.pub_hex_a)
        self.assertFalse(ok)
        self.assertIn("MISSING_PAYLOAD_FILE_winkey_desktop.exe", err)

        # Server rejects ZIP with missing file
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as z:
            z.writestr("manifest.json", fixture["manifest_bytes"])
            z.writestr("manifest.sig", fixture["sig_bytes"])
            z.writestr("winkey_service.exe", fixture["payloads"]["winkey_service.exe"])
            z.writestr("winkey_helper.exe", fixture["payloads"]["winkey_helper.exe"])
            # omitted winkey_desktop.exe

        server_root = self.root / "server_repo_missing"
        repo = UpdateRepository(root=server_root, public_key=self.pub_bytes_a)
        with self.assertRaises(ValueError) as ctx:
            repo.publish(zip_buf.getvalue())
        self.assertIn("E_PACKAGE_FILE_SET", str(ctx.exception))

    def test_05_negative_path_traversal_payload_rejected(self):
        """
        Negative Contract:
        Payload path with .. or absolute path is strictly rejected.
        """
        release_dir = self.root / "stage_traversal"
        release_dir.mkdir(parents=True)
        manifest_data = {
            "version": "2.5.0",
            "timestamp": 1700000000.0,
            "min_host_protocol_version": 1,
            "files": [{"path": "../evil.exe", "sha256": "00"*32, "size": 10}]
        }
        mf_bytes = json.dumps(manifest_data).encode("utf-8")
        (release_dir / "manifest.json").write_bytes(mf_bytes)
        (release_dir / "manifest.sig").write_bytes(self.signer_a.sign(mf_bytes))

        ok, _, err = build.verify_release_dir(release_dir, pub_key_hex=self.pub_hex_a)
        self.assertFalse(ok)
        self.assertIn("INVALID_PAYLOAD_PATH", err)

    def test_06_crlf_checkout_verified_and_publish_normalizes_to_lf(self):
        """
        CRLF Resiliency Contract:
        If a checkout on Windows corrupts manifest.json to CRLF, build verification accepts it via
        normalization; the test's ZIP helper writes the original LF fixture bytes.
        Production create_update_package is not called here.
        """
        release_dir = self.root / "stage_crlf"
        fixture = self._create_fixture_release(release_dir, "2.6.0", self.signer_a)

        # Corrupt manifest to CRLF
        mf = release_dir / "manifest.json"
        crlf_bytes = fixture["manifest_bytes"].replace(b"\n", b"\r\n")
        mf.write_bytes(crlf_bytes)

        # 1. Build verification still passes via normalization
        ok, data, err = build.verify_release_dir(release_dir, pub_key_hex=self.pub_hex_a)
        self.assertTrue(ok, f"Verification must succeed on CRLF manifest: {err}")
        self.assertEqual(data["version"], "2.6.0")

        # 2. Package into zip ensuring LF bytes are written
        zip_bytes = self._package_to_zip(fixture)
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
            extracted_mf = z.read("manifest.json")
            self.assertNotIn(b"\r\n", extracted_mf, "ZIP manifest.json MUST be clean LF bytes")

        # 3. Server accepts clean ZIP
        server_root = self.root / "server_repo_crlf"
        repo = UpdateRepository(root=server_root, public_key=self.pub_bytes_a)
        res = repo.publish(zip_bytes)
        self.assertIsNotNone(res)
        self.assertEqual(res["version"], "2.6.0")


if __name__ == "__main__":
    unittest.main()

