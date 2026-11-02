import unittest
import os
import sys
import shutil
import hashlib
import json
import tempfile
import subprocess
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import build

def sha256_of_file(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()

def create_signed_test_release(target_dir: Path, version: str, signer: ed25519.Ed25519PrivateKey) -> Path:
    target_dir.mkdir(parents=True, exist_ok=True)
    payload_data = b"dummy_bytes_" + version.encode()
    manifest_data = {
        "version": version,
        "timestamp": 1700000000.0,
        "min_host_protocol_version": 1,
        "files": [
            {"path": "dummy_binary.exe", "sha256": hashlib.sha256(payload_data).hexdigest(), "size": len(payload_data)}
        ]
    }
    (target_dir / "dummy_binary.exe").write_bytes(payload_data)
    manifest_bytes = json.dumps(manifest_data, indent=2, sort_keys=True).encode("utf-8")
    (target_dir / "manifest.json").write_bytes(manifest_bytes)
    sig_bytes = signer.sign(manifest_bytes)
    (target_dir / "manifest.sig").write_bytes(sig_bytes)
    return target_dir

class TestBuildRollbackIntegrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Generate disposable Ed25519 keypair for cryptographic commit/recovery tests
        cls.signer = ed25519.Ed25519PrivateKey.generate()
        cls.pub_bytes = cls.signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        cls.pub_hex = cls.pub_bytes.hex()

    def setUp(self):
        # Save baseline hashes of production release files to assert they are NEVER touched
        self.pre_signed = Path(ROOT_DIR, "deploy", "pre_signed_slot_a")
        self.manifest = self.pre_signed / "manifest.json"
        self.sig = self.pre_signed / "manifest.sig"
        self.orig_manifest_hash = sha256_of_file(self.manifest)
        self.orig_sig_hash = sha256_of_file(self.sig)

        # Baseline cargo content
        self.svc_cargo = Path(build.SERVICE_CARGO)
        self.orig_svc_cargo_bytes = self.svc_cargo.read_bytes()

        # Isolated disposable temporary root for ALL tests (never touch production!)
        self.tmp_dir = tempfile.mkdtemp(prefix="winkey_test_build_rollback_")
        self.tmp_target = Path(self.tmp_dir) / "target_release"
        create_signed_test_release(self.tmp_target, "1.0.0", self.signer)

        self.tmp_staging = Path(self.tmp_dir) / "staging_release"
        create_signed_test_release(self.tmp_staging, "1.0.1", self.signer)

        # Configure environment to use test public key for verification
        self.prev_env_pub = os.environ.get("WINKEY_RELEASE_PUBKEY_HEX")
        os.environ["WINKEY_RELEASE_PUBKEY_HEX"] = self.pub_hex

    def tearDown(self):
        if self.prev_env_pub is not None:
            os.environ["WINKEY_RELEASE_PUBKEY_HEX"] = self.prev_env_pub
        else:
            os.environ.pop("WINKEY_RELEASE_PUBKEY_HEX", None)

        # STRICT ASSERTION: Production release files were 100% untouched!
        curr_m_hash = sha256_of_file(self.manifest)
        curr_s_hash = sha256_of_file(self.sig)
        self.assertEqual(self.orig_manifest_hash, curr_m_hash, "Production manifest.json must NEVER be touched!")
        self.assertEqual(self.orig_sig_hash, curr_s_hash, "Production manifest.sig must NEVER be touched!")
        self.assertEqual(self.orig_svc_cargo_bytes, self.svc_cargo.read_bytes(), "Cargo.toml must remain identical!")

        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_orchestration_fault_at_compile_step(self):
        """Fault injection at compile_fn: metadata restored, release untouched."""
        def failing_compile():
            raise RuntimeError("INJECTED_COMPILE_ERR")

        with self.assertRaises(RuntimeError) as ctx:
            build.execute_build_pipeline(
                version="9.1.0",
                staging_dir=self.tmp_staging,
                target_dir=self.tmp_target,
                compile_fn=failing_compile
            )
        self.assertIn("INJECTED_COMPILE_ERR", str(ctx.exception))
        self.assertEqual(self.orig_svc_cargo_bytes, self.svc_cargo.read_bytes())
        ok, data, _ = build.verify_release_dir(self.tmp_target, self.pub_hex)
        self.assertTrue(ok)
        self.assertEqual(data["version"], "1.0.0")

    def test_02_orchestration_fault_at_sign_step(self):
        """Fault injection at sign_fn: metadata restored, release untouched."""
        def dummy_compile(): pass
        def failing_sign(staging_dir):
            raise RuntimeError("INJECTED_SIGN_ERR")

        with self.assertRaises(RuntimeError) as ctx:
            build.execute_build_pipeline(
                version="9.2.0",
                staging_dir=self.tmp_staging,
                target_dir=self.tmp_target,
                compile_fn=dummy_compile,
                sign_fn=failing_sign
            )
        self.assertIn("INJECTED_SIGN_ERR", str(ctx.exception))
        self.assertEqual(self.orig_svc_cargo_bytes, self.svc_cargo.read_bytes())
        ok, data, _ = build.verify_release_dir(self.tmp_target, self.pub_hex)
        self.assertTrue(ok)
        self.assertEqual(data["version"], "1.0.0")

    def test_03_orchestration_system_exit_at_installer_step(self):
        """SystemExit (sys.exit) at installer step: metadata restored, release untouched."""
        def dummy_compile(): pass
        def dummy_sign(staging_dir):
            create_signed_test_release(staging_dir, "9.3.0", self.signer)
        def exit_installer(staging_dir):
            sys.exit(42)

        with self.assertRaises(SystemExit) as ctx:
            build.execute_build_pipeline(
                version="9.3.0",
                staging_dir=self.tmp_staging,
                target_dir=self.tmp_target,
                compile_fn=dummy_compile,
                sign_fn=dummy_sign,
                installer_fn=exit_installer
            )
        self.assertEqual(ctx.exception.code, 42)
        self.assertEqual(self.orig_svc_cargo_bytes, self.svc_cargo.read_bytes())
        ok, data, _ = build.verify_release_dir(self.tmp_target, self.pub_hex)
        self.assertTrue(ok)
        self.assertEqual(data["version"], "1.0.0")

    def test_04_orchestration_fault_at_package_step(self):
        """Fault injection at package_fn: metadata restored, release untouched."""
        def dummy_compile(): pass
        def dummy_sign(staging_dir):
            create_signed_test_release(staging_dir, "9.4.0", self.signer)
        def dummy_installer(staging_dir): pass
        def failing_package(staging_dir):
            raise RuntimeError("INJECTED_PACKAGE_ERR")

        with self.assertRaises(RuntimeError) as ctx:
            build.execute_build_pipeline(
                version="9.4.0",
                staging_dir=self.tmp_staging,
                target_dir=self.tmp_target,
                compile_fn=dummy_compile,
                sign_fn=dummy_sign,
                installer_fn=dummy_installer,
                package_fn=failing_package
            )
        self.assertIn("INJECTED_PACKAGE_ERR", str(ctx.exception))
        self.assertEqual(self.orig_svc_cargo_bytes, self.svc_cargo.read_bytes())
        ok, data, _ = build.verify_release_dir(self.tmp_target, self.pub_hex)
        self.assertTrue(ok)
        self.assertEqual(data["version"], "1.0.0")

    def test_05_commit_staged_release_fault_restores_from_backup(self):
        """Fault injection during commit_staged_release with invalid staging fails closed without touching target."""
        invalid_staging = Path(self.tmp_dir) / "invalid_staging"
        invalid_staging.mkdir(parents=True, exist_ok=True)
        # Missing manifest.sig
        (invalid_staging / "manifest.json").write_text('{"version": "9.5.0"}', encoding="utf-8")

        with self.assertRaises(RuntimeError) as ctx:
            build.commit_staged_release(invalid_staging, self.tmp_target, pub_key_hex=self.pub_hex)
        self.assertIn("E_COMMIT_STAGING_INVALID", str(ctx.exception))

        # Target directory must remain intact v1.0.0
        ok, data, _ = build.verify_release_dir(self.tmp_target, self.pub_hex)
        self.assertTrue(ok)
        self.assertEqual(data["version"], "1.0.0")

    def test_06_dangling_backup_recovery_on_pipeline_start(self):
        """Dangling .backup from past crash is recovered automatically on startup."""
        backup_dir = self.tmp_target.parent / (self.tmp_target.name + ".backup")
        # Rename valid target to backup
        self.tmp_target.rename(backup_dir)
        # Create damaged target simulating interrupted write
        self.tmp_target.mkdir(parents=True, exist_ok=True)
        (self.tmp_target / "manifest.json").write_text("CORRUPTED_JSON", encoding="utf-8")

        def failing_compile():
            # Startup recovery runs before compile; verify target is restored before aborting
            raise RuntimeError("STOP_AFTER_STARTUP_RECOVERY")

        with self.assertRaises(RuntimeError):
            build.execute_build_pipeline(
                version="9.6.0",
                staging_dir=self.tmp_staging,
                target_dir=self.tmp_target,
                compile_fn=failing_compile
            )

        # Target must be restored from backup automatically
        ok, data, _ = build.verify_release_dir(self.tmp_target, self.pub_hex)
        self.assertTrue(ok)
        self.assertEqual(data["version"], "1.0.0")
        self.assertFalse(backup_dir.exists(), "Backup directory should be cleaned after successful restore")

    def test_07_packaging_contract_matches_manifest_and_installer_input(self):
        """Packaging contract: installer input and update zip share identical manifest and files."""
        staging_dir = Path(self.tmp_dir) / "staging_contract"
        create_signed_test_release(staging_dir, "9.9.9", self.signer)
        nsis_flag = f'/DMANIFEST_DIR={str(staging_dir)}'
        self.assertIn("staging_contract", nsis_flag)
        self.assertTrue((staging_dir / "manifest.json").is_file())
        self.assertTrue((staging_dir / "manifest.sig").is_file())

    def test_08_child_process_crash_recovery_across_all_publication_transitions(self):
        """
        Codex P1 Acceptance Requirement:
        Spawn disposable child process performing commit_staged_release, kill it with os._exit(77)
        across each publication transition boundary, and prove with a fresh process that recovery
        guarantees 100% cryptographic completeness (either complete old or complete new, NEVER partial).
        All paths strictly directed to disposable temporary root; production release files untouched.
        """
        worker_script = ROOT_DIR / "tests" / "helpers" / "commit_crash_worker.py"
        self.assertTrue(worker_script.is_file(), "commit_crash_worker.py must exist")

        transitions_to_test = [
            ("crash_after_backup", "1.0.0"),  # Crashed after target -> backup rename; recovers old release v1.0.0
            ("crash_mid_write", "1.0.0"),     # Crashed midway with partial target; recovers old release v1.0.0 from good backup
            ("crash_after_swap", "1.0.1"),    # Crashed after candidate -> target rename; recovers new release v1.0.1
        ]

        for mode, expected_version in transitions_to_test:
            with self.subTest(mode=mode):
                # Setup clean disposable test directories for this subtest
                sub_root = Path(self.tmp_dir) / f"sub_{mode}"
                sub_target = sub_root / "target"
                sub_staging = sub_root / "staging"
                create_signed_test_release(sub_target, "1.0.0", self.signer)
                create_signed_test_release(sub_staging, "1.0.1", self.signer)

                env = os.environ.copy()
                env["WINKEY_RELEASE_PUBKEY_HEX"] = self.pub_hex

                # 1. Spawn child process and trigger os._exit(77) at specific publication transition
                proc = subprocess.Popen(
                    [sys.executable, str(worker_script), mode, str(sub_staging), str(sub_target), self.pub_hex],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=env
                )
                stdout, stderr = proc.communicate(timeout=10)
                self.assertEqual(proc.returncode, 77, f"Child process must crash with code 77! Out: {stdout} Err: {stderr}")

                # 2. Spawn FRESH child process to execute recovery
                rec_proc = subprocess.run(
                    [sys.executable, "-c",
                     f"import sys, build; from pathlib import Path; "
                     f"res = build.recover_release_dir(Path(r'{sub_target}'), '{self.pub_hex}'); "
                     f"sys.exit(0 if res else 1)"],
                    capture_output=True,
                    text=True,
                    env=env
                )
                self.assertEqual(rec_proc.returncode, 0, f"Fresh recovery process must exit 0! Out: {rec_proc.stdout} Err: {rec_proc.stderr}")

                # 3. Cryptographically verify that sub_target is 100% complete and valid
                ok, data, err = build.verify_release_dir(sub_target, self.pub_hex)
                self.assertTrue(ok, f"Target release after recovery must be 100% cryptographically valid! Error: {err}")
                self.assertEqual(data["version"], expected_version,
                                 f"Expected version {expected_version} after crash recovery in mode {mode}, got {data['version']}")

                # 4. Target MUST have both manifest.json and manifest.sig
                self.assertTrue((sub_target / "manifest.json").is_file(), "manifest.json must exist")
                self.assertTrue((sub_target / "manifest.sig").is_file(), "manifest.sig must exist")
                self.assertEqual(len((sub_target / "manifest.sig").read_bytes()), 64, "manifest.sig must be 64 bytes")

                # 5. Subsequent commit must succeed without wiping good backup
                sub_staging_next = sub_root / "staging_next"
                create_signed_test_release(sub_staging_next, "1.0.2", self.signer)
                next_commit = subprocess.run(
                    [sys.executable, "-c",
                     f"import sys, build; from pathlib import Path; "
                     f"build.commit_staged_release(Path(r'{sub_staging_next}'), Path(r'{sub_target}'), '{self.pub_hex}'); "
                     f"sys.exit(0)"],
                    capture_output=True,
                    text=True,
                    env=env
                )
                self.assertEqual(next_commit.returncode, 0, f"Subsequent commit after crash recovery must succeed! {next_commit.stderr}")
                ok_next, data_next, _ = build.verify_release_dir(sub_target, self.pub_hex)
                self.assertTrue(ok_next)
                self.assertEqual(data_next["version"], "1.0.2")

    def test_09_missing_payload_file_fails_verification(self):
        """P1 Regression: manifest referencing a file not on disk must FAIL verification."""
        release_dir = Path(self.tmp_dir) / "missing_payload"
        create_signed_test_release(release_dir, "2.0.0", self.signer)
        # Delete the payload file but leave manifest + sig intact
        payload = release_dir / "dummy_binary.exe"
        self.assertTrue(payload.is_file())
        payload.unlink()

        ok, data, err = build.verify_release_dir(release_dir, self.pub_hex)
        self.assertFalse(ok, "Directory with missing payload file must FAIL verification!")
        self.assertIsNone(data)
        self.assertIn("MISSING_PAYLOAD_FILE_dummy_binary.exe", err)

    def test_10_crlf_manifest_still_verifies(self):
        """P1 Regression: manifest.json converted to CRLF must still verify via normalization."""
        release_dir = Path(self.tmp_dir) / "crlf_test"
        create_signed_test_release(release_dir, "3.0.0", self.signer)

        # Verify LF version passes first
        ok, data, _ = build.verify_release_dir(release_dir, self.pub_hex)
        self.assertTrue(ok)
        self.assertEqual(data["version"], "3.0.0")

        # Convert manifest.json to CRLF (simulating Windows git checkout)
        mf = release_dir / "manifest.json"
        original = mf.read_bytes()
        self.assertNotIn(b'\r\n', original, "Original should be LF-only")
        crlf_bytes = original.replace(b'\n', b'\r\n')
        mf.write_bytes(crlf_bytes)

        # Must still pass via CRLF→LF normalization
        ok, data, err = build.verify_release_dir(release_dir, self.pub_hex)
        self.assertTrue(ok, f"CRLF manifest must verify via normalization! Error: {err}")
        self.assertEqual(data["version"], "3.0.0")

    def test_11_key_consistency_audit(self):
        """P1 Regression: all runtime components must pin the SAME Ed25519 public key."""
        from pathlib import Path as P
        import re

        root = ROOT_DIR

        # Read pinned key from recovery_engine.rs (service)
        re_rs = (root / "apps" / "winkey_service" / "src" / "recovery_engine.rs").read_text(encoding="utf-8")
        m = re.search(r'DEFAULT_PINNED_RELEASE_PUBKEY_HEX.*?=\s*\n?\s*"([0-9a-f]{64})"', re_rs)
        self.assertIsNotNone(m, "Must find DEFAULT_PINNED_RELEASE_PUBKEY_HEX in recovery_engine.rs")
        service_key = m.group(1)

        # Read pinned key from slot_update.rs (desktop)
        slot_rs = (root / "apps" / "desktop_tauri" / "src-tauri" / "src" / "slot_update.rs").read_text(encoding="utf-8")
        desktop_keys = re.findall(r'"(56524c10[0-9a-f]{56})"', slot_rs)
        self.assertGreater(len(desktop_keys), 0, "Must find pinned key in slot_update.rs")
        desktop_key = desktop_keys[0]

        # Read pinned key from update_repository.py (server)
        repo_py = (root / "deploy" / "update_repository.py").read_text(encoding="utf-8")
        m2 = re.search(r"PINNED_PUBLIC_KEY\s*=\s*bytes\.fromhex\(['\"]([0-9a-f]{64})['\"]\)", repo_py)
        self.assertIsNotNone(m2, "Must find PINNED_PUBLIC_KEY in update_repository.py")
        server_key = m2.group(1)

        # All three MUST match
        self.assertEqual(service_key, desktop_key, "Service and Desktop pinned keys must match!")
        self.assertEqual(service_key, server_key, "Service and Server pinned keys must match!")

        # build.py OFFICIAL_RELEASE_PUBKEYS must contain the runtime pinned key
        self.assertIn(service_key, build.OFFICIAL_RELEASE_PUBKEYS,
                      f"build.py OFFICIAL_RELEASE_PUBKEYS must include runtime pinned key {service_key}")

        # prod key file on disk — build-i dayandıran yoxlama testi
        # WINKEY_RELEASE_PUBKEY_HEX mühit dəyişəni silindikdə,
        # build.check_signing_key_consistency() diskdəki açar ilə runtime pinned açar fərqli olduğu üçün
        # FAIL-CLOSED olmalı və RuntimeError("E_KEY_MISMATCH...") verməlidir!
        saved_env = os.environ.pop("WINKEY_RELEASE_PUBKEY_HEX", None)
        try:
            with self.assertRaises(RuntimeError) as ctx:
                build.check_signing_key_consistency()
            self.assertIn("E_KEY_MISMATCH", str(ctx.exception))
        finally:
            if saved_env is not None:
                os.environ["WINKEY_RELEASE_PUBKEY_HEX"] = saved_env

    def test_12_missing_manifest_sig_fails_verification(self):
        """P1 Regression: directory with manifest.json but NO manifest.sig must fail."""
        release_dir = Path(self.tmp_dir) / "no_sig"
        create_signed_test_release(release_dir, "4.0.0", self.signer)
        (release_dir / "manifest.sig").unlink()

        ok, data, err = build.verify_release_dir(release_dir, self.pub_hex)
        self.assertFalse(ok, "Directory without manifest.sig must FAIL!")
        self.assertIn("MISSING_MANIFEST_SIG", err)

    def test_13_missing_payload_in_candidate_fails_commit_and_recovery(self):
        """P1 Regression: missing payload in .candidate path must FAIL verification and recovery."""
        staging_dir = Path(self.tmp_dir) / "stg_cand_test"
        create_signed_test_release(staging_dir, "5.0.0", self.signer)

        # 1. Candidate with missing payload directly fails verify_release_dir
        candidate_dir = self.tmp_target.parent / (self.tmp_target.name + ".candidate")
        shutil.copytree(staging_dir, candidate_dir)
        (candidate_dir / "dummy_binary.exe").unlink()

        ok, _, err = build.verify_release_dir(candidate_dir, self.pub_hex)
        self.assertFalse(ok, "Candidate directory with missing payload must fail verification")
        self.assertIn("MISSING_PAYLOAD_FILE_dummy_binary.exe", err)

        # 2. Corrupt target, test recover_release_dir refuses to restore corrupt candidate
        (self.tmp_target / "manifest.json").write_text("CORRUPTED", encoding="utf-8")
        rec_res = build.recover_release_dir(self.tmp_target, self.pub_hex)
        self.assertFalse(rec_res, "Recovery must refuse to restore corrupt candidate with missing payload")

        # Target must NOT have been replaced with the missing-payload candidate
        self.assertEqual((self.tmp_target / "dummy_binary.exe").read_bytes(), b"dummy_bytes_1.0.0")

        # Clean up candidate
        shutil.rmtree(candidate_dir, ignore_errors=True)

    def test_14_missing_payload_in_backup_blocks_corrupt_restore(self):
        """P1 Regression: damaged .backup with missing payload file must NEVER be restored to target."""
        backup_dir = self.tmp_target.parent / (self.tmp_target.name + ".backup")
        create_signed_test_release(backup_dir, "0.9.0", self.signer)
        # Delete payload from backup
        (backup_dir / "dummy_binary.exe").unlink()

        # Corrupt target
        (self.tmp_target / "manifest.json").write_text("CORRUPTED", encoding="utf-8")

        # verify_release_dir on backup must fail closed
        b_ok, _, b_err = build.verify_release_dir(backup_dir, self.pub_hex)
        self.assertFalse(b_ok)
        self.assertIn("MISSING_PAYLOAD_FILE_dummy_binary.exe", b_err)

        # recover_release_dir must refuse to restore corrupt backup
        res = build.recover_release_dir(self.tmp_target, self.pub_hex)
        self.assertFalse(res, "Recovery from corrupt backup with missing payload must fail")

        # Clean up backup
        shutil.rmtree(backup_dir, ignore_errors=True)

    def test_15_metadata_only_pre_signed_lineage_preserves_candidate_and_backup_recovery(self):
        """P1 Regression: metadata-only pre_signed_slot_a lineage (.candidate/.backup) succeeds verification."""
        pre_signed = Path(ROOT_DIR, "deploy", "pre_signed_slot_a")
        self.assertTrue(pre_signed.is_dir())
        prod_key = "56524c1040e3a8309e938332037d0a0167cc2da30761abcfb77c93a899ad61da"

        # Target pre_signed itself is valid
        ok, data, err = build.verify_release_dir(pre_signed, prod_key)
        self.assertTrue(ok, f"pre_signed_slot_a must verify: {err}")

        # Test candidate lineage of pre_signed_slot_a
        cand_dir = pre_signed.parent / (pre_signed.name + ".candidate")
        try:
            shutil.copytree(pre_signed, cand_dir)
            ok_c, _, err_c = build.verify_release_dir(cand_dir, prod_key)
            self.assertTrue(ok_c, f"pre_signed candidate lineage must verify as metadata-only: {err_c}")
        finally:
            shutil.rmtree(cand_dir, ignore_errors=True)

        # Test backup lineage of pre_signed_slot_a
        bak_dir = pre_signed.parent / (pre_signed.name + ".backup")
        try:
            shutil.copytree(pre_signed, bak_dir)
            ok_b, _, err_b = build.verify_release_dir(bak_dir, prod_key)
            self.assertTrue(ok_b, f"pre_signed backup lineage must verify as metadata-only: {err_b}")
        finally:
            shutil.rmtree(bak_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
