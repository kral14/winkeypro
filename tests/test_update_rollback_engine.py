"""
WinKey Pro — Update & Rollback Engine Test Suite
Spesifikasiya: plan/UPDATE_ROLLBACK.md
"""

import os
import sys
import json
import shutil
import hashlib
import tempfile
from cryptography.hazmat.primitives.asymmetric import ed25519

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

# Import our engine
sys.path.insert(0, os.path.abspath("."))
from pc_agent.update_rollback_engine import UpdateRollbackEngine

def generate_keypair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes_raw()
    return private_key, pub_bytes.hex()

def sign_manifest(manifest_dict, private_key):
    manifest_bytes = json.dumps(manifest_dict, sort_keys=True, separators=(',', ':')).encode('utf-8')
    sig = private_key.sign(manifest_bytes)
    return sig

def test_full_update_and_rollback_suite():
    temp_dir = tempfile.mkdtemp(prefix="winkey_update_test_")
    print(f"[SETUP] Müvəqqəti test qovluğu: {temp_dir}")

    try:
        priv_key, pub_hex = generate_keypair()
        engine = UpdateRollbackEngine(temp_dir, pub_hex)

        # -------------------------------------------------------------
        # 1. Düzgün Yenilənmə və Uğurlu Keçid (Happy Path)
        # -------------------------------------------------------------
        print("\n--- TEST 1: Düzgün imzalanmış yenilənmə paketi ---")
        runner_code = b"import time\ntime.sleep(2)\nprint('Healthy candidate')\n"
        runner_hash = hashlib.sha256(runner_code).hexdigest()

        manifest_v1 = {
            "version": "0.2.0",
            "target": "x86_64-pc-windows-msvc",
            "files": {
                "run.py": runner_hash
            }
        }
        sig_v1 = sign_manifest(manifest_v1, priv_key)
        ok, msg = engine.stage_update_bundle(manifest_v1, {"run.py": runner_code}, sig_v1)
        assert ok, f"Staging failed: {msg}"
        print(f"[PASS] Staging uğurlu: {msg}")

        ok_act, msg_act = engine.activate_candidate_and_monitor(timeout_sec=1)
        assert ok_act and msg_act == "UPDATE_COMMITTED", f"Activation failed: {msg_act}"
        journal = engine._read_journal()
        assert journal["current_slot"] == "slot_b", "Slot B aktiv olmalı idi"
        assert journal["last_known_good_slot"] == "slot_b", "LKG Slot B olmalı idi"
        print("[PASS] Yenilənmə v0.2.0 uğurla təsdiqləndi (COMMITTED)!")

        # -------------------------------------------------------------
        # 2. Saxta İmza Qoruması (Invalid Signature Fail-Closed)
        # -------------------------------------------------------------
        print("\n--- TEST 2: Saxta / Etibarsız İmza Qoruması ---")
        bogus_sig = b"X" * 64
        manifest_v2 = {
            "version": "0.3.0",
            "target": "x86_64-pc-windows-msvc",
            "files": {"run.py": runner_hash}
        }
        ok_fake, msg_fake = engine.stage_update_bundle(manifest_v2, {"run.py": runner_code}, bogus_sig)
        assert not ok_fake and "E_INVALID_SIGNATURE" in msg_fake, f"Fake sig accepted: {msg_fake}"
        print(f"[PASS] Saxta imza dərhal rədd edildi: {msg_fake}")

        # -------------------------------------------------------------
        # 3. Zədələnmiş Payload Hash Qoruması (Tampered File)
        # -------------------------------------------------------------
        print("\n--- TEST 3: Zədələnmiş Payload Hash Uyğunsuzluğu ---")
        tampered_code = b"import time\nprint('Tampered')"
        sig_v3 = sign_manifest(manifest_v2, priv_key)
        ok_tamp, msg_tamp = engine.stage_update_bundle(manifest_v2, {"run.py": tampered_code}, sig_v3)
        assert not ok_tamp and "E_INTEGRITY_HASH_MISMATCH" in msg_tamp, f"Tampered accepted: {msg_tamp}"
        print(f"[PASS] Zədələnmiş fayl aşkarlandı və rədd edildi: {msg_tamp}")

        # -------------------------------------------------------------
        # 4. Path Traversal (Zip-Slip) Qoruması
        # -------------------------------------------------------------
        print("\n--- TEST 4: Path Traversal (Zip-Slip) Qoruması ---")
        slip_manifest = {
            "version": "0.3.1",
            "target": "x86_64-pc-windows-msvc",
            "files": {"../evil.exe": runner_hash}
        }
        slip_sig = sign_manifest(slip_manifest, priv_key)
        ok_slip, msg_slip = engine.stage_update_bundle(slip_manifest, {"../evil.exe": runner_code}, slip_sig)
        assert not ok_slip and "E_SECURITY_PATH_TRAVERSAL" in msg_slip, f"Zip-slip accepted: {msg_slip}"
        print(f"[PASS] Path traversal cəhdi dərhal bloklandı: {msg_slip}")

        # -------------------------------------------------------------
        # 5. Candidate Crash-Loop və Avtomatik Rollback
        # -------------------------------------------------------------
        print("\n--- TEST 5: Namizəd Crash-Loop və Avtomatik Rollback ---")
        crash_code = b"import sys\nprint('CRASH!')\nsys.exit(42)\n"
        crash_hash = hashlib.sha256(crash_code).hexdigest()
        manifest_crash = {
            "version": "0.4.0-bad",
            "target": "x86_64-pc-windows-msvc",
            "files": {"run.py": crash_hash}
        }
        sig_crash = sign_manifest(manifest_crash, priv_key)
        ok_cr_stage, _ = engine.stage_update_bundle(manifest_crash, {"run.py": crash_code}, sig_crash)
        assert ok_cr_stage, "Crash candidate staging failed"

        ok_act_cr, msg_act_cr = engine.activate_candidate_and_monitor(timeout_sec=2)
        assert not ok_act_cr, "Crash candidate should not commit!"
        assert "ROLLED_BACK_TO_slot_b" in msg_act_cr, f"Expected rollback to slot_b, got: {msg_act_cr}"

        journal = engine._read_journal()
        assert journal["current_slot"] == "slot_b", "Rollback LKG slot_b-yə qayıtmalı idi"
        assert "0.4.0-bad" in journal["quarantined_versions"], "0.4.0-bad karantinə alınmalı idi"
        print(f"[PASS] Çökən namizəd dərhal əvvəlki LKG slota qayıtdı və karantinə alındı: {msg_act_cr}")

        # -------------------------------------------------------------
        # 6. Karantinə Alınmış Versiyanın Təkrar Yüklənməsi Qadağası
        # -------------------------------------------------------------
        print("\n--- TEST 6: Karantin Qoruması ---")
        ok_q, msg_q = engine.stage_update_bundle(manifest_crash, {"run.py": crash_code}, sig_crash)
        assert not ok_q and "E_VERSION_QUARANTINED" in msg_q, f"Quarantine bypass: {msg_q}"
        print(f"[PASS] Karantindəki versiya rədd edildi: {msg_q}")

        # -------------------------------------------------------------
        # 7. Zədələnmiş Journal Bərpası
        # -------------------------------------------------------------
        print("\n--- TEST 7: Zədələnmiş Journal Bərpası ---")
        with open(engine.journal_file, "w", encoding="utf-8") as f:
            f.write("BOGUS_INVALID_JSON_CORRUPTED{{{")
        recovered_journal = engine._read_journal()
        assert recovered_journal["state"] == "CORRUPTED_RECOVERED", "Corrupted recovery failed"
        print(f"[PASS] Zədələnmiş journal təhlükəsiz şəkildə bərpa olundu!")

        print("\n=============================================================")
        print("  BÜTÜN UPDATE & ROLLBACK SINAQLARI 100% UĞURLA TAMAMLANDI!  ")
        print("=============================================================")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    test_full_update_and_rollback_suite()
