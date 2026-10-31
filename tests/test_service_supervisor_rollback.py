"""
WinKey Pro — Service Supervisor Autonomous Boot Recovery Test
Spesifikasiya: plan/GEMINI_FINAL_BATCH_REVISION.md Bölmə P1
"""

import os
import sys
import time
import shutil
import tempfile

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

sys.path.insert(0, os.path.abspath("."))
from pc_agent.service_supervisor import ServiceSupervisor

def main():
    real_service_exe = os.path.abspath("apps/winkey_service/target/release/winkey_service.exe")
    if not os.path.exists(real_service_exe):
        print(f"FAIL: winkey_service.exe tapılmadı: {real_service_exe}")
        sys.exit(1)

    temp_base = tempfile.mkdtemp(prefix="winkey_sup_auto_")
    temp_data = os.path.join(temp_base, "data")
    os.makedirs(temp_data, exist_ok=True)

    dummy_pubkey = "0" * 64

    try:
        supervisor = ServiceSupervisor(temp_base, temp_data, dummy_pubkey)

        # 1. Slot A-ya real winkey_service.exe yerləşdirilir (LKG baza)
        slot_a_exe = os.path.join(supervisor.engine.slot_a_dir, "winkey_service.exe")
        shutil.copy2(real_service_exe, slot_a_exe)

        print("[TEST 1] Slot A-da sağlam xidmətin ilkin başladılması...")
        ok, msg = supervisor.start_supervised_service(is_mock=True, health_timeout_sec=2.0)
        assert ok and "slot_a" in msg, f"Initial start failed: {msg}"
        print(f"[PASS] Xidmət uğurla başladı: {msg}")
        supervisor.stop_service()

        # 2. Xarab namizədin Slot B-yə yerləşdirilməsi
        print("\n[TEST 2] Slot B-yə xarab namizədin yerləşdirilməsi...")
        journal = supervisor.engine._read_journal()
        journal["candidate_version"] = "0.9.0-broken"
        journal["current_slot"] = "slot_b"
        journal["last_known_good_slot"] = "slot_a"
        supervisor.engine._write_journal(journal)

        slot_b_exe = os.path.join(supervisor.engine.slot_b_dir, "winkey_service.exe")
        with open(slot_b_exe, "wb") as f:
            f.write(b"NOT_A_VALID_PE_CORRUPTED")

        # 3. TƏK ÇAĞIRIŞLA AVTONOM BƏRPA TESTİ:
        # Test ikinci dəfə start çağırmır; supervisor özü namizəd qəzasını tutub LKG-ni qaldırmalıdır!
        print("\n[TEST 3] Supervisor xarab namizədi başladır və tək dövr daxilində avtonom bərpa edir...")
        ok_rec, msg_rec = supervisor.start_supervised_service(is_mock=True, health_timeout_sec=2.0)

        assert ok_rec, "Autonomous recovery should succeed!"
        assert "AUTONOMOUS_RECOVERED_TO_LKG_slot_a" in msg_rec, f"Expected autonomous recovery to slot_a, got: {msg_rec}"
        print(f"[PASS] SUPERVISOR AVTONOM BƏRPASI UĞURLU OLDU: {msg_rec}")

        # Journal vəziyyətinin yoxlanışı
        journal_after = supervisor.engine._read_journal()
        assert journal_after["current_slot"] == "slot_a", "Current slot should be slot_a"
        assert journal_after["state"] == "ROLLED_BACK", "State should be ROLLED_BACK"
        assert "0.9.0-broken" in journal_after["quarantined_versions"], "Broken candidate should be quarantined"
        print(f"[PASS] Zədələnmiş namizəd karantinə alındı, LKG slot_a aktiv və işlək saxlanıldı!")

        supervisor.stop_service()
        print("\n=============================================================")
        print("  AVTONOM SCM BOOT RECOVERY TESTİ 100% UĞURLA KEÇDİ!         ")
        print("=============================================================")

    finally:
        supervisor.stop_service()
        shutil.rmtree(temp_base, ignore_errors=True)

if __name__ == "__main__":
    main()
