"""
WinKey Pro — Final Batch Comprehensive Test Runner
Bütün testləri ardıcıl icra edir və nəticələri plan/reports/final_batch/ qovluğuna toplayır.
"""

import os
import sys
import subprocess
import time

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

REPORTS_DIR = os.path.abspath("plan/reports/final_batch")
os.makedirs(REPORTS_DIR, exist_ok=True)

TESTS = [
    ("01_desktop_tray_singleton", ["python", "scripts/test_desktop_tray_singleton.py"]),
    ("02_service_pause_resume", ["python", "tests/test_service_pause_resume.py"]),
    ("03_service_supervisor_rollback", ["python", "tests/test_service_supervisor_rollback.py"]),
    ("04_update_rollback_engine", ["python", "tests/test_update_rollback_engine.py"]),
    ("05_deploy_backend_security", ["python", "tests/test_deploy_backend_security.py"]),
    ("06_diagnostics_outbox", ["python", "tests/test_diagnostics_outbox.py"]),
    ("07_mobile_gateway_flow", ["python", "tests/test_mobile_gateway_flow.py"]),
    ("08_codex_nonphysical_e2e", ["python", "scripts/codex_run_nonphysical_e2e.py"]),
    ("09_helper_pipe_access", ["python", "scripts/test_helper_pipe_access.py"]),
    ("10_negative_security_suite", ["python", "tests/test_negative_security_suite.py"]),
    ("11_ipc_stop_lifecycle", ["python", "scripts/test_ipc_stop_lifecycle.py"]),
    ("12_telemetry_p95_suite", ["python", "tests/test_telemetry_p95_suite.py"]),
    ("13_gateway_security_regression", ["python", "tests/test_gateway_security_regression.py"]),
    ("14_codex_final_gateway_audit", ["python", "scripts/codex_final_gateway_audit.py"]),
    ("15_codex_gateway_ownership_audit", ["python", "scripts/codex_gateway_ownership_audit.py"]),
    ("16_codex_recovery_boundary_audit", ["python", "scripts/codex_recovery_boundary_audit.py"]),
    ("17_extracted_zip_clean_layout", ["python", "tests/test_extracted_zip_clean_layout.py"]),
    ("18_native_rust_boot_recovery", ["cargo", "test", "--manifest-path", "apps/winkey_service/Cargo.toml"]),
    ("19_supervisor_nonreply_hang", ["python", "tests/test_supervisor_nonreply_hang.py"]),
    ("20_production_gateway_full_integration", ["python", "tests/test_production_gateway_full_integration.py"]),
    ("21_fresh_install_preflight", ["python", "tests/test_fresh_install_preflight.py"]),
    ("22_native_launcher_executable_switch", ["python", "tests/test_native_launcher_executable_switch.py"]),
    ("23_release_zip_no_private_keys", ["python", "tests/test_release_zip_no_private_keys.py"]),
    ("24_system_slot_acl_security", ["python", "tests/test_system_slot_acl_security.py"]),
    ("25_host_worker_health_and_pause", ["python", "tests/test_host_worker_health_and_pause.py"]),
    ("26_native_worker_gateway_action", ["python", "tests/test_native_worker_gateway_action.py"]),
    ("27_public_mobile_private_admin", ["python", "tests/test_public_mobile_private_admin.py"]),
    ("28_native_auto_update_pipeline", ["python", "-c", "import unittest, sys; sys.path.insert(0, r'tests'); from test_native_auto_update_pipeline import TestNativeAutoUpdatePipeline; suite = unittest.TestLoader().loadTestsFromTestCase(TestNativeAutoUpdatePipeline); res = unittest.TextTestRunner(verbosity=2).run(suite); sys.exit(0 if res.wasSuccessful() else 1)"]),
    ("29_real_update_delivery", ["python", "tests/test_real_update_delivery.py"]),
    ("30_installer_admin_diagnostics", ["python", "tests/test_installer_admin_diagnostics.py"]),
    ("31_installer_dryrun_telemetry", ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "& { & scripts/service_installer.ps1 -DryRun }"]),
    ("32_release_zip_manifest_integrity", ["python", "-m", "unittest", "-v", "tests.test_release_zip_no_private_keys"]),
]

def main():
    print("==================================================================")
    print("   WinKey Pro — Yekun Toplu Test Süitləri İcrası (Final Batch)    ")
    print("==================================================================")

    summary = []
    all_passed = True

    for name, cmd in TESTS:
        log_file = os.path.join(REPORTS_DIR, f"{name}.log")
        print(f"\n[RUNNING] {name}...")
        t0 = time.time()
        res = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace")
        dur = time.time() - t0

        output = f"COMMAND: {' '.join(cmd)}\nEXIT_CODE: {res.returncode}\nDURATION: {dur:.2f}s\n\n--- STDOUT ---\n{res.stdout}\n\n--- STDERR ---\n{res.stderr}\n"
        with open(log_file, "w", encoding="utf-8") as f:
            f.write(output)

        status_str = "PASS" if res.returncode == 0 else f"FAIL (Code {res.returncode})"
        if res.returncode != 0:
            all_passed = False
        print(f"[{status_str}] Müddət: {dur:.2f}s | Loq: {log_file}")
        summary.append((name, status_str, dur))

    print("\n==================================================================")
    print("   TEST NƏTİCƏLƏRİNİN XÜLASƏSİ (FINAL BATCH SUMMARY)              ")
    print("==================================================================")
    for name, st, dur in summary:
        print(f"  {name:<35} : {st:<10} ({dur:.2f}s)")

    summary_file = os.path.join(REPORTS_DIR, "TEST_RUN_SUMMARY.txt")
    with open(summary_file, "w", encoding="utf-8") as f:
        f.write("WinKey Pro — Final Batch Test Run Summary\n")
        f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for name, st, dur in summary:
            f.write(f"{name:<35} : {st:<10} ({dur:.2f}s)\n")
        f.write(f"\nStatus: {'ALL_PASS' if all_passed else 'SOME_FAILED'}\n")

    print(f"\nXülasə faylı yazıldı: {summary_file}")
    if not all_passed:
        sys.exit(1)

if __name__ == "__main__":
    main()
