"""
WinKey Pro — Diagnostics Outbox & Telemetry Resilience Test Suite
Spesifikasiya: plan/DIAGNOSTICS_SUPPORT.md
"""

import os
import sys
import time
import json
import shutil
import tempfile
import threading
import urllib.request

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

sys.path.insert(0, os.path.abspath("."))
from pc_agent.diagnostics_reporter import DiagnosticsReporter
from deploy.gateway_production_server import run_server, ADMIN_SECRET

def main():
    temp_dir = tempfile.mkdtemp(prefix="winkey_diag_test_")
    db_path = os.path.join(temp_dir, "diag.db")
    port = 8299
    gateway_url = f"http://127.0.0.1:{port}"

    try:
        # 1. OFFLINE Hadisələrin Toplanması Testi
        print("\n--- TEST 1: Offline Hadisələrin Durable Outbox-da Qorunması ---")
        reporter = DiagnosticsReporter(temp_dir, gateway_origin=gateway_url)
        evt1 = reporter.record_event("installer", "bootstrap_started")
        evt2 = reporter.record_event("installer", "requirements_check")
        evt3 = reporter.record_event("service", "service_install")

        queue_before = reporter._load_queue()
        assert len(queue_before) == 3, f"Expected 3 offline events in outbox, got {len(queue_before)}"
        print(f"[PASS] Server offline ikən 3 hadisə outbox disk faylında saxlanıldı: {[e['stage'] for e in queue_before]}")

        # 2. Canary Redaction Guard Testi
        print("\n--- TEST 2: Canary Redaction (Zero PIN/Secret Leakage) ---")
        evt_canary = reporter.record_event("auth", "pin_verify", error_code="E_WRONG_PIN_1234_SECRET")
        queue_canary = reporter._load_queue()
        last_evt = queue_canary[-1]
        assert last_evt["error_code"] == "[REDACTED_CANARY_STRICT]", f"Canary not redacted: {last_evt['error_code']}"
        print(f"[PASS] PIN və Secret canary dərhal təmizləndi: {last_evt['error_code']}")

        # 3. Gateway Başladılır və Outbox Flush Edilir (Replay)
        print("\n--- TEST 3: Şəbəkə Bərpasından Sonra Outbox Replay və Flush ---")
        server = run_server(port, db_path)
        srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
        srv_thread.start()
        time.sleep(0.5)

        flushed = reporter.flush()
        assert flushed == 4, f"Expected 4 events flushed, got {flushed}"
        queue_after = reporter._load_queue()
        assert len(queue_after) == 0, f"Expected empty outbox after flush, got {len(queue_after)}"
        print(f"[PASS] Bütün {flushed} offline hadisə uğurla Gateway-ə çatdırıldı və outbox təmizləndi!")

        # 4. Admin Paneli Vasitəsilə Hadisələrin Təsdiqi
        print("\n--- TEST 4: Admin Paneli Telemetriya Timeline Yoxlanışı ---")
        req = urllib.request.Request(f"{gateway_url}/admin/telemetry", headers={"X-Owner-Admin-Secret": ADMIN_SECRET})
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            events = data.get("telemetry", [])
            assert len(events) >= 4, f"Admin should see at least 4 events, got {len(events)}"
            stages = [e["stage"] for e in events]
            assert "bootstrap_started" in stages and "service_install" in stages
            print(f"[PASS] Admin paneli bütün hadisələri qəbul etdi: {stages}")

        # 5. P95 Latency SLA Testi
        print("\n--- TEST 5: Hadisə Çatdırılma P95 Latency SLA Ölçümü ---")
        latencies = []
        for i in range(20):
            t0 = time.time()
            reporter.record_event("runtime", f"latency_test_{i}")
            latencies.append((time.time() - t0) * 1000)

        latencies.sort()
        p95_idx = int(len(latencies) * 0.95)
        p95_val = latencies[p95_idx]
        print(f"[LATENCY] 20 hadisə ölçümü: Min={min(latencies):.2f}ms, Max={max(latencies):.2f}ms, P95={p95_val:.2f}ms")
        assert p95_val < 5000, f"P95 latency should be <5000ms, got {p95_val}ms"
        print(f"[PASS] Event-to-Server P95 SLA qəbul olundu (P95 = {p95_val:.2f}ms <= 5000ms)!")

        print("\n=============================================================")
        print("  DIAGNOSTICS & OUTBOX RESILIENCE TESTİ 100% PASS OLDU!      ")
        print("=============================================================")

    finally:
        try:
            server.shutdown()
        except Exception:
            pass
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    main()
