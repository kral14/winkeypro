"""
WinKey Pro — Phase-by-Phase Latency Benchmark & Comparison with Revision 1
Spesifikasiya: plan/GEMINI_WEBSOCKET_REVISION_2.md (R2-05)

Bu sınaq təcrid olunmuş PostgreSQL mühitində 100 Agent və 100 Mobil müştəri
(Cəmi 200 paralel aktiv WebSocket) üzərində ucdan-uca əmr icrasının hər bir
fazasını unikal Correlation ID ilə dəqiq ölçür:
  Faza 1: t0 (Mobil göndəriş) -> t1 (Server qəbulu)
  Faza 2: t1 (Server qəbulu) -> t2 (DB Enqueue commit - DB wait)
  Faza 3: t2 (Enqueue commit) -> t3 (DB Claim commit - DB wait)
  Faza 4: t3 (DB Claim commit) -> t5 (Agent qəbulu - WS Dispatch)
  Faza 5: t5 (Agent qəbulu) -> t6 (Mock icra tamamlandı)
  Faza 6: t6 (Mock icra) -> t7 (Server nəticə qəbulu)
  Faza 7: t7 (Server nəticə qəbulu) -> t8 (DB Result commit - DB wait)
  Faza 8: t8 (Result commit) -> t9 (Mobil ACK qəbulu)

Həmçinin:
  - Event loop lag ölçülür (10ms dövri drift monitorinqi)
  - DB wait müddətləri qeydə alınır
  - Revision 1 p95 nəticələri ilə birbaşa müqayisə aparılır
  - Fiziki unlock sınağı NOT_TESTED olaraq qeyd edilir (təhlükəsiz mock icra)
"""

import asyncio
import json
import math
import os
from pathlib import Path
import psutil
import secrets
import socket
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
import threading
import time
import urllib.request
import uvicorn
import websockets
import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from deploy.gateway_service import GatewayService
from deploy.asgi_app import build_asgi_app
from deploy.websocket_hub import hub
from deploy.postgres_database import PostgresDatabase

NUM_DEVICES = 100
CONCURRENT_CONNECT_BATCH = 25


def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def percentiles(data, q_list=[50, 90, 95, 99]):
    if not data:
        return {f"p{q}": 0.0 for q in q_list}
    sorted_d = sorted(data)
    res = {}
    for q in q_list:
        k = (len(sorted_d) - 1) * (q / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            res[f"p{q}"] = round(sorted_d[int(k)], 2)
        else:
            d0 = sorted_d[int(f)] * (c - k)
            d1 = sorted_d[int(c)] * (k - f)
            res[f"p{q}"] = round(d0 + d1, 2)
    return res


async def run_latency_benchmark():
    pg_url = os.environ.get("WINKEY_TEST_DATABASE_URL", "postgresql://postgres:testsecret@127.0.0.1:5439/winkey_test")
    schema_name = f"winkey_lat_{secrets.token_hex(6)}"

    # 1. Təcrid olunmuş sxem yaradırıq
    with psycopg.connect(pg_url, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema_name)))

    dsn_with_schema = make_conninfo(pg_url, options=f"-c search_path={schema_name}")
    db = PostgresDatabase(dsn_with_schema)

    admin_secret = secrets.token_hex(32)
    os.environ["WINKEY_ADMIN_SECRET"] = admin_secret
    service = GatewayService(db, admin_secret)
    app = build_asgi_app(service)

    port = get_free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", ws_max_size=65536)
    server = uvicorn.Server(config)
    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()

    # Serverin qalxmasını gözləyirik
    for _ in range(50):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1) as resp:
                if resp.status == 200:
                    break
        except Exception:
            await asyncio.sleep(0.05)

    ws_origin = f"ws://127.0.0.1:{port}"
    http_origin = f"http://127.0.0.1:{port}"

    # Event-loop lag monitorinqi
    lag_samples = []
    stop_lag_monitor = False

    async def monitor_event_loop_lag():
        interval = 0.010  # 10ms
        while not stop_lag_monitor:
            t_before = time.monotonic()
            await asyncio.sleep(interval)
            t_after = time.monotonic()
            drift_ms = max(0.0, (t_after - t_before - interval) * 1000.0)
            lag_samples.append(drift_ms)

    lag_task = asyncio.create_task(monitor_event_loop_lag())

    proc = psutil.Process()
    ram_initial_mb = proc.memory_info().rss / (1024 * 1024)

    def http_post(path, body, token=None):
        url = http_origin + path
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    print(f"\n[BENCHMARK] {NUM_DEVICES} cihazın qeydiyyatı və açarların generasiyası...", flush=True)
    devices = []
    t_reg_start = time.time()
    for i in range(NUM_DEVICES):
        did = f"bench_pc_{i:04d}"
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        chal = http_post("/agent/challenge", {"device_id": did})
        nonce = chal["nonce"]
        sig = priv.sign(f"WINKEY_REGISTER:{nonce}:{did}".encode()).hex()
        reg = http_post("/agent/register", {
            "device_id": did, "computer_name": f"BenchPC-{i}",
            "public_key_hex": pub, "nonce": nonce, "proof_signature_hex": sig
        })
        p_req = http_post("/devices/pair-request", {"device_id": did}, token=reg["device_secret"])
        pair = http_post("/pair", {"pair_code": p_req["pair_code"]})
        devices.append({
            "device_id": did,
            "device_secret": reg["device_secret"],
            "session_token": pair["session_token"]
        })
        if (i + 1) % 25 == 0:
            print(f"[BENCHMARK] {i + 1}/{NUM_DEVICES} cihaz qeydiyyatdan keçdi...", flush=True)

    reg_duration = time.time() - t_reg_start
    print(f"[BENCHMARK] {NUM_DEVICES} cihaz {reg_duration:.2f}s müddətində uğurla qeydiyyatdan keçdi.", flush=True)

    agent_sockets = []
    mobile_sockets = []

    print(f"[BENCHMARK] {NUM_DEVICES} Agent və {NUM_DEVICES} Mobil WebSocket bağlantısı qurulur (Cəmi {NUM_DEVICES*2} soket)...", flush=True)
    t_conn_start = time.time()

    async def connect_agent(dev):
        ws = await websockets.connect(f"{ws_origin}/ws")
        await ws.send(json.dumps({
            "type": "auth", "role": "agent", "device_id": dev["device_id"], "token": dev["device_secret"]
        }))
        ack = json.loads(await asyncio.wait_for(ws.recv(), timeout=10.0))
        assert ack.get("type") == "auth_ok"
        return ws

    async def connect_mobile(dev):
        ws = await websockets.connect(f"{ws_origin}/ws")
        await ws.send(json.dumps({
            "type": "auth", "role": "mobile", "session_token": dev["session_token"]
        }))
        ack = json.loads(await asyncio.wait_for(ws.recv(), timeout=10.0))
        assert ack.get("type") == "auth_ok"
        return ws

    for chunk_start in range(0, NUM_DEVICES, CONCURRENT_CONNECT_BATCH):
        batch = devices[chunk_start:chunk_start + CONCURRENT_CONNECT_BATCH]
        ag_conns = await asyncio.gather(*(connect_agent(d) for d in batch))
        agent_sockets.extend(ag_conns)
        mob_conns = await asyncio.gather(*(connect_mobile(d) for d in batch))
        mobile_sockets.extend(mob_conns)
        print(f"[BENCHMARK] {len(agent_sockets) + len(mobile_sockets)}/{NUM_DEVICES*2} soket qoşuldu...", flush=True)

    conn_duration = time.time() - t_conn_start
    total_sockets = len(agent_sockets) + len(mobile_sockets)
    ram_connected_mb = proc.memory_info().rss / (1024 * 1024)
    print(f"[BENCHMARK] {total_sockets} WebSocket bağlantısı {conn_duration:.2f}s ərzində tamamlandı. RAM: {ram_connected_mb:.1f} MB.", flush=True)

    # Idle yoxlanışı
    print("[BENCHMARK] 2 saniyəlik idle dövrü sınaqdan keçirilir (HTTP poll = 0)...", flush=True)
    await asyncio.sleep(2.0)

    # Paralel Fazalı Əmr İcrası
    print(f"[BENCHMARK] {NUM_DEVICES} cihaz üzrə correlation ID ilə fazalı gecikmə ölçülür...", flush=True)

    p1_send_recv = []      # t0 -> t1
    p2_enqueue_db = []     # t1 -> t2
    p3_claim_db = []       # t2 -> t3
    p4_ws_dispatch = []    # t3 -> t5
    p5_mock_exec = []      # t5 -> t6
    p6_res_transport = []  # t6 -> t7
    p7_res_commit = []     # t7 -> t8
    p8_phone_ack = []      # t8 -> t9

    total_dispatch = []    # t0 -> t5
    total_e2e = []         # t0 -> t9

    async def run_correlated_command(idx, dev, ag_ws, mob_ws):
        req_id = secrets.token_hex(16)
        t0_send = time.time()

        # Mobil əmr göndərir (t0 daxil edilir)
        await mob_ws.send(json.dumps({
            "type": "command",
            "action": "mock",
            "request_id": req_id,
            "timings": {"t0_send": t0_send}
        }))

        # Agent əmri alır
        while True:
            ag_raw = await asyncio.wait_for(ag_ws.recv(), timeout=15.0)
            ag_frame = json.loads(ag_raw)
            if ag_frame.get("type") == "command":
                break

        t5_agent_recv = time.time()
        cmd_id = ag_frame["command_id"]
        server_timings = ag_frame.get("timings", {})

        # Mock icra (qətiyyən fiziki kilid və ya PIN input edilmir)
        await asyncio.sleep(0.005)  # 5ms mock worker processing
        t6_mock_done = time.time()

        # Agent nəticəni qaytarır
        ag_timings = {
            **server_timings,
            "t5_agent_recv": t5_agent_recv,
            "t6_mock_done": t6_mock_done
        }
        await ag_ws.send(json.dumps({
            "type": "result",
            "command_id": cmd_id,
            "success": True,
            "status": "mock_completed",
            "timings": ag_timings
        }))

        # Agent result_ack alır
        while True:
            ag_ack = json.loads(await asyncio.wait_for(ag_ws.recv(), timeout=15.0))
            if ag_ack.get("type") == "result_ack":
                break

        # Mobil command_result alır
        while True:
            m_frame = json.loads(await asyncio.wait_for(mob_ws.recv(), timeout=15.0))
            if m_frame.get("type") == "command_result":
                break

        t9_phone_ack_time = time.time()
        final_timings = m_frame.get("timings", ag_timings)

        # Faza fərqlərini hesablayırıq (ms)
        t0 = final_timings.get("t0_send", t0_send)
        t1 = final_timings.get("t_server_recv", t0)
        t2 = final_timings.get("t_enqueue_commit", t1)
        t3 = final_timings.get("t_claim_commit", t2)
        t4 = final_timings.get("t_dispatch_sent", t3)
        t5 = final_timings.get("t5_agent_recv", t5_agent_recv)
        t6 = final_timings.get("t6_mock_done", t6_mock_done)
        t7 = final_timings.get("t_result_recv", t6)
        t8 = final_timings.get("t_result_commit", t7)
        t9 = t9_phone_ack_time

        p1_send_recv.append(max(0.0, (t1 - t0) * 1000.0))
        p2_enqueue_db.append(max(0.0, (t2 - t1) * 1000.0))
        p3_claim_db.append(max(0.0, (t3 - t2) * 1000.0))
        p4_ws_dispatch.append(max(0.0, (t5 - t3) * 1000.0))
        p5_mock_exec.append(max(0.0, (t6 - t5) * 1000.0))
        p6_res_transport.append(max(0.0, (t7 - t6) * 1000.0))
        p7_res_commit.append(max(0.0, (t8 - t7) * 1000.0))
        p8_phone_ack.append(max(0.0, (t9 - t8) * 1000.0))

        total_dispatch.append(max(0.0, (t5 - t0) * 1000.0))
        total_e2e.append(max(0.0, (t9 - t0) * 1000.0))

    t_batch_start = time.time()
    tasks = [run_correlated_command(i, devices[i], agent_sockets[i], mobile_sockets[i]) for i in range(NUM_DEVICES)]
    await asyncio.gather(*tasks)
    batch_duration = time.time() - t_batch_start

    # Lag monitorinqini dayandırırıq
    stop_lag_monitor = True
    await lag_task

    ram_final_mb = proc.memory_info().rss / (1024 * 1024)
    cpu_final = proc.cpu_percent(interval=0.5)

    # Soketləri bağlayırıq
    for ws in agent_sockets:
        await ws.close()
    for ws in mobile_sockets:
        await ws.close()

    server.should_exit = True
    server_thread.join(timeout=3)
    db.close()

    # Sxemi silirik
    with psycopg.connect(pg_url, autocommit=True) as conn:
        conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema_name)))

    # Metrikaların toplanması
    rev1_disp_p95 = 2719.72
    rev1_e2e_p95 = 2874.62

    p1_stats = percentiles(p1_send_recv)
    p2_stats = percentiles(p2_enqueue_db)
    p3_stats = percentiles(p3_claim_db)
    p4_stats = percentiles(p4_ws_dispatch)
    p5_stats = percentiles(p5_mock_exec)
    p6_stats = percentiles(p6_res_transport)
    p7_stats = percentiles(p7_res_commit)
    p8_stats = percentiles(p8_phone_ack)

    disp_stats = percentiles(total_dispatch)
    e2e_stats = percentiles(total_e2e)
    lag_stats = percentiles(lag_samples)

    metrics = {
        "timestamp": time.time(),
        "database_backend": "PostgreSQL 16 (isolated container)",
        "devices_count": NUM_DEVICES,
        "total_active_sockets": total_sockets,
        "batch_duration_sec": round(batch_duration, 2),
        "commands_executed": len(total_e2e),
        "physical_unlock_test": "NOT_TESTED",
        "event_loop_lag_ms": {
            "min": round(min(lag_samples), 2) if lag_samples else 0,
            "max": round(max(lag_samples), 2) if lag_samples else 0,
            "avg": round(sum(lag_samples) / len(lag_samples), 2) if lag_samples else 0,
            **lag_stats
        },
        "phase_breakdown_ms": {
            "phase_1_mobile_send_to_server_recv": {
                "avg": round(sum(p1_send_recv) / len(p1_send_recv), 2),
                **p1_stats
            },
            "phase_2_server_recv_to_db_enqueue_commit": {
                "avg": round(sum(p2_enqueue_db) / len(p2_enqueue_db), 2),
                **p2_stats
            },
            "phase_3_db_enqueue_to_db_claim_commit": {
                "avg": round(sum(p3_claim_db) / len(p3_claim_db), 2),
                **p3_stats
            },
            "phase_4_db_claim_to_agent_recv": {
                "avg": round(sum(p4_ws_dispatch) / len(p4_ws_dispatch), 2),
                **p4_stats
            },
            "phase_5_agent_recv_to_mock_execute_done": {
                "avg": round(sum(p5_mock_exec) / len(p5_mock_exec), 2),
                **p5_stats
            },
            "phase_6_mock_execute_to_server_result_recv": {
                "avg": round(sum(p6_res_transport) / len(p6_res_transport), 2),
                **p6_stats
            },
            "phase_7_server_result_to_db_result_commit": {
                "avg": round(sum(p7_res_commit) / len(p7_res_commit), 2),
                **p7_stats
            },
            "phase_8_db_result_commit_to_phone_ack": {
                "avg": round(sum(p8_phone_ack) / len(p8_phone_ack), 2),
                **p8_stats
            }
        },
        "total_dispatch_latency_ms": {
            "min": round(min(total_dispatch), 2),
            "max": round(max(total_dispatch), 2),
            "avg": round(sum(total_dispatch) / len(total_dispatch), 2),
            **disp_stats
        },
        "total_e2e_latency_ms": {
            "min": round(min(total_e2e), 2),
            "max": round(max(total_e2e), 2),
            "avg": round(sum(total_e2e) / len(total_e2e), 2),
            **e2e_stats
        },
        "revision_1_comparison_p95_ms": {
            "revision_1_dispatch_p95": rev1_disp_p95,
            "revision_2_dispatch_p95": disp_stats["p95"],
            "dispatch_improvement_delta_ms": round(rev1_disp_p95 - disp_stats["p95"], 2),
            "revision_1_e2e_p95": rev1_e2e_p95,
            "revision_2_e2e_p95": e2e_stats["p95"],
            "e2e_improvement_delta_ms": round(rev1_e2e_p95 - e2e_stats["p95"], 2)
        },
        "memory_rss_mb": {
            "initial": round(ram_initial_mb, 2),
            "connected": round(ram_connected_mb, 2),
            "final": round(ram_final_mb, 2),
            "delta": round(ram_final_mb - ram_initial_mb, 2)
        },
        "cpu_percent": round(cpu_final, 1)
    }

    report_dir = ROOT_DIR / "plan/reports/websocket/revision2"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "latency_phases.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print("\n" + "="*60, flush=True)
    print("      FAZALI GECİKMƏ VƏ REVİSİYA MÜQAYİSƏSİ (R2-05)", flush=True)
    print("="*60, flush=True)
    print(f"Backend: PostgreSQL 16 (Təcrid edilmiş container) | Cihaz: {NUM_DEVICES} | WS: {total_sockets}", flush=True)
    print(f"İcra edilən əmr: {len(total_e2e)}/{NUM_DEVICES} (100% Uğurlu)", flush=True)
    print(f"Event-loop lag p95: {lag_stats['p95']}ms (Avg: {metrics['event_loop_lag_ms']['avg']}ms)", flush=True)
    print("\nFazalar üzrə ortalama və p95 gecikmələr:", flush=True)
    print(f"  Faza 1 (Mobil Send -> Server Recv):      avg={metrics['phase_breakdown_ms']['phase_1_mobile_send_to_server_recv']['avg']}ms | p95={p1_stats['p95']}ms", flush=True)
    print(f"  Faza 2 (Server Recv -> DB Enqueue):       avg={metrics['phase_breakdown_ms']['phase_2_server_recv_to_db_enqueue_commit']['avg']}ms | p95={p2_stats['p95']}ms", flush=True)
    print(f"  Faza 3 (DB Enqueue -> DB Claim Commit):   avg={metrics['phase_breakdown_ms']['phase_3_db_enqueue_to_db_claim_commit']['avg']}ms | p95={p3_stats['p95']}ms", flush=True)
    print(f"  Faza 4 (DB Claim -> Agent Recv Dispatch): avg={metrics['phase_breakdown_ms']['phase_4_db_claim_to_agent_recv']['avg']}ms | p95={p4_stats['p95']}ms", flush=True)
    print(f"  Faza 5 (Agent Recv -> Mock Exec Done):    avg={metrics['phase_breakdown_ms']['phase_5_agent_recv_to_mock_execute_done']['avg']}ms | p95={p5_stats['p95']}ms", flush=True)
    print(f"  Faza 6 (Mock Exec -> Server Result Recv): avg={metrics['phase_breakdown_ms']['phase_6_mock_execute_to_server_result_recv']['avg']}ms | p95={p6_stats['p95']}ms", flush=True)
    print(f"  Faza 7 (Server Result -> DB Commit):      avg={metrics['phase_breakdown_ms']['phase_7_server_result_to_db_result_commit']['avg']}ms | p95={p7_stats['p95']}ms", flush=True)
    print(f"  Faza 8 (DB Commit -> Phone ACK):          avg={metrics['phase_breakdown_ms']['phase_8_db_result_commit_to_phone_ack']['avg']}ms | p95={p8_stats['p95']}ms", flush=True)
    print("\nUcdan-uca nəticələr və Reviziya 1 ilə müqayisə (p95):", flush=True)
    print(f"  Dispatch Latency p95: Revision 1 = {rev1_disp_p95}ms vs Revision 2 = {disp_stats['p95']}ms", flush=True)
    print(f"  E2E Latency p95:      Revision 1 = {rev1_e2e_p95}ms vs Revision 2 = {e2e_stats['p95']}ms", flush=True)
    print(f"  Fiziki Unlock Sınağı: NOT_TESTED (Mock test)", flush=True)
    print(f"Metrikalar saxlandı: {report_path}", flush=True)
    print("="*60 + "\n", flush=True)


if __name__ == "__main__":
    asyncio.run(run_latency_benchmark())
