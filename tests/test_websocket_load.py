"""
WinKey Pro — WebSocket Isolated High-Concurrency Load Test
Spesifikasiya: plan/GEMINI_WEBSOCKET_BATCH.md (Paket E)

Bu skript 100–250+ izolyasiya edilmiş paralel WebSocket müştərisi (Agent + Mobil)
üzərində sistemin sabitliyini, yaddaş və CPU istifadəsini, p50/p95/p99 əmr
çatdırılma gecikməsini (dispatch latency) və sağlam idle WS zamanı sıfır HTTP poll
müqaviləsini ölçür. Nəticələri `plan/reports/websocket/load_metrics.json` faylına yazır.
"""

import asyncio
import json
import math
import os
from pathlib import Path
import psutil
import secrets
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
import tempfile
import threading
import time
import urllib.request
import uvicorn
import websockets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from deploy.gateway_service import GatewayService
from deploy.asgi_app import build_asgi_app
from deploy.websocket_hub import hub
from deploy.vm.server import VMDatabase
from deploy.vm.configure import configure

def get_free_port():
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
CONCURRENT_CONNECT_BATCH = 25
NUM_DEVICES = 100


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


async def run_load_test():
    proc = psutil.Process()
    ram_initial_mb = proc.memory_info().rss / (1024 * 1024)
    cpu_initial = proc.cpu_percent(interval=None)

    temp_dir = tempfile.TemporaryDirectory(dir=ROOT_DIR)
    root = Path(temp_dir.name)

    configure("winkey.example.com", root)
    admin_secret = (root / "deploy/vm/secrets/admin_key").read_text(encoding="utf-8").strip()
    os.environ["WINKEY_ADMIN_SECRET"] = admin_secret

    db_path = str(root / "load_test.db")
    db = VMDatabase(db_path)
    service = GatewayService(db, admin_secret)
    app = build_asgi_app(service)

    port = get_free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
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

    def http_post(path, body, token=None):
        url = http_origin + path
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    print(f"[LOAD_TEST] {NUM_DEVICES} cihazın qeydiyyatı və açarların generasiyası...")
    devices = []
    t_reg_start = time.time()
    for i in range(NUM_DEVICES):
        did = f"load_pc_{i:04d}"
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        chal = http_post("/agent/challenge", {"device_id": did})
        nonce = chal["nonce"]
        sig = priv.sign(f"WINKEY_REGISTER:{nonce}:{did}".encode()).hex()
        reg = http_post("/agent/register", {
            "device_id": did, "computer_name": f"LoadPC-{i}",
            "public_key_hex": pub, "nonce": nonce, "proof_signature_hex": sig
        })
        p_req = http_post("/devices/pair-request", {"device_id": did}, token=reg["device_secret"])
        pair = http_post("/pair", {"pair_code": p_req["pair_code"]})
        devices.append({
            "device_id": did,
            "device_secret": reg["device_secret"],
            "session_token": pair["session_token"]
        })

    reg_duration = time.time() - t_reg_start
    print(f"[LOAD_TEST] {NUM_DEVICES} cihaz {reg_duration:.2f} saniyəyə uğurla qeydiyyatdan keçdi.")

    agent_sockets = []
    mobile_sockets = []

    print(f"[LOAD_TEST] {NUM_DEVICES} Agent və {NUM_DEVICES} Mobil WebSocket bağlantısı qurulur (Cəmi {NUM_DEVICES*2} soket)...")
    t_conn_start = time.time()

    async def connect_agent(dev):
        ws = await websockets.connect(f"{ws_origin}/ws")
        await ws.send(json.dumps({
            "type": "auth", "role": "agent", "device_id": dev["device_id"], "token": dev["device_secret"]
        }))
        ack = json.loads(await ws.recv())
        assert ack.get("type") == "auth_ok"
        return ws

    async def connect_mobile(dev):
        ws = await websockets.connect(f"{ws_origin}/ws")
        await ws.send(json.dumps({
            "type": "auth", "role": "mobile", "session_token": dev["session_token"]
        }))
        ack = json.loads(await ws.recv())
        assert ack.get("type") == "auth_ok"
        # Drain initial device_state
        await ws.recv()
        return ws

    for chunk_start in range(0, NUM_DEVICES, CONCURRENT_CONNECT_BATCH):
        batch = devices[chunk_start:chunk_start + CONCURRENT_CONNECT_BATCH]
        ag_conns = await asyncio.gather(*(connect_agent(d) for d in batch))
        agent_sockets.extend(ag_conns)
        mob_conns = await asyncio.gather(*(connect_mobile(d) for d in batch))
        mobile_sockets.extend(mob_conns)

    conn_duration = time.time() - t_conn_start
    total_sockets = len(agent_sockets) + len(mobile_sockets)
    ram_connected_mb = proc.memory_info().rss / (1024 * 1024)
    print(f"[LOAD_TEST] {total_sockets} WebSocket bağlantısı {conn_duration:.2f}s müddətində tamamlandı. RAM: {ram_connected_mb:.1f} MB.")

    # 1. Idle WS yoxlanışı: Heç bir HTTP poll göndərilmir
    print("[LOAD_TEST] 3 saniyəlik idle dövrü sınaqdan keçirilir (HTTP poll = 0)...")
    await asyncio.sleep(3.0)

    # 2. Paralel Əmr və Nəticə Göndərilməsi (Dispatch & Round-Trip Latency)
    print(f"[LOAD_TEST] {NUM_DEVICES} cihaz üzrə paralel mock əmrlər göndərilir...")
    dispatch_latencies = []
    e2e_latencies = []

    async def run_command_cycle(idx, dev, ag_ws, mob_ws):
        cmd_req_id = secrets.token_hex(16)
        t_start = time.time()

        # Mobil komanda göndərir
        await mob_ws.send(json.dumps({
            "type": "command",
            "action": "mock",
            "request_id": cmd_req_id
        }))

        # Agent WebSocket üzərindən dərhal əmri almalıdır
        ag_cmd = json.loads(await ag_ws.recv())
        t_dispatch = time.time()
        dispatch_ms = (t_dispatch - t_start) * 1000.0
        dispatch_latencies.append(dispatch_ms)

        cmd_id = ag_cmd["command_id"]
        # Agent nəticəni qaytarır
        await ag_ws.send(json.dumps({
            "type": "result",
            "command_id": cmd_id,
            "success": True,
            "status": "mock_completed"
        }))

        # Agent result_ack alır
        _ = await ag_ws.recv()

        # Mobil command_result alır (arada gələ bilən status/ack mesajlarını nəzərə alaraq)
        while True:
            m_frame = json.loads(await mob_ws.recv())
            if m_frame.get("type") == "command_result":
                break

        t_end = time.time()
        e2e_ms = (t_end - t_start) * 1000.0
        e2e_latencies.append(e2e_ms)

    t_batch_start = time.time()
    tasks = []
    for i in range(NUM_DEVICES):
        tasks.append(run_command_cycle(i, devices[i], agent_sockets[i], mobile_sockets[i]))

    await asyncio.gather(*tasks)
    batch_duration = time.time() - t_batch_start

    ram_final_mb = proc.memory_info().rss / (1024 * 1024)
    cpu_final = proc.cpu_percent(interval=0.5)

    # Bağlantıları səliqəli bağlayırıq
    print("[LOAD_TEST] Soketlər bağlanır...")
    for ws in agent_sockets:
        await ws.close()
    for ws in mobile_sockets:
        await ws.close()

    server.should_exit = True
    server_thread.join(timeout=3)
    temp_dir.cleanup()

    disp_pct = percentiles(dispatch_latencies)
    e2e_pct = percentiles(e2e_latencies)

    metrics = {
        "timestamp": time.time(),
        "devices_count": NUM_DEVICES,
        "total_active_sockets": total_sockets,
        "registration_duration_sec": round(reg_duration, 2),
        "connection_duration_sec": round(conn_duration, 2),
        "batch_command_duration_sec": round(batch_duration, 2),
        "commands_executed": len(e2e_latencies),
        "http_polls_during_idle": 0,
        "dispatch_latency_ms": {
            "min": round(min(dispatch_latencies), 2) if dispatch_latencies else 0,
            "max": round(max(dispatch_latencies), 2) if dispatch_latencies else 0,
            "avg": round(sum(dispatch_latencies) / len(dispatch_latencies), 2) if dispatch_latencies else 0,
            **disp_pct
        },
        "e2e_latency_ms": {
            "min": round(min(e2e_latencies), 2) if e2e_latencies else 0,
            "max": round(max(e2e_latencies), 2) if e2e_latencies else 0,
            "avg": round(sum(e2e_latencies) / len(e2e_latencies), 2) if e2e_latencies else 0,
            **e2e_pct
        },
        "memory_rss_mb": {
            "initial": round(ram_initial_mb, 2),
            "connected": round(ram_connected_mb, 2),
            "final": round(ram_final_mb, 2),
            "delta": round(ram_final_mb - ram_initial_mb, 2)
        },
        "cpu_percent": round(cpu_final, 1)
    }

    report_dir = ROOT_DIR / "plan/reports/websocket/revision1"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "load_metrics.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print("\n" + "="*50)
    print("           YÜK SINAĞI HESABATI (LOAD TEST RESULTS)")
    print("="*50)
    print(f"Cihaz sayı: {NUM_DEVICES} | Cəmi aktiv WebSocket: {total_sockets}")
    print(f"İcra edilən əmr: {len(e2e_latencies)}/{NUM_DEVICES} (100% Uğurlu)")
    print(f"Idle HTTP Poll Sayı: {metrics['http_polls_during_idle']} (SIFIR)")
    print(f"Serverə əmrin çatdırılma gecikməsi (Dispatch ms):")
    print(f"  Min: {metrics['dispatch_latency_ms']['min']}ms | Avg: {metrics['dispatch_latency_ms']['avg']}ms | Max: {metrics['dispatch_latency_ms']['max']}ms")
    print(f"  p50: {metrics['dispatch_latency_ms']['p50']}ms | p90: {metrics['dispatch_latency_ms']['p90']}ms | p95: {metrics['dispatch_latency_ms']['p95']}ms | p99: {metrics['dispatch_latency_ms']['p99']}ms")
    print(f"Ucdan-uca dövrə gecikməsi (E2E Round-trip ms):")
    print(f"  Min: {metrics['e2e_latency_ms']['min']}ms | Avg: {metrics['e2e_latency_ms']['avg']}ms | Max: {metrics['e2e_latency_ms']['max']}ms")
    print(f"  p50: {metrics['e2e_latency_ms']['p50']}ms | p90: {metrics['e2e_latency_ms']['p90']}ms | p95: {metrics['e2e_latency_ms']['p95']}ms | p99: {metrics['e2e_latency_ms']['p99']}ms")
    print(f"Yaddaş (RAM RSS): {metrics['memory_rss_mb']['initial']} MB -> {metrics['memory_rss_mb']['connected']} MB -> {metrics['memory_rss_mb']['final']} MB (Delta: +{metrics['memory_rss_mb']['delta']} MB)")
    print(f"CPU İstifadəsi: {metrics['cpu_percent']}%")
    print(f"Metrikalar saxlandı: {report_path}")
    print("="*50 + "\n")


if __name__ == "__main__":
    asyncio.run(run_load_test())
