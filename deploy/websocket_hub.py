"""
WinKey Pro — Async WebSocket Hub & Connection Manager
Spesifikasiya: plan/GEMINI_WEBSOCKET_BATCH.md & plan/GEMINI_WEBSOCKET_REVISION.md

Bu modul çoxsaylı Agent, Mobil və Admin WebSocket bağlantılarını idarə edir.
Hər bağlantı üçün izolyasiya edilmiş bounded queue (backpressure) istifadə olunur.
Bir cihaz üçün tək aktiv agent/claim sahibi qaydası (WS-02) təmin edilir;
eyni əmr heç vaxt paralel olaraq birdən çox agent soketinə göndərilmir.
"""

import asyncio
import json
import time
from typing import Dict, List, Set, Optional, Any

MAX_SOCKET_QUEUE_SIZE = 128
AUTH_DEADLINE_SECONDS = 5.0
MAX_FRAME_BYTES = 65536  # 64 KB


class ClientConnection:
    def __init__(self, ws, role: str, identifier: str, metadata: Optional[Dict[str, Any]] = None):
        self.ws = ws
        self.role = role  # "agent", "mobile", "admin"
        self.identifier = identifier  # device_id for agent/mobile, "admin" for admin
        self.metadata = metadata or {}
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=MAX_SOCKET_QUEUE_SIZE)
        self.is_active = True
        self.connected_at = time.time()
        self.last_seen = time.time()
        self.writer_task: Optional[asyncio.Task] = None

    async def start_writer(self):
        self.writer_task = asyncio.create_task(self._write_loop())

    async def _write_loop(self):
        try:
            while self.is_active:
                item = await self.queue.get()
                if item is None:  # Sentinel to terminate
                    break
                msg, receipt = item
                try:
                    await asyncio.wait_for(self.ws.send_text(msg), timeout=5.0)
                    if receipt and not receipt.done():
                        receipt.set_result(True)
                except BaseException:
                    if receipt and not receipt.done():
                        receipt.set_result(False)
                    raise
                finally:
                    self.queue.task_done()
        except Exception:
            self.is_active = False
        finally:
            self.is_active = False
            while not self.queue.empty():
                item = self.queue.get_nowait()
                if item and item[1] and not item[1].done():
                    item[1].set_result(False)
                self.queue.task_done()

    def enqueue(self, payload: Dict[str, Any]) -> bool:
        if not self.is_active:
            return False
        try:
            text = json.dumps(payload)
            self.queue.put_nowait((text, None))
            return True
        except asyncio.QueueFull:
            # Slow consumer protection (WS-07): teardown connection immediately
            self.is_active = False
            if self.writer_task and not self.writer_task.done():
                self.writer_task.cancel()
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self.close(code=4008, reason="SLOW_CONSUMER"))
            except RuntimeError:
                pass
            return False

    async def send_confirmed(self, payload):
        if not self.is_active:
            return False
        receipt = asyncio.get_running_loop().create_future()
        try:
            self.queue.put_nowait((json.dumps(payload), receipt))
        except asyncio.QueueFull:
            return False
        try:
            sent = await asyncio.wait_for(receipt, timeout=6.0)
        except asyncio.TimeoutError:
            sent = False
        if not sent:
            await self.close(code=4008, reason="COMMAND_DELIVERY_UNCERTAIN")
            raise RuntimeError("E_COMMAND_DELIVERY_UNCERTAIN")
        return True

    async def close(self, code: int = 1000, reason: str = "Normal"):
        self.is_active = False
        try:
            if self.writer_task and not self.writer_task.done():
                self.writer_task.cancel()
            await asyncio.wait_for(self.ws.close(code=code, reason=reason), timeout=1.0)
        except Exception:
            pass


class WebSocketHub:
    def __init__(self):
        self._agents: Dict[str, List[ClientConnection]] = {}  # device_id -> list[ClientConnection]
        self._mobiles: Dict[str, List[ClientConnection]] = {}  # device_id -> list[ClientConnection]
        self._admins: Set[ClientConnection] = set()
        self._lock: Optional[asyncio.Lock] = None
        self._total_commands_dispatched = 0
        self._total_results_received = 0
        self.http_poll_count = 0
        self.loop_lag_ms = 0.0

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def register_agent(self, conn: ClientConnection):
        async with self._get_lock():
            did = conn.identifier
            if did not in self._agents:
                self._agents[did] = []
            self._agents[did].append(conn)
            await conn.start_writer()

    async def register_mobile(self, conn: ClientConnection):
        async with self._get_lock():
            did = conn.identifier
            if did not in self._mobiles:
                self._mobiles[did] = []
            self._mobiles[did].append(conn)
            await conn.start_writer()

    async def register_admin(self, conn: ClientConnection):
        async with self._get_lock():
            self._admins.add(conn)
            await conn.start_writer()

    async def unregister(self, conn: ClientConnection):
        async with self._get_lock():
            did = conn.identifier
            if conn.role == "agent" and did in self._agents:
                self._agents[did] = [c for c in self._agents[did] if c != conn]
                if not self._agents[did]:
                    del self._agents[did]
            elif conn.role == "mobile" and did in self._mobiles:
                self._mobiles[did] = [c for c in self._mobiles[did] if c != conn]
                if not self._mobiles[did]:
                    del self._mobiles[did]
            elif conn.role == "admin":
                self._admins.discard(conn)

        await conn.close()

    def has_active_agent(self, device_id: str) -> bool:
        conns = self._agents.get(device_id, [])
        return any(c.is_active for c in conns)

    # --- PUSH & BROADCAST METHODS ---

    async def push_command_to_agent(self, device_id: str, command_id: str, action: str, created_at: float, timings: Optional[Dict[str, Any]] = None) -> bool:
        """
        WS-02 İnvaryantı: Bir cihaz üçün TƏK aktiv agent soketi əmri qəbul edir.
        Əmr əsla bir neçə agent bağlantısına paralel broadcast edilmir.
        """
        payload = {
            "type": "command",
            "command_id": command_id,
            "action": action,
            "created_at": created_at
        }
        if timings:
            payload["timings"] = timings
        delivered = False
        async with self._get_lock():
            active_conns = [c for c in self._agents.get(device_id, []) if c.is_active]
            if active_conns:
                # Ən son autentifikasiya olunmuş aktiv agent əsas qəbulçu (claim owner) olur
                target = active_conns[-1]
                # Wait outside the hub lock. Queue insertion alone isn't delivery.
                target = active_conns[-1]
            else:
                target = None

        if target:
            delivered = await target.send_confirmed(payload)

        if delivered:
            self._total_commands_dispatched += 1
            # Mobil müştərilərə status push edilir
            await self.push_command_status(device_id, command_id, "delivered", action)
        return delivered

    async def push_command_status(self, device_id: str, command_id: str, status: str, action: str):
        payload = {
            "type": "command_status",
            "command_id": command_id,
            "status": status,
            "action": action,
            "timestamp": time.time()
        }
        for m in list(self._mobiles.get(device_id, [])):
            if m.is_active:
                m.enqueue(payload)

    async def push_command_result(self, device_id: str, command_id: str, success: bool, status_str: str, completed_at: float, source_agent: Optional[ClientConnection] = None, timings: Optional[Dict[str, Any]] = None):
        """
        WS-03 İnvaryantı: Nəticə təsdiqi (result_ack) yalnız nəticəni təqdim edən
        agentə göndərilir, bütün agentlərə yayılmır.
        """
        payload = {
            "type": "command_result",
            "command_id": command_id,
            "status": "completed" if success else "failed",
            "result": status_str,
            "completed_at": completed_at
        }
        if timings:
            payload["timings"] = timings
        for m in list(self._mobiles.get(device_id, [])):
            if m.is_active:
                m.enqueue(payload)

        # ACK yalnız müvafiq agentə göndərilir
        ack_payload = {
            "type": "result_ack",
            "command_id": command_id
        }
        if source_agent and source_agent.is_active:
            source_agent.enqueue(ack_payload)
        else:
            for a in list(self._agents.get(device_id, [])):
                if a.is_active:
                    a.enqueue(ack_payload)
                    break

        self._total_results_received += 1

    async def push_device_state(self, device_id: str, locked: bool, pin_ready: bool, online: bool = True):
        payload = {
            "type": "device_state",
            "device_id": device_id,
            "locked": locked,
            "pin_ready": pin_ready,
            "online": online,
            "timestamp": time.time()
        }
        for m in list(self._mobiles.get(device_id, [])):
            if m.is_active:
                m.enqueue(payload)
        for adm in list(self._admins):
            if adm.is_active:
                adm.enqueue(payload)

    async def disconnect_device(self, device_id: str, code: int = 4403, reason: str = "REVOKED"):
        """Cihaz ləğv edildikdə bütün əlaqəli Agent və Mobil bağlantılarını kəsir."""
        targets = []
        async with self._get_lock():
            if device_id in self._agents:
                targets.extend(self._agents.pop(device_id))
            if device_id in self._mobiles:
                targets.extend(self._mobiles.pop(device_id))

        for conn in targets:
            await conn.close(code=code, reason=reason)

    async def disconnect_mobile_session(self, session_token: str, code: int = 4403, reason: str = "REVOKED"):
        """Mobil sessiya ləğv edildikdə həmin sessiyanın WebSocket bağlantısını kəsir."""
        targets = []
        async with self._get_lock():
            for did, m_list in list(self._mobiles.items()):
                matched = [c for c in m_list if c.metadata.get("session_token") == session_token]
                for m in matched:
                    if m in m_list:
                        m_list.remove(m)
                    targets.append(m)
                if not m_list and did in self._mobiles:
                    del self._mobiles[did]

        for conn in targets:
            await conn.close(code=code, reason=reason)

    def get_metrics(self) -> Dict[str, Any]:
        agent_count = sum(len(conns) for conns in self._agents.values())
        mobile_count = sum(len(conns) for conns in self._mobiles.values())
        admin_count = len(self._admins)
        return {
            "connected_agents": agent_count,
            "connected_mobiles": mobile_count,
            "connected_admins": admin_count,
            "active_device_ids": list(self._agents.keys()),
            "total_commands_dispatched": self._total_commands_dispatched,
            "total_results_received": self._total_results_received,
            "http_agent_polls": self.http_poll_count,
            "event_loop_lag_ms": self.loop_lag_ms
        }

# Global singleton hub
hub = WebSocketHub()
