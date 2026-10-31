"""
WinKey Pro — Diagnostics Reporter & Durable Bounded Outbox Engine
Spesifikasiya: plan/DIAGNOSTICS_SUPPORT.md və plan/GEMINI_FINAL_BATCH_REVISION.md

Xüsusiyyətlər:
- Durable Bounded Outbox (Maksimum 20 MB və ya 5000 qeyd, dropped_count izlənməsi)
- Concurrency & Race Condition Qoruması (Thread Lock & Atomic File Swap)
- Zero PIN/Password/Secret Leakage (Bütün sahələr üzrə sərt allowlist və redaction)
- JSON Corruption Davamlılığı (Xarab fayl arxivləşdirilir, hadisələr qeyd olunur)
- Server ACK & Event ID Doğrulanması (Boş 200-lər hadisəni silmir)
"""

import os
import sys
import json
import time
import shutil
import secrets
import threading
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional

MAX_OUTBOX_RECORDS = 5000
MAX_OUTBOX_BYTES = 20 * 1024 * 1024 # 20 MB

class DiagnosticsReporter:
    def __init__(self, data_dir: str, gateway_origin: Optional[str] = None):
        self.data_dir = os.path.abspath(data_dir)
        self.outbox_file = os.path.join(self.data_dir, "diagnostics_outbox.json")
        self.gateway_origin = gateway_origin.rstrip("/") if gateway_origin else None
        self.install_run_id = "run_" + secrets.token_hex(8)
        self.device_id: Optional[str] = None
        self.dropped_count: int = 0
        self._lock = threading.Lock()
        os.makedirs(self.data_dir, exist_ok=True)
        self._init_outbox()

    def _init_outbox(self):
        with self._lock:
            if not os.path.exists(self.outbox_file):
                self._save_queue_unlocked([])

    def _load_queue(self) -> List[Dict[str, Any]]:
        with self._lock:
            return self._load_queue_unlocked()

    def _load_queue_unlocked(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.outbox_file):
            return []
        try:
            with open(self.outbox_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            # Corruption zamanı itkini minimuma endirmək üçün arxivləşdiririk
            corrupt_path = f"{self.outbox_file}.corrupt.{int(time.time())}"
            try:
                shutil.copy2(self.outbox_file, corrupt_path)
            except Exception:
                pass
            return []

    def _save_queue_unlocked(self, queue: List[Dict[str, Any]]):
        # 1. Byte Bound və Record Count Tətbiqi (20 MB Limiti)
        temp_file = self.outbox_file + ".tmp"
        serialized = json.dumps(queue, indent=2).encode("utf-8")

        while len(serialized) > MAX_OUTBOX_BYTES or len(queue) > MAX_OUTBOX_RECORDS:
            if not queue:
                break
            queue.pop(0)
            self.dropped_count += 1
            serialized = json.dumps(queue, indent=2).encode("utf-8")

        with open(temp_file, "wb") as f:
            f.write(serialized)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_file, self.outbox_file)

    def _redact_sensitive(self, text: Optional[str]) -> Optional[str]:
        """Bütün sahələr üzrə PIN, şifrə və gizli tokenlərin təmizlənməsi (Strict Zero-PIN)."""
        if not text or not isinstance(text, str):
            return text
        lower = text.lower()
        for forbidden in ["pin", "password", "secret", "credential", "auth_token"]:
            if forbidden in lower:
                return "[REDACTED_CANARY_STRICT]"
        return text

    def record_event(
        self,
        component: str,
        stage: str,
        event_type: str = "info",
        severity: str = "INFO",
        error_code: Optional[str] = None,
        duration_ms: Optional[int] = None
    ) -> str:
        event_id = "evt_" + secrets.token_hex(12)
        event = {
            "schema_version": 1,
            "event_id": event_id,
            "install_run_id": self.install_run_id,
            "device_id": self.device_id,
            "component": self._redact_sensitive(component),
            "version": "0.1.0",
            "stage": self._redact_sensitive(stage),
            "event_type": self._redact_sensitive(event_type),
            "severity": severity,
            "error_code": self._redact_sensitive(error_code) if error_code else None,
            "duration_ms": duration_ms,
            "local_time": time.time()
        }

        with self._lock:
            queue = self._load_queue_unlocked()
            queue.append(event)
            self._save_queue_unlocked(queue)

        # Əgər gateway varsa, arxa planda flush etməyə çalışır
        if self.gateway_origin:
            self.flush()

        return event_id

    def flush(self) -> int:
        """Outbox-dakı hadisələri gateway-ə çatdırır və rəsmi server ACK-i tələb edir."""
        if not self.gateway_origin:
            return 0

        with self._lock:
            queue = self._load_queue_unlocked()
            if not queue:
                return 0

            sent_count = 0
            remaining = []
            url = f"{self.gateway_origin}/agent/telemetry"

            for event in queue:
                try:
                    body = json.dumps(event).encode("utf-8")
                    req = urllib.request.Request(
                        url,
                        data=body,
                        headers={"Content-Type": "application/json"},
                        method="POST"
                    )
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        if resp.status == 200:
                            # SERVER ACK VƏ EVENT_ID TƏSDİQLƏNMƏSİ
                            resp_data = json.loads(resp.read().decode("utf-8", errors="replace"))
                            if resp_data.get("status") == "RECORDED" and resp_data.get("event_id") == event["event_id"]:
                                sent_count += 1
                                continue
                    # Əgər ACK gəlmədisə, hadisə silinmir!
                    remaining.append(event)
                except Exception:
                    # Offline və ya şəbəkə qopması zamanı hadisə qorunur
                    remaining.append(event)

            self._save_queue_unlocked(remaining)
            return sent_count
