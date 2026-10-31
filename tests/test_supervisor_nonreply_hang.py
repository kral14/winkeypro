"""
WinKey Pro — Service Supervisor Overlapped I/O & Nonreply Hanging Server Fault-Injection Test
Yoxlayır:
1. Server susduqda (nonreply / hang) check_pipe_health sonsuz bloklanmır, CancelIoEx ilə bounded vaxtda çıxır və False qaytarır.
2. Qırıq / natamam framing və ya JSON gəldikdə False qaytarır.
3. Yanlış server PID-i verildikdə təhlükəsiz rədd edir (False).
4. Sağlam RUNNING statusu gəldikdə True qaytarır.
"""

import os
import sys
import time
import json
import uuid
import ctypes
from ctypes import wintypes
import threading
import unittest

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Layihə kökünü əlavə edirik
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from pc_agent.service_supervisor import ServiceSupervisor

kernel32 = ctypes.windll.kernel32

PIPE_ACCESS_DUPLEX = 0x00000003
PIPE_TYPE_BYTE = 0x00000000
PIPE_READMODE_BYTE = 0x00000000
PIPE_WAIT = 0x00000000
INVALID_HANDLE_VALUE = -1

class TestSupervisorNonreplyHang(unittest.TestCase):

    def setUp(self):
        import tempfile
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base_dir = self.tmp_dir.name
        self.data_dir = os.path.join(self.base_dir, "data")
        os.makedirs(self.data_dir, exist_ok=True)
        self.supervisor = ServiceSupervisor(base_dir=self.base_dir, data_dir=self.data_dir, pinned_pubkey=b"\x00"*32)
        self.pipe_name = f"\\\\.\\pipe\\WinKey_Test_Nonreply_{uuid.uuid4().hex[:8]}"

    def tearDown(self):
        self.tmp_dir.cleanup()

    def _create_server_pipe(self):
        h_pipe = kernel32.CreateNamedPipeW(
            self.pipe_name,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            4096,
            4096,
            1000,
            None
        )
        return h_pipe

    def test_01_nonreply_hanging_server_bounded_timeout(self):
        """Fault-Injection: Server sorğunu qəbul edir, lakin heç vaxt cavab yazmır (susur/hang)."""
        stop_server = threading.Event()
        connected_evt = threading.Event()

        def hanging_server_worker():
            h_pipe = self._create_server_pipe()
            if h_pipe == INVALID_HANDLE_VALUE:
                return
            connected = kernel32.ConnectNamedPipe(h_pipe, None)
            if connected or kernel32.GetLastError() == 535: # ERROR_PIPE_CONNECTED
                connected_evt.set()
                # Server qəsdən susur və heç nə yazmır
                while not stop_server.is_set():
                    time.sleep(0.05)
            kernel32.DisconnectNamedPipe(h_pipe)
            kernel32.CloseHandle(h_pipe)

        t = threading.Thread(target=hanging_server_worker, daemon=True)
        t.start()
        time.sleep(0.1)

        t_start = time.time()
        # timeout_sec = 0.5 təyin edirik
        health = self.supervisor.check_pipe_health(pipe_name=self.pipe_name, timeout_sec=0.5)
        elapsed = time.time() - t_start

        stop_server.set()
        t.join(timeout=1.0)

        # Nonreply server üçün mütləq False qayıtmalıdır və bloklanmamalıdır (maksimum 1.8 saniyə)
        self.assertFalse(health, "Hanging server üçün sağlamlıq False olmalıdır!")
        self.assertLess(elapsed, 2.0, f"Overlapped CancelIoEx donmanı dayandıra bilmədi! Vaxt: {elapsed:.2f}s")
        print(f"\n[PASS] Nonreply server bounded çıxış: {elapsed:.2f}s (timeout_sec=0.5) -> Result: {health}")

    def test_02_partial_corrupted_response_rejected(self):
        """Framing / Schema: Server natamam və ya xarab JSON göndərdikdə fail-closed olmalıdır."""
        def corrupt_server_worker():
            h_pipe = self._create_server_pipe()
            if h_pipe == INVALID_HANDLE_VALUE:
                return
            connected = kernel32.ConnectNamedPipe(h_pipe, None)
            if connected or kernel32.GetLastError() == 535:
                # Natamam kəsik baytlar
                corrupt_bytes = b'{"status": "RUN'
                written = wintypes.DWORD(0)
                kernel32.WriteFile(h_pipe, corrupt_bytes, len(corrupt_bytes), ctypes.byref(written), None)
                time.sleep(0.2)
            kernel32.DisconnectNamedPipe(h_pipe)
            kernel32.CloseHandle(h_pipe)

        t = threading.Thread(target=corrupt_server_worker, daemon=True)
        t.start()
        time.sleep(0.1)

        health = self.supervisor.check_pipe_health(pipe_name=self.pipe_name, timeout_sec=0.8)
        t.join(timeout=1.0)

        self.assertFalse(health, "Xarab framing/JSON rədd edilməlidir!")
        print(f"[PASS] Corrupted/Partial framing düzgün rədd edildi -> Result: {health}")

    def test_03_pid_mismatch_rejected(self):
        """PID spoofing / Mismatch: Xidmətin gözlənilən PID-i uyğun gəlmədikdə rədd edilməlidir."""
        def normal_server_worker():
            h_pipe = self._create_server_pipe()
            if h_pipe == INVALID_HANDLE_VALUE:
                return
            connected = kernel32.ConnectNamedPipe(h_pipe, None)
            if connected or kernel32.GetLastError() == 535:
                resp = b'{"status": "RUNNING"}\n'
                written = wintypes.DWORD(0)
                kernel32.WriteFile(h_pipe, resp, len(resp), ctypes.byref(written), None)
                time.sleep(0.1)
            kernel32.DisconnectNamedPipe(h_pipe)
            kernel32.CloseHandle(h_pipe)

        t = threading.Thread(target=normal_server_worker, daemon=True)
        t.start()
        time.sleep(0.1)

        # Real proses deyil, saxta 999999 PID gözləyirik
        health = self.supervisor.check_pipe_health(pipe_name=self.pipe_name, timeout_sec=0.5, expected_pid=999999)
        t.join(timeout=1.0)

        self.assertFalse(health, "PID uyğunsuzluğu olduqda False qaytarmalıdır!")
        print(f"[PASS] PID mismatch rədd edildi -> Result: {health}")

    def test_04_healthy_server_accepted(self):
        """Normal / Healthy: Server düzgün RUNNING cavabı verdikdə True qaytarmalıdır."""
        def healthy_server_worker():
            h_pipe = self._create_server_pipe()
            if h_pipe == INVALID_HANDLE_VALUE:
                return
            connected = kernel32.ConnectNamedPipe(h_pipe, None)
            if connected or kernel32.GetLastError() == 535:
                buf = ctypes.create_string_buffer(512)
                read_b = wintypes.DWORD(0)
                kernel32.ReadFile(h_pipe, buf, 512, ctypes.byref(read_b), None)

                resp = b'{"status": "RUNNING", "version": "0.1.0"}\n'
                written = wintypes.DWORD(0)
                kernel32.WriteFile(h_pipe, resp, len(resp), ctypes.byref(written), None)
                kernel32.FlushFileBuffers(h_pipe)
                time.sleep(0.5)
            kernel32.DisconnectNamedPipe(h_pipe)
            kernel32.CloseHandle(h_pipe)

        t = threading.Thread(target=healthy_server_worker, daemon=True)
        t.start()
        time.sleep(0.1)

        # Cari proses PID-i ilə gözləyirik
        current_pid = os.getpid()
        health = self.supervisor.check_pipe_health(pipe_name=self.pipe_name, timeout_sec=1.0, expected_pid=current_pid)
        t.join(timeout=1.0)

        self.assertTrue(health, "Düzgün işləyən server üçün True qaytarmalıdır!")
        print(f"[PASS] Sağlam server uğurla təsdiqləndi -> Result: {health}")

if __name__ == "__main__":
    unittest.main()
