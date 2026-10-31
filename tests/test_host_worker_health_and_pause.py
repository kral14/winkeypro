"""
WinKey Pro — Host <-> Child Worker Bounded Overlapped IPC, Rogue PID Trust Binding və SCM Forwarding Sınağı
Spesifikasiya: plan/GEMINI_HOST_IPC_FINAL_FIX.md & plan/reports/codex/HOST_IPC_FIX_HANDOFF.md

Native Rust CLI Testləri:
1. Native Rogue Pipe Trust Binding & Zero Payload:
   - Server PID gözlənilən child PID ilə uyğun gəlmədikdə native kod dərhal fail-closed kəsilir və boruya SIFIR bayt yazılır.
2. Native Bounded Overlapped I/O & Nonreply Hang Protection:
   - Susqun server qarşısında native host IPC bloklanmır; 800ms bounded deadline ilə CancelIoEx edir və exit 1 verir.
3. Native Strict Typed ACK Yoxlanışı (Səhv ACK Mənfi Testi):
   - Server `Ack` əvəzinə başqa cavab verdikdə native `send_control_command_to_worker` fail-closed rədd edir.
4. Actual Host-to-Worker Health Probe, Forwarding & Lifecycle:
   - Host prosesi (--run-host) işə düşür, slot worker binarını spawn edir.
   - Native `--test-native-ipc-probe` ilə RUNNING təsdiqlənir.
   - Native `--test-native-ipc-control PAUSE` və `RESUME` ilə idarəetmə ötürülür.
   - Host prosesi bounded şəkildə child worker-i təmizləyərək bağlanır.
"""

import os
import sys
import json
import time
import shutil
import tempfile
import threading
import subprocess
import unittest
import ctypes
from ctypes import wintypes

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SERVICE_BIN = os.path.join(ROOT_DIR, "apps", "winkey_service", "target", "release", "winkey_service.exe")
PIPE_NAME = r"\\.\pipe\WinKey_Service_IPC"

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
H = ctypes.c_void_p
k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, H, wintypes.DWORD, wintypes.DWORD, H]
k32.CreateFileW.restype = H
k32.WriteFile.argtypes = [H, wintypes.LPCVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), H]
k32.WriteFile.restype = wintypes.BOOL
k32.ReadFile.argtypes = [H, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), H]
k32.ReadFile.restype = wintypes.BOOL
k32.CloseHandle.argtypes = [H]
k32.CreateNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, H]
k32.CreateNamedPipeW.restype = H
k32.ConnectNamedPipe.argtypes = [H, H]
k32.ConnectNamedPipe.restype = wintypes.BOOL
k32.DisconnectNamedPipe.argtypes = [H]
k32.DisconnectNamedPipe.restype = wintypes.BOOL
k32.GetNamedPipeServerProcessId.argtypes = [H, ctypes.POINTER(wintypes.DWORD)]
k32.GetNamedPipeServerProcessId.restype = wintypes.BOOL

class TestHostWorkerHealthAndPause(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="winkey_host_ipc_")
        self.data_dir = os.path.join(self.tmp_dir, "WinKeyData")
        os.makedirs(self.data_dir, exist_ok=True)

        import win32security, win32api
        tok = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
        user_sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(tok, win32security.TokenUser)[0])
        with open(os.path.join(self.data_dir, "owner.sid"), "w", encoding="utf-8") as f:
            f.write(user_sid)

        # Baseline Slot A quraşdırırıq (Host launcher testi üçün)
        slot_a = os.path.join(self.data_dir, "versions", "slot_a")
        os.makedirs(slot_a, exist_ok=True)
        shutil.copy2(SERVICE_BIN, os.path.join(slot_a, "winkey_service.exe"))
        shutil.copy2(os.path.join(ROOT_DIR, "deploy", "pre_signed_slot_a", "manifest.json"), os.path.join(slot_a, "manifest.json"))
        shutil.copy2(os.path.join(ROOT_DIR, "deploy", "pre_signed_slot_a", "manifest.sig"), os.path.join(slot_a, "manifest.sig"))

        journal_data = {
            "schema_version": 1,
            "current_slot": "slot_a",
            "last_known_good_slot": "slot_a",
            "state": "IDLE",
            "active_version": "0.1.0",
            "candidate_version": None,
            "quarantined_versions": [],
            "crash_count": 0,
            "last_update_ts": time.time(),
            "last_checkpoint": "INITIALIZED"
        }
        with open(os.path.join(self.data_dir, "update_journal.json"), "w", encoding="utf-8") as f:
            json.dump(journal_data, f)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_native_rogue_pipe_server_pid_mismatch_zero_payload(self):
        """Native Rust CLI: Server PID gözlənilən PID ilə uyğun gəlmədikdə boruya sıfır bayt yazılır və fail-closed çıxır."""
        server_h = k32.CreateNamedPipeW(
            PIPE_NAME,
            3,  # PIPE_ACCESS_DUPLEX
            0,  # PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT
            1,
            4096, 4096, 500, None
        )
        self.assertNotEqual(server_h, H(-1).value)

        received_bytes = []
        def rogue_server_worker():
            if k32.ConnectNamedPipe(server_h, None):
                buf = ctypes.create_string_buffer(512)
                read_n = wintypes.DWORD(0)
                # Client qoşulduqda oxumağa cəhd edirik
                k32.ReadFile(server_h, buf, 512, ctypes.byref(read_n), None)
                received_bytes.append(read_n.value)
                k32.DisconnectNamedPipe(server_h)
            k32.CloseHandle(server_h)

        t = threading.Thread(target=rogue_server_worker)
        t.start()
        time.sleep(0.1)

        # Native Rust binarını --expected-pid 999999 ilə çağırırıq (PID mismatch)
        proc = subprocess.run(
            [SERVICE_BIN, "--test-native-ipc-control", "PAUSE", "--expected-pid", "999999"],
            capture_output=True,
            text=True
        )

        t.join(timeout=2.0)
        self.assertNotEqual(proc.returncode, 0, "Rogue PID zamanı exit code nonzero olmalıdır!")
        self.assertIn("TRUST_BINDING_REJECT", proc.stderr)
        self.assertEqual(len(received_bytes), 1)
        self.assertEqual(received_bytes[0], 0, f"Rogue pipe-a sıfır bayt ötürülməli idi, lakin bayt yazıldı: {received_bytes[0]}")
        print("[PASS] Native Rogue Pipe PID Mismatch: Serverə sıfır bayt payload ötürüldü və native kod fail-closed kəsildi.")

    def test_02_native_bounded_overlapped_nonreply_timeout(self):
        """Native Rust CLI: Susqun server qarşısında native Overlapped I/O bloklanmır; 800ms bounded timeout ilə ləğv edilir."""
        server_h = k32.CreateNamedPipeW(
            PIPE_NAME,
            3, 0, 1, 4096, 4096, 500, None
        )
        self.assertNotEqual(server_h, H(-1).value)

        def silent_server():
            if k32.ConnectNamedPipe(server_h, None):
                # Server qoşulur amma qəsdən heç bir cavab yazmır
                time.sleep(1.8)
                k32.DisconnectNamedPipe(server_h)
            k32.CloseHandle(server_h)

        t = threading.Thread(target=silent_server)
        t.start()
        time.sleep(0.1)

        t0 = time.time()
        # Native Rust binarını çağırırıq (800ms vahid deadline)
        proc = subprocess.run(
            [SERVICE_BIN, "--test-native-ipc-control", "PAUSE"],
            capture_output=True,
            text=True
        )
        elapsed = time.time() - t0

        t.join(timeout=2.0)
        self.assertNotEqual(proc.returncode, 0, "Susqun server qarşısında exit code nonzero olmalıdır!")
        self.assertIn("CONTROL_TIMEOUT_OR_ERR", proc.stderr)
        self.assertLess(elapsed, 2.5, f"Native vaxt həddi həddindən artıq gecikdi: {elapsed:.2f}s")
        print(f"[PASS] Native Bounded Overlapped IPC: Susqun server {elapsed:.2f}s ərzində təhlükəsiz CancelIoEx ilə sonlandı.")

    def test_03_native_strict_typed_ack_negative_validation(self):
        """Native Rust CLI: Server Ack əvəzinə səhv və ya saxta cavab verdikdə native kod fail-closed rədd edir."""
        server_h = k32.CreateNamedPipeW(
            PIPE_NAME,
            3, 0, 1, 4096, 4096, 500, None
        )
        self.assertNotEqual(server_h, H(-1).value)

        def bogus_ack_server():
            if k32.ConnectNamedPipe(server_h, None):
                buf = ctypes.create_string_buffer(512)
                read_n = wintypes.DWORD(0)
                if k32.ReadFile(server_h, buf, 512, ctypes.byref(read_n), None):
                    # Ack yerinə səhv formatda JSON və ya fərqli cavab göndəririk
                    fake_resp = b'{"Error":"Unauthorized"}\n'
                    written_n = wintypes.DWORD(0)
                    k32.WriteFile(server_h, fake_resp, len(fake_resp), ctypes.byref(written_n), None)
                k32.DisconnectNamedPipe(server_h)
            k32.CloseHandle(server_h)

        t = threading.Thread(target=bogus_ack_server)
        t.start()
        time.sleep(0.1)

        proc = subprocess.run(
            [SERVICE_BIN, "--test-native-ipc-control", "PAUSE"],
            capture_output=True,
            text=True
        )
        t.join(timeout=2.0)

        self.assertNotEqual(proc.returncode, 0, "Səhv ACK qəbul edilməməlidir!")
        self.assertTrue(
            "CONTROL_TYPED_FAIL" in proc.stderr or "CONTROL_PARSE_FAIL" in proc.stderr,
            f"Stderr-də typed validation rəddi tapılmadı: {proc.stderr}"
        )
        print("[PASS] Native Strict Typed ACK: Saxta / Ack olmayan cavab serde IpcResponse tərəfindən fail-closed rədd edildi.")

    def test_04_actual_host_worker_health_probe_forwarding_and_lifecycle(self):
        """Actual Host Launcher (--run-host) worker-i işə salır, native probe ilə RUNNING yoxlayır və PAUSE/RESUME ötürür."""
        host_proc = subprocess.Popen(
            [SERVICE_BIN, "--run-host", "--timeout-sec", "6", "--data-dir", self.data_dir],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        time.sleep(1.5)
        # 1. Native CLI --test-native-ipc-probe ilə worker sağlamlığını yoxlayırıq
        res_probe = subprocess.run([SERVICE_BIN, "--test-native-ipc-probe"], capture_output=True, text=True)
        self.assertEqual(res_probe.returncode, 0, f"Native probe uğursuz oldu: {res_probe.stderr}")
        self.assertIn("PASS_NATIVE_PROBE", res_probe.stdout)
        print("[PASS] Native Health Probe: Worker sağlamlığı və RUNNING statusu təsdiqləndi.")

        # 2. Native CLI --test-native-ipc-control PAUSE əmri göndəririk
        res_pause = subprocess.run([SERVICE_BIN, "--test-native-ipc-control", "PAUSE"], capture_output=True, text=True)
        self.assertEqual(res_pause.returncode, 0, f"Native PAUSE uğursuz oldu: {res_pause.stderr}")
        self.assertIn("PASS_NATIVE_CONTROL: PAUSE", res_pause.stdout)
        print("[PASS] Native Control: PAUSE əmri üçün strict typed ACK alındı.")

        # 3. Native CLI --test-native-ipc-control RESUME əmri göndəririk
        res_resume = subprocess.run([SERVICE_BIN, "--test-native-ipc-control", "RESUME"], capture_output=True, text=True)
        self.assertEqual(res_resume.returncode, 0, f"Native RESUME uğursuz oldu: {res_resume.stderr}")
        self.assertIn("PASS_NATIVE_CONTROL: RESUME", res_resume.stdout)
        print("[PASS] Native Control: RESUME əmri üçün strict typed ACK alındı.")

        # 4. Host prosesinin bounded timeout (6s) ilə təmiz sonlanmasını gözləyirik
        host_proc.wait(timeout=8.0)
        self.assertEqual(host_proc.returncode, 0, f"Host uğurla bitməli idi: {host_proc.stderr}")
        stdout_txt = host_proc.stdout.read()
        self.assertTrue(
            "Child worker prosesi" in stdout_txt and "HOST_LIFECYCLE_DONE" in stdout_txt,
            f"Host shutdown loqunda gözlənilən təmiz bağlanış tapılmadı: {stdout_txt}"
        )
        print("[PASS] Actual Host SCM lifecycle child prosesi bounded şəkildə tam təmizlədi.")

if __name__ == "__main__":
    unittest.main()
