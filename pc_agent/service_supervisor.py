"""
WinKey Pro — Service Supervisor & Autonomous Boot Recovery Engine
Spesifikasiya: plan/UPDATE_ROLLBACK.md və plan/GEMINI_FINAL_BATCH_REVISION.md

Xüsusiyyətlər:
1. A/B Slot İdarəsi (Slot A / Slot B)
2. Imza, Hash və Bütövlük Təsdiqi
3. Real Win32 Named Pipe IPC Sağlamlıq Yoxlanışı (STATUS sorğusu)
4. Namizəd Qəzası və ya IPC Timeout Zamanı TƏK DÖVR DAXİLİNDƏ AVTOMATİK LKG BƏRPASI (Autonomous Auto-Recovery)
5. User Data (ProgramData/WinKey) Qorunması
"""

import os
import sys
import time
import json
import shutil
import hashlib
import subprocess
from typing import Optional, Tuple, Dict, Any

sys.path.insert(0, os.path.abspath("."))
try:
    from pc_agent.update_rollback_engine import UpdateRollbackEngine
except ModuleNotFoundError:
    try:
        from update_rollback_engine import UpdateRollbackEngine
    except ModuleNotFoundError:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from update_rollback_engine import UpdateRollbackEngine

class ServiceSupervisor:
    def __init__(self, base_dir: str, data_dir: str, pinned_pubkey: str):
        self.base_dir = os.path.abspath(base_dir)
        self.data_dir = os.path.abspath(data_dir)
        self.engine = UpdateRollbackEngine(self.base_dir, pinned_pubkey)
        self.current_process: Optional[subprocess.Popen] = None
        self.active_slot: str = "slot_a"

    def check_pipe_health(self, expected_pid: Optional[int] = None, timeout_sec: float = 3.0, pipe_name: Optional[str] = None) -> bool:
        """
        Real Windows Named Pipe (\\\\.\\pipe\\WinKey_Service_IPC) vasitəsilə
        server PID yoxlanışı və bloklanmayan (Overlapped I/O + CancelIoEx) STATUS yoxlayır.
        Fail-Closed: PID alınmazsa, server susarsa (timeout/cancel), WriteFile/ReadFile uğursuz olarsa
        və ya status RUNNING/OK gəlməzsə False qaytarır.
        """
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.windll.kernel32

        class OVERLAPPED(ctypes.Structure):
            _fields_ = [
                ("Internal", ctypes.c_void_p),
                ("InternalHigh", ctypes.c_void_p),
                ("Offset", wintypes.DWORD),
                ("OffsetHigh", wintypes.DWORD),
                ("hEvent", wintypes.HANDLE),
            ]

        if hasattr(kernel32, "CreateFileW"):
            kernel32.CreateFileW.restype = wintypes.HANDLE
            kernel32.CreateFileW.argtypes = [
                wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE
            ]
        if hasattr(kernel32, "CloseHandle"):
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL

        GetNamedPipeServerProcessId = getattr(kernel32, "GetNamedPipeServerProcessId", None)
        if GetNamedPipeServerProcessId:
            GetNamedPipeServerProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
            GetNamedPipeServerProcessId.restype = wintypes.BOOL

        CreateEventW = getattr(kernel32, "CreateEventW", None)
        if CreateEventW:
            CreateEventW.restype = wintypes.HANDLE
            CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]

        WaitForSingleObject = getattr(kernel32, "WaitForSingleObject", None)
        if WaitForSingleObject:
            WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            WaitForSingleObject.restype = wintypes.DWORD

        CancelIoEx = getattr(kernel32, "CancelIoEx", None)
        if CancelIoEx:
            CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
            CancelIoEx.restype = wintypes.BOOL

        GetOverlappedResult = getattr(kernel32, "GetOverlappedResult", None)
        if GetOverlappedResult:
            GetOverlappedResult.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL]
            GetOverlappedResult.restype = wintypes.BOOL

        GetLastError = getattr(kernel32, "GetLastError", lambda: 0)

        PIPE_MIN_USER_CHANNEL_MASK = 0x0012008B
        OPEN_EXISTING = 3
        FILE_FLAG_OVERLAPPED = 0x40000000
        ERROR_IO_PENDING = 997
        WAIT_OBJECT_0 = 0
        pipe_path = pipe_name or r"\\.\pipe\WinKey_Service_IPC"
        INVALID_HANDLE = wintypes.HANDLE(-1).value

        # Overlapped dəstəyi yoxlanışı
        has_overlapped = bool(CreateEventW and WaitForSingleObject and GetOverlappedResult)
        flags = FILE_FLAG_OVERLAPPED if has_overlapped else 0

        def _drain_and_cancel(h_p, ov, h_ev):
            """Win32 Overlapped Cancellation & Terminal Completion Drain Protocol"""
            if CancelIoEx:
                CancelIoEx(h_p, ctypes.byref(ov))
            if WaitForSingleObject and h_ev:
                WaitForSingleObject(h_ev, 200)
            dummy_bytes = wintypes.DWORD(0)
            if GetOverlappedResult:
                GetOverlappedResult(h_p, ctypes.byref(ov), ctypes.byref(dummy_bytes), False)

        start_t = time.time()
        while time.time() - start_t < timeout_sec:
            h_pipe = kernel32.CreateFileW(
                pipe_path,
                PIPE_MIN_USER_CHANNEL_MASK,
                0,
                None,
                OPEN_EXISTING,
                flags,
                None
            )
            if not h_pipe or h_pipe == INVALID_HANDLE:
                time.sleep(0.1)
                continue

            h_ev_write = None
            h_ev_read = None
            try:
                # 1. Server PID yoxlanışı (Fail-Closed)
                if expected_pid is not None:
                    if not GetNamedPipeServerProcessId:
                        kernel32.CloseHandle(h_pipe)
                        time.sleep(0.1)
                        continue
                    server_pid = wintypes.DWORD(0)
                    pid_ok = GetNamedPipeServerProcessId(h_pipe, ctypes.byref(server_pid))
                    if not pid_ok or server_pid.value != expected_pid:
                        kernel32.CloseHandle(h_pipe)
                        time.sleep(0.1)
                        continue

                # 2. STATUS request göndərilməsi (Overlapped və ya sinxron)
                req_payload = b'{"action":"STATUS"}\n'
                written = wintypes.DWORD(0)

                if has_overlapped:
                    h_ev_write = CreateEventW(None, True, False, None)
                    ov_write = OVERLAPPED()
                    ov_write.hEvent = h_ev_write
                    res_write = kernel32.WriteFile(h_pipe, req_payload, len(req_payload), None, ctypes.byref(ov_write))
                    if not res_write:
                        if GetLastError() == ERROR_IO_PENDING:
                            w_res = WaitForSingleObject(h_ev_write, int(max(0.1, timeout_sec) * 1000))
                            if w_res != WAIT_OBJECT_0:
                                _drain_and_cancel(h_pipe, ov_write, h_ev_write)
                                kernel32.CloseHandle(h_pipe)
                                time.sleep(0.1)
                                continue
                            GetOverlappedResult(h_pipe, ctypes.byref(ov_write), ctypes.byref(written), False)
                        else:
                            kernel32.CloseHandle(h_pipe)
                            time.sleep(0.1)
                            continue
                else:
                    write_ok = kernel32.WriteFile(h_pipe, req_payload, len(req_payload), ctypes.byref(written), None)
                    if not write_ok or (hasattr(written, 'value') and written.value == 0):
                        kernel32.CloseHandle(h_pipe)
                        time.sleep(0.1)
                        continue

                # 3. Cavabın oxunması (Overlapped deadline + CancelIoEx terminal drain)
                buf = ctypes.create_string_buffer(4096)
                read_bytes = wintypes.DWORD(0)

                if has_overlapped:
                    h_ev_read = CreateEventW(None, True, False, None)
                    ov_read = OVERLAPPED()
                    ov_read.hEvent = h_ev_read
                    res_read = kernel32.ReadFile(h_pipe, buf, 4096, None, ctypes.byref(ov_read))
                    if not res_read:
                        if GetLastError() == ERROR_IO_PENDING:
                            # Qalan vaxt qədər gözləyirik
                            rem_ms = int(max(0.1, timeout_sec - (time.time() - start_t)) * 1000)
                            r_res = WaitForSingleObject(h_ev_read, rem_ms)
                            if r_res != WAIT_OBJECT_0:
                                # SERVER SUSDU (Nonreply hanging server) -> Terminal cancellation və drain!
                                _drain_and_cancel(h_pipe, ov_read, h_ev_read)
                                kernel32.CloseHandle(h_pipe)
                                time.sleep(0.1)
                                continue
                            GetOverlappedResult(h_pipe, ctypes.byref(ov_read), ctypes.byref(read_bytes), False)
                        else:
                            kernel32.CloseHandle(h_pipe)
                            time.sleep(0.1)
                            continue
                    else:
                        # Dərhal tamamlanan oxuma üçün bayt sayını əldə edirik
                        GetOverlappedResult(h_pipe, ctypes.byref(ov_read), ctypes.byref(read_bytes), False)
                else:
                    read_ok = kernel32.ReadFile(h_pipe, buf, 4096, ctypes.byref(read_bytes), None)
                    if not read_ok or (hasattr(read_bytes, 'value') and read_bytes.value == 0):
                        kernel32.CloseHandle(h_pipe)
                        time.sleep(0.1)
                        continue

                # 4. Strict Schema yoxlanışı: Status mütləq RUNNING və ya OK olmalıdır
                resp_bytes = buf.raw[:read_bytes.value] if hasattr(read_bytes, 'value') else b""
                resp_str = resp_bytes.decode("utf-8", errors="replace").strip()
                try:
                    data = json.loads(resp_str)
                    st = data.get("status") or data.get("state")
                    if st in ("RUNNING", "OK", "ACTIVE"):
                        kernel32.CloseHandle(h_pipe)
                        return True
                except Exception:
                    pass

                kernel32.CloseHandle(h_pipe)
            except Exception:
                try:
                    kernel32.CloseHandle(h_pipe)
                except Exception:
                    pass
            finally:
                if h_ev_write: kernel32.CloseHandle(h_ev_write)
                if h_ev_read: kernel32.CloseHandle(h_ev_read)
            time.sleep(0.1)
        return False

    def start_supervised_service(self, is_mock: bool = False, health_timeout_sec: float = 4.0) -> Tuple[bool, str]:
        """
        Xidməti başladır və izləyir.
        Əgər namizəd çökərsə və ya IPC cavabı verməzsə, supervisor EYNİ METOD DAXİLİNDƏ
        avtomatik olaraq Last-Known-Good (LKG) slotuna qayıdır və xidməti bərpa edir!
        """
        journal = self.engine._read_journal()
        candidate = journal.get("candidate_version")
        target_slot = journal.get("current_slot", "slot_a")
        lkg_slot = journal.get("last_known_good_slot", "slot_a")

        print(f"[SUPERVISOR] Başladılır: Slot={target_slot} (Namizəd={candidate}, LKG={lkg_slot})")

        slot_dir = os.path.join(self.engine.versions_dir, target_slot)
        service_exe = os.path.join(slot_dir, "winkey_service.exe")

        # 1. Slot icra cəhdi
        success, proc, err_reason = self._spawn_binary(service_exe, is_mock)

        # 2. Əgər namizəd dərhal uğursuz oldusa və ya tez çökdüsə -> AVTOMATİK ROLLBACK VƏ BƏRPA
        crashed = False
        if not success:
            crashed = True
        else:
            # 2a. Real IPC sağlamlığı yoxlanışı
            t0 = time.time()
            ipc_ok = False
            while time.time() - t0 < health_timeout_sec:
                poll_res = proc.poll()
                if poll_res is not None:
                    crashed = True
                    err_reason = f"E_EARLY_CRASH_EXIT_{poll_res}"
                    break
                if self.check_pipe_health(expected_pid=proc.pid if (proc and hasattr(proc, 'pid')) else None, timeout_sec=0.4):
                    ipc_ok = True
                    break

            if not crashed and not ipc_ok:
                # Namizəd susdu (IPC Timeout)
                crashed = True
                err_reason = "E_IPC_HEALTH_TIMEOUT"

        # 3. AVTONOM BƏRPA ZƏNCİRİ (AUTONOMOUS AUTO-RECOVERY TO LKG)
        if crashed:
            print(f"[SUPERVISOR_ALERT] Namizəd ({target_slot}) uğursuz oldu: {err_reason}!")
            if proc and proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=2)
                except Exception: proc.kill()

            # Rollback tətiyi
            self.engine.trigger_rollback(err_reason)
            recovered_journal = self.engine._read_journal()
            safe_slot = recovered_journal.get("current_slot", "slot_a")

            print(f"[SUPERVISOR_AUTORECOVERY] Dərhal etibarlı LKG slot ({safe_slot}) qaldırılır...")
            safe_exe = os.path.join(self.engine.versions_dir, safe_slot, "winkey_service.exe")
            safe_ok, safe_proc, safe_err = self._spawn_binary(safe_exe, is_mock)

            if not safe_ok:
                return False, f"FATAL_LKG_FAILED_TO_START: {safe_err}"

            self.current_process = safe_proc
            self.active_slot = safe_slot
            print(f"[SUPERVISOR_AUTORECOVERY] Etibarlı LKG ({safe_slot}) uğurla bərpa olundu və işləyir!")
            return True, f"AUTONOMOUS_RECOVERED_TO_LKG_{safe_slot}"

        # Uğurlu namizəd təsdiqlənir
        self.current_process = proc
        self.active_slot = target_slot
        if candidate:
            journal["state"] = "COMMITTED"
            journal["last_known_good_slot"] = target_slot
            journal["active_version"] = candidate
            journal["candidate_version"] = None
            self.engine._write_journal(journal)
            print(f"[SUPERVISOR] Namizəd uğurla COMMITTED oldu: {target_slot} (v{candidate})")

        return True, f"RUNNING_ON_{target_slot}"

    def _spawn_binary(self, exe_path: str, is_mock: bool) -> Tuple[bool, Optional[subprocess.Popen], str]:
        if not os.path.exists(exe_path):
            return False, None, "E_EXE_FILE_NOT_FOUND"

        cmd = [exe_path, "--standalone", "--timeout-sec", "60", "--data-dir", self.data_dir]
        if is_mock:
            cmd.append("--mock")

        env = os.environ.copy()
        env["WINKEY_DATA_DIR"] = self.data_dir

        try:
            proc = subprocess.Popen(
                cmd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            time.sleep(0.3)
            poll_res = proc.poll()
            if poll_res is not None:
                return False, proc, f"E_EXIT_CODE_{poll_res}"
            return True, proc, "OK"
        except OSError as e:
            return False, None, f"E_OS_CREATE_PROCESS_{getattr(e, 'winerror', e)}"

    def stop_service(self):
        if self.current_process and self.current_process.poll() is None:
            self.current_process.terminate()
            try:
                self.current_process.wait(timeout=2)
            except Exception:
                self.current_process.kill()
            self.current_process = None

def main():
    import argparse
    parser = argparse.ArgumentParser(description="WinKey Pro Service Supervisor Boot Entrypoint")
    parser.add_argument("--service", action="store_true", help="Run supervisor as system boot entrypoint")
    parser.add_argument("--base-dir", default=os.path.abspath("."), help="Base install dir")
    parser.add_argument("--data-dir", default=r"C:\ProgramData\WinKey", help="Data storage dir")
    parser.add_argument("--pubkey", default="0" * 64, help="Pinned Ed25519 public key")
    parser.add_argument("--mock", action="store_true", help="Run in mock mode")
    args = parser.parse_args()

    supervisor = ServiceSupervisor(args.base_dir, args.data_dir, args.pubkey)

    if args.service:
        print("[SUPERVISOR_BOOT] SCM Boot Entrypoint başlatıldı...")
        ok, reason = supervisor.start_supervised_service(is_mock=args.mock, health_timeout_sec=5.0)
        print(f"[SUPERVISOR_BOOT] Nəticə: ok={ok}, reason={reason}")
        if not ok:
            sys.exit(1)
        try:
            while supervisor.current_process and supervisor.current_process.poll() is None:
                time.sleep(1.0)
        except KeyboardInterrupt:
            supervisor.stop_service()
        sys.exit(0)
    else:
        print("WinKey Pro Service Supervisor v0.1.0")

if __name__ == "__main__":
    main()
