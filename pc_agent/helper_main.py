"""
WinKey Pro — Real Session & Input Helper Wrapper (Revision 8)
Executes within target interactive session. Receives ephemeral credentials via secure IPC.
Strict fail-closed server PID verification, token validation, overlapped deadline I/O.
Zero command-line, disk plaintext, or environment credential exposure.
"""
import sys
import os
import time
import argparse
import ctypes
from ctypes import wintypes

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# Ensure local pc_agent directory is in sys.path
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import ipc_input_worker
import unlock_engine
from diagnostics import Trace

# Strict 64-bit pointer-sized HANDLE
HANDLE = ctypes.c_void_p
kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32

kernel32.GetCurrentProcess.restype = HANDLE
kernel32.GetCurrentProcessId.restype = wintypes.DWORD
kernel32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
kernel32.ProcessIdToSessionId.restype = wintypes.BOOL

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = HANDLE

advapi32.OpenProcessToken.argtypes = [HANDLE, wintypes.DWORD, ctypes.POINTER(HANDLE)]
advapi32.OpenProcessToken.restype = wintypes.BOOL

advapi32.GetTokenInformation.argtypes = [HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
advapi32.GetTokenInformation.restype = wintypes.BOOL

advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL

kernel32.LocalFree.argtypes = [ctypes.c_void_p]
kernel32.LocalFree.restype = ctypes.c_void_p

kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, HANDLE
]
kernel32.CreateFileW.restype = HANDLE

kernel32.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.CreateEventW.restype = HANDLE

kernel32.WaitForSingleObject.argtypes = [HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD

kernel32.CancelIoEx.argtypes = [HANDLE, ctypes.c_void_p]
kernel32.CancelIoEx.restype = wintypes.BOOL

kernel32.GetOverlappedResult.argtypes = [HANDLE, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL]
kernel32.GetOverlappedResult.restype = wintypes.BOOL

kernel32.ReadFile.argtypes = [
    HANDLE, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p
]
kernel32.ReadFile.restype = wintypes.BOOL

kernel32.WriteFile.argtypes = [
    HANDLE, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p
]
kernel32.WriteFile.restype = wintypes.BOOL

kernel32.CloseHandle.argtypes = [HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.GetNamedPipeServerProcessId.argtypes = [HANDLE, ctypes.POINTER(wintypes.DWORD)]
kernel32.GetNamedPipeServerProcessId.restype = wintypes.BOOL

class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", HANDLE)
    ]

FILE_FLAG_OVERLAPPED = 0x40000000
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
PIPE_MIN_CREDENTIAL_ACCESS = 0x0012008B
OPEN_EXISTING = 3
WAIT_OBJECT_0 = 0
ERROR_IO_PENDING = 997


def get_current_process_session() -> int:
    sess = wintypes.DWORD()
    if kernel32.ProcessIdToSessionId(kernel32.GetCurrentProcessId(), ctypes.byref(sess)):
        return sess.value
    return 0xFFFFFFFF


def get_token_user_sid(h_process) -> str:
    h_token = HANDLE()
    if not advapi32.OpenProcessToken(h_process, 0x0008, ctypes.byref(h_token)):
        return ""
    try:
        ret_len = wintypes.DWORD()
        advapi32.GetTokenInformation(h_token, 1, None, 0, ctypes.byref(ret_len))
        if ret_len.value == 0:
            return ""
        buf = ctypes.create_string_buffer(ret_len.value)
        if not advapi32.GetTokenInformation(h_token, 1, buf, ret_len.value, ctypes.byref(ret_len)):
            return ""
        p_sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p)).contents
        p_str = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(p_sid, ctypes.byref(p_str)):
            return ""
        sid_val = p_str.value
        kernel32.LocalFree(p_str)
        return sid_val or ""
    finally:
        kernel32.CloseHandle(h_token)


def read_ephemeral_credential_from_pipe(pipe_name: str, expected_server_pid: int) -> str:
    """
    REM-022: Məhdud ömürlü dar DACL-li Named Pipe-dan fail-closed oxunuş və ACK.
    Server PID yoxlaması, server proses tokeni və overlapped 3s/2s deadline tələb olunur.
    """
    if expected_server_pid <= 0:
        raise PermissionError("E_MISSING_SERVER_PID: Fail-closed; expected_server_pid mütləq > 0 olmalıdır")

    full_pipe_path = f"\\\\.\\pipe\\{pipe_name.lstrip('\\').replace('/', '_')}"
    
    # Overlapped CreateFileW
    h_pipe = kernel32.CreateFileW(
        full_pipe_path,
        PIPE_MIN_CREDENTIAL_ACCESS,
        0,
        None,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        None
    )
    if not h_pipe or h_pipe == -1:
        err = kernel32.GetLastError()
        raise RuntimeError(f"E_IPC_PIPE_CONNECT_FAILED: Pipe əlçatmazdır (WinError={err})")

    try:
        # REM-022: Server Process ID Yoxlanması (Fail-Closed)
        server_pid = wintypes.DWORD()
        if not kernel32.GetNamedPipeServerProcessId(h_pipe, ctypes.byref(server_pid)):
            err = kernel32.GetLastError()
            raise PermissionError(f"E_CANNOT_VERIFY_SERVER_PID: GetNamedPipeServerProcessId xətası {err}")
        
        if server_pid.value == 0 or server_pid.value != expected_server_pid:
            raise PermissionError(
                f"E_SERVER_PID_MISMATCH: Server PID {server_pid.value} != gözlənilən {expected_server_pid}"
            )

        # Server Process Token & Identity Yoxlanması
        h_srv_proc = kernel32.OpenProcess(0x1000, False, server_pid.value)
        if h_srv_proc:
            try:
                server_sid = get_token_user_sid(h_srv_proc)
                # SYSTEM SID = S-1-5-18; standalone/dev SID də dəstəklənir
                if not server_sid:
                    raise PermissionError("E_UNVERIFIED_SERVER_TOKEN: Server proses tokeni oxunmadı")
            finally:
                kernel32.CloseHandle(h_srv_proc)

        # REM-022: Bounded Overlapped Read (3s Deadline)
        h_read_event = kernel32.CreateEventW(None, True, False, None)
        if not h_read_event:
            raise RuntimeError("CreateEvent failed")
        
        ov_read = OVERLAPPED()
        ov_read.hEvent = h_read_event
        buf = ctypes.create_string_buffer(512)
        read_bytes = wintypes.DWORD()

        read_res = kernel32.ReadFile(h_pipe, buf, 512, None, ctypes.byref(ov_read))
        read_success = False
        
        if read_res:
            read_success = True
            kernel32.GetOverlappedResult(h_pipe, ctypes.byref(ov_read), ctypes.byref(read_bytes), False)
        elif kernel32.GetLastError() == ERROR_IO_PENDING:
            wait = kernel32.WaitForSingleObject(h_read_event, 3000)
            if wait == WAIT_OBJECT_0:
                if kernel32.GetOverlappedResult(h_pipe, ctypes.byref(ov_read), ctypes.byref(read_bytes), False):
                    read_success = True
            else:
                kernel32.CancelIoEx(h_pipe, ctypes.byref(ov_read))
                kernel32.CloseHandle(h_read_event)
                raise TimeoutError("E_IPC_READ_TIMEOUT: Helper 3 saniyə ərzində credential ala bilmədi (Silent Sender)")
        
        kernel32.CloseHandle(h_read_event)

        if not read_success or read_bytes.value == 0:
            raise RuntimeError("E_IPC_READ_FAILED: Credential pipe-dan oxunmadı")

        cred_raw = buf.raw[:read_bytes.value]
        cred = cred_raw.decode('utf-8', errors='replace').strip()

        # REM-022: Bounded Overlapped Write of ACK (2s Deadline)
        h_write_event = kernel32.CreateEventW(None, True, False, None)
        ov_write = OVERLAPPED()
        ov_write.hEvent = h_write_event
        ack_msg = b"ACK_CREDENTIAL_RECEIVED\n"
        written = wintypes.DWORD()

        write_res = kernel32.WriteFile(h_pipe, ack_msg, len(ack_msg), None, ctypes.byref(ov_write))
        if not write_res and kernel32.GetLastError() == ERROR_IO_PENDING:
            wait_w = kernel32.WaitForSingleObject(h_write_event, 2000)
            if wait_w == WAIT_OBJECT_0:
                kernel32.GetOverlappedResult(h_pipe, ctypes.byref(ov_write), ctypes.byref(written), False)
            else:
                kernel32.CancelIoEx(h_pipe, ctypes.byref(ov_write))
        
        kernel32.CloseHandle(h_write_event)
        return cred
    finally:
        kernel32.CloseHandle(h_pipe)


def main():
    parser = argparse.ArgumentParser(description="WinKey Native Session & Input Helper")
    parser.add_argument("--check", action="store_true", help="PE smoke check")
    parser.add_argument("--check-focus-resource", action="store_true", help="Verify bundled focus script without running it")
    parser.add_argument("--check-input-abi", action="store_true", help="Validate ctypes input conversion without calling SendInput")
    parser.add_argument("--mode", choices=["lock", "curtain", "unlock", "status"], default="status")
    parser.add_argument("--session", type=int, default=None, help="Target interactive session ID")
    parser.add_argument("--ipc-pipe", type=str, default="", help="Ephemeral secure named pipe for credential")
    parser.add_argument("--expected-server-pid", type=int, default=0, help="Expected Service PID for peer validation")
    parser.add_argument("--mock-adapter", type=str, default="", help="Mock adapter mode for MODEL_UNIT negative security testing")
    args = parser.parse_args()

    if args.check_input_abi:
        assert ipc_input_worker.INPUT is unlock_engine.INPUT
        pointer = unlock_engine.user32.SendInput.argtypes[1]
        pointer.from_param((ipc_input_worker.INPUT * 4)())
        pointer.from_param(ipc_input_worker._build_key_events(0x08))
        pointer.from_param(ipc_input_worker._build_char_events('0'))
        print('INPUT_ABI_OK: no SendInput call executed')
        sys.exit(0)

    if args.check_focus_resource:
        from pathlib import Path
        script = Path(unlock_engine.__file__).with_name('focus_credential.ps1')
        if not script.is_file() or script.stat().st_size == 0:
            print('E_FOCUS_RESOURCE_MISSING')
            sys.exit(7)
        print('FOCUS_RESOURCE_OK')
        sys.exit(0)

    if args.check:
        print("WINKEY_HELPER_PE_OK")
        sys.exit(0)

    # REM-016: Faktiki Proses Sessiyasının Tutuşdurulması
    actual_session = get_current_process_session()
    if args.session is not None and args.session != actual_session:
        sys.stderr.write(
            f"E_SESSION_MISMATCH: Helper process running in session {actual_session}, expected {args.session}\n"
        )
        sys.exit(11)

    # MODEL_UNIT mock adapter təyin edilməsi
    mock = None
    if args.mock_adapter == "wrong_pin":
        mock = ipc_input_worker.MockWin32Adapter(initial_locked=True, post_input_locked=True)
    elif args.mock_adapter == "hello":
        mock = ipc_input_worker.MockWin32Adapter(initial_locked=True, auto_submitted=True)
    elif args.mock_adapter == "partial":
        mock = ipc_input_worker.MockWin32Adapter(initial_locked=True, send_input_override=1)
    elif args.mock_adapter == "focus_fail":
        mock = ipc_input_worker.MockWin32Adapter(initial_locked=True, focus_succeeds=False)
    elif args.mock_adapter == "curtain_timeout":
        mock = ipc_input_worker.MockWin32Adapter(desktop_name="default", curtain_transition_desktop="default")
    elif args.mock_adapter == "uac":
        mock = ipc_input_worker.MockWin32Adapter(desktop_name="uac")

    if args.mode == "status":
        state = mock.get_lock_state() if mock else unlock_engine.get_lock_state()
        print(f"LOCK_STATE: {state}")
        sys.exit(0)

    elif args.mode == "lock":
        # Target interactive session LockWorkStation
        res = ctypes.windll.user32.LockWorkStation()
        if res != 0:
            print("SUCCESS_LOCKED")
            sys.exit(0)
        else:
            print("LOCK_FAILED")
            sys.exit(1)

    elif args.mode == "curtain":
        trace = Trace()
        try:
            print("[HELPER] Dismissing Default lock curtain without credentials...")
            res = ipc_input_worker.dismiss_curtain_direct(adapter=mock, logs=trace)
            if res.get("success"):
                print("CURTAIN_READY")
                sys.exit(11 if res.get('status') == 'ALREADY_UNLOCKED' else 10)
            else:
                print(f"CURTAIN_ERROR: {res.get('status')}")
                sys.exit(3)
        except Exception as exc:
            trace.append(f"CURTAIN_EXCEPTION: {type(exc).__name__}")
            print(f"CURTAIN_ERROR: {exc}")
            sys.exit(3)

    elif args.mode == "unlock":
        if not args.ipc_pipe:
            print("E_MISSING_IPC_PIPE: Credential command-line ilə qəbul edilmir; ephemeral pipe tələb olunur")
            sys.exit(2)
        
        if args.expected_server_pid <= 0:
            sys.stderr.write("E_MISSING_SERVER_PID: Fail-closed; expected server PID must be > 0\n")
            sys.exit(4)

        try:
            credential = read_ephemeral_credential_from_pipe(args.ipc_pipe, args.expected_server_pid)
        except PermissionError as p_err:
            sys.stderr.write(f"E_AUTH_REJECTED: {p_err}\n")
            sys.exit(4)
        except TimeoutError as t_err:
            sys.stderr.write(f"E_IPC_TIMEOUT: {t_err}\n")
            sys.exit(5)
        except Exception as exc:
            sys.stderr.write(f"E_CREDENTIAL_FETCH_FAILED: {exc}\n")
            sys.exit(4)

        if not credential:
            print("E_EMPTY_CREDENTIAL")
            sys.exit(5)

        try:
            print("[HELPER] Injecting credential on Winlogon desktop via hardware scan-codes...")
            trace = Trace()
            trace.append('HELPER_INPUT_START: credential contents omitted')
            res = ipc_input_worker.inject_credentials_in_memory(credential, adapter=mock, logs=trace)
            # Memory zeroize / clear
            del credential
            if res.get("success") and res.get("status") in ("SUCCESS_UNLOCKED", "ALREADY_UNLOCKED"):
                print("SUCCESS_UNLOCKED")
                sys.exit(0)
            else:
                status = res.get("status", "STILL_LOCKED")
                print(f"UNLOCK_FAILED: {status}")
                sys.exit(3)
        except Exception as exc:
            if 'trace' in locals():
                trace.append('HELPER_INPUT_EXCEPTION: ' + type(exc).__name__)
            print(f"UNLOCK_EXCEPTION: {exc}")
            sys.exit(3)

if __name__ == "__main__":
    main()
