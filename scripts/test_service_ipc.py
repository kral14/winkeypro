import sys
import time
import json
import ctypes
from ctypes import wintypes

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

PIPE_NAME = r"\\.\pipe\WinKey_Service_IPC"
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = -1

kernel32 = ctypes.windll.kernel32

def send_pipe_command(msg_str):
    handle = kernel32.CreateFileW(
        PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        None,
        OPEN_EXISTING,
        0,
        None
    )
    if handle == INVALID_HANDLE_VALUE:
        err = kernel32.GetLastError()
        raise RuntimeError(f"CreateFileW failed with Win32 Error: {err}")

    try:
        data = (msg_str + "\n").encode("utf-8")
        written = wintypes.DWORD()
        res = kernel32.WriteFile(handle, data, len(data), ctypes.byref(written), None)
        if not res:
            raise RuntimeError(f"WriteFile failed with Error: {kernel32.GetLastError()}")

        buf = ctypes.create_string_buffer(512)
        read = wintypes.DWORD()
        res = kernel32.ReadFile(handle, buf, 512, ctypes.byref(read), None)
        if not res:
            raise RuntimeError(f"ReadFile failed with Error: {kernel32.GetLastError()}")

        return buf.value[:read.value].decode("utf-8")
    finally:
        kernel32.CloseHandle(handle)

def run_test():
    print(f"Connecting to WinKey Service Pipe: {PIPE_NAME}")
    
    # 1. PING Test
    resp_ping = send_pipe_command("PING")
    print(f"[RECV] PING -> {resp_ping.strip()}")
    assert "ACK" in resp_ping and "WinKeyService" in resp_ping
    print("[PASS] PING ACK successfully received.")

    time.sleep(0.3)

    # 2. STATUS Test
    resp_stat = send_pipe_command("STATUS")
    print(f"[RECV] STATUS -> {resp_stat.strip()}")
    assert "RUNNING" in resp_stat
    print("[PASS] STATUS RUNNING successfully received.")

if __name__ == "__main__":
    try:
        run_test()
        sys.exit(0)
    except Exception as e:
        print(f"[FAIL] {e}")
        sys.exit(1)
