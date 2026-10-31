"""Short-lived input worker in the current session. Credentials stay in memory."""
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import subprocess
import sys
import psutil

class STARTUPINFO(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
                ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


def _launch_on_desktop(credential, logs, desktop="Winlogon", mode="unlock"):
    # CreateProcessWithTokenW uses the primary token for the entire process,
    # unlike ImpersonateLoggedOnUser, which changes only a thread token.
    try:
        from . import unlock_engine as engine
    except ImportError:
        import unlock_engine as engine
    engine.enable_debug_privilege()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    security.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    security.DuplicateTokenEx.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    security.CreateProcessWithTokenW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(STARTUPINFO), ctypes.POINTER(PROCESS_INFORMATION)]
    security.CreateProcessWithTokenW.restype = wintypes.BOOL
    handles = []
    try:
        session = wintypes.DWORD()
        if not kernel.ProcessIdToSessionId(os.getpid(), ctypes.byref(session)):
            raise ctypes.WinError(ctypes.get_last_error())
        for process in psutil.process_iter(['name']):
            candidate = wintypes.DWORD()
            if (process.info['name'] or '').lower() == 'winlogon.exe' and kernel.ProcessIdToSessionId(process.pid, ctypes.byref(candidate)) and candidate.value == session.value:
                target = process.pid
                break
        else:
            raise RuntimeError("Cari sessiyada Winlogon tapılmadı")
        logs.append(f"SYSTEM_TOKEN: session={session.value}; winlogon_pid={target}")
        proc = kernel.OpenProcess(0x0400, False, target)
        if not proc:
            raise ctypes.WinError(ctypes.get_last_error())
        handles.append(proc)
        token = wintypes.HANDLE()
        if not security.OpenProcessToken(proc, 0x000B, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        handles.append(token)
        primary = wintypes.HANDLE()
        if not security.DuplicateTokenEx(token, 0x02000000, None, 2, 1, ctypes.byref(primary)):
            raise ctypes.WinError(ctypes.get_last_error())
        handles.append(primary)
        env = dict(os.environ)
        env['WINKEY_WORKER_CREDENTIAL'] = credential
        env['WINKEY_SECURE_WORKER'] = '1'
        env['WINKEY_WORKER_MODE'] = mode
        env['WINKEY_ATTEMPT_ID'] = getattr(logs, 'attempt_id', '')
        environment = ctypes.create_unicode_buffer('\0'.join(f'{k}={v}' for k, v in sorted(env.items())) + '\0\0')
        script = str(Path(__file__).resolve())
        command = ctypes.create_unicode_buffer(subprocess.list2cmdline([sys.executable, script]))
        startup = STARTUPINFO()
        startup.cb = ctypes.sizeof(startup)
        startup.lpDesktop = 'winsta0\\' + desktop
        info = PROCESS_INFORMATION()
        logs.append(f"SYSTEM_CREATE_START: desktop=winsta0/{desktop}; mode={mode}; credential_present={bool(credential)}")
        if not security.CreateProcessWithTokenW(primary, 0, sys.executable, command, 0x08000400, environment, str(Path(script).parent), ctypes.byref(startup), ctypes.byref(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        handles.extend([info.hProcess, info.hThread])
        logs.append(f"SYSTEM_CREATED: pid={info.dwProcessId}")
        wait = kernel.WaitForSingleObject(info.hProcess, 30000)
        logs.append(f"SYSTEM_WAIT_END: wait_code={wait}")
        if wait != 0:
            kernel.TerminateProcess(info.hProcess, 4)
            raise RuntimeError("SYSTEM köməkçisi vaxtında cavab vermədi")
        code = wintypes.DWORD()
        if not kernel.GetExitCodeProcess(info.hProcess, ctypes.byref(code)):
            raise ctypes.WinError(ctypes.get_last_error())
        logs.append(f"SYSTEM_EXIT: code={code.value}")
        if mode == 'curtain' and code.value == 10:
            return 'CURTAIN_READY'
        if mode == 'unlock' and code.value == 0:
            return 'SUCCESS'
        raise RuntimeError(f"SYSTEM köməkçisi kilidi aça bilmədi (kod {code.value}); unlock_debug.log faylını yoxlayın.")
    except OSError as exc:
        raise RuntimeError(f"SYSTEM köməkçisi başlamadı: {exc}. Serveri Administrator kimi başladın.") from exc
    finally:
        for handle in reversed(handles):
            kernel.CloseHandle(handle)


def launch(credential, logs):
    try:
        from . import unlock_engine as engine
    except ImportError:
        import unlock_engine as engine
    state = engine.get_lock_state()
    logs.append("UNLOCK_ROUTE: " + str(state))
    if state["desktop"].lower() == "default" and state["locked"]:
        logs.append("STAGE_1: click visible Default curtain; no credential passed to this process")
        _launch_on_desktop("", logs, "Default", "curtain")
    logs.append("STAGE_2: Winlogon credential process")
    return _launch_on_desktop(credential, logs, "Winlogon", "unlock")


def dismiss_curtain(engine, logs):
    engine.log_input_context(logs, "curtain_worker_start")
    for click_number in range(2):
        state = engine.get_lock_state()
        if state["desktop"].lower() == "winlogon":
            logs.append("CURTAIN_READY: active desktop is Winlogon")
            return
        if not state['wts'].get('confirmed') or not state['wts'].get('locked'):
            raise RuntimeError("CURTAIN_ABORT: session lock not confirmed; no desktop click")
        if state['desktop'].lower() != 'default':
            raise RuntimeError("CURTAIN_ABORT: active desktop unavailable")
        # This process starts on Default; clicks are never sent to inactive Winlogon.
        width = engine.user32.GetSystemMetrics(0)
        height = engine.user32.GetSystemMetrics(1)
        if width <= 0 or height <= 0:
            raise RuntimeError("CURTAIN_ABORT: invalid display size")
        x, y = width // 2, height // 3
        if not engine.user32.SetCursorPos(x, y):
            raise RuntimeError("CURTAIN_ABORT: SetCursorPos failed on Default")
        events = (engine.INPUT * 2)()
        events[0].type = events[1].type = 0
        events[0].mi.dwFlags = 0x0002
        events[1].mi.dwFlags = 0x0004
        engine.kernel32.SetLastError(0)
        sent = engine.user32.SendInput(2, events, ctypes.sizeof(engine.INPUT))
        error = engine.kernel32.GetLastError()
        logs.append(f"DEFAULT_CURTAIN_CLICK: number={click_number + 1}; x={x}; y={y}; accepted={sent}/2; win32_error={error}")
        if sent != 2:
            raise RuntimeError(f"CURTAIN_CLICK_FAILED: accepted={sent}/2; win32_error={error}")
        for poll in range(15):
            engine.time.sleep(0.1)
            after = engine.get_lock_state()
            logs.append(f"CURTAIN_TRANSITION: poll={poll}; evidence={after}")
            if after['desktop'].lower() == 'winlogon':
                logs.append("CURTAIN_READY: Default -> Winlogon confirmed")
                return
    raise RuntimeError("CURTAIN_NOT_DISMISSED: input desktop did not switch to Winlogon")


if __name__ == '__main__':
    import unlock_engine as engine
    credential = os.environ.pop('WINKEY_WORKER_CREDENTIAL', '')
    if os.environ.get('WINKEY_WORKER_MODE') == 'curtain':
        logs = engine.Trace()
        try:
            dismiss_curtain(engine, logs)
            sys.exit(10)
        except Exception as exc:
            logs.append(f"CURTAIN_ERROR: {type(exc).__name__}: {exc}")
            sys.exit(3)
    result = engine.unlock_workstation(credential)
    sys.exit(0 if result.get('success') else 3)
