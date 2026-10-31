"""
Windows Lock / Unlock Engine with Hardware Scan Code Injection & Winlogon Token Impersonation.
RustDesk platform/windows.cc və enigo win_impl.rs əsasında.
"""
import ctypes
from ctypes import wintypes
import time
import winreg
import os
import datetime
import psutil
import hashlib
import threading
import subprocess
from pathlib import Path

try:
    from .diagnostics import Trace, VERSION
except ImportError:
    from diagnostics import Trace, VERSION

_unlock_lock = threading.Lock()
_input_stats = threading.local()

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32

LOG_FILE = os.path.join(os.environ.get("WINKEY_DATA_DIR", os.path.dirname(__file__)), "unlock_debug.log")
LOADED_ENGINE_SHA = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()[:12] if Path(__file__).is_file() else "packaged-build"

# Setup 64-bit safe Win32 API signatures
kernel32.GetCurrentProcess.restype = ctypes.c_void_p
kernel32.OpenProcess.restype = ctypes.c_void_p
advapi32.OpenProcessToken.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
advapi32.DuplicateTokenEx.argtypes = [
    ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)
]
advapi32.ImpersonateLoggedOnUser.argtypes = [ctypes.c_void_p]

# Pointer-sized handles are mandatory on 64-bit Windows.
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.GetCurrentThreadId.restype = wintypes.DWORD
kernel32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
kernel32.ProcessIdToSessionId.restype = wintypes.BOOL
user32.GetThreadDesktop.argtypes = [wintypes.DWORD]
user32.GetThreadDesktop.restype = wintypes.HANDLE
user32.OpenInputDesktop.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
user32.OpenInputDesktop.restype = wintypes.HANDLE
user32.SetThreadDesktop.argtypes = [wintypes.HANDLE]
user32.SetThreadDesktop.restype = wintypes.BOOL
user32.CloseDesktop.argtypes = [wintypes.HANDLE]
user32.CloseDesktop.restype = wintypes.BOOL
user32.OpenDesktopW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
user32.OpenDesktopW.restype = wintypes.HANDLE
user32.GetUserObjectInformationA.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
advapi32.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p]
advapi32.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]
user32.mouse_event.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_ulonglong]
user32.mouse_event.restype = None
user32.SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]
user32.SetCursorPos.restype = wintypes.BOOL
user32.GetSystemMetrics.argtypes = [ctypes.c_int]
user32.GetSystemMetrics.restype = ctypes.c_int

# Constants
HWND_BROADCAST = 0xFFFF
WM_SYSCOMMAND = 0x0112
SC_MONITORPOWER = 0xF170
MONITOR_ON = -1

ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001
ES_DISPLAY_REQUIRED = 0x00000002

KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004
VK_RETURN = 0x0D
VK_SPACE = 0x20
VK_ESCAPE = 0x1B
VK_BACK = 0x08

class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

class MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", wintypes.LONG),
        ("dy", wintypes.LONG),
        ("mouseData", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t)
    ]

class KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", wintypes.WORD),
        ("wScan", wintypes.WORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t)
    ]

class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [
        ("uMsg", wintypes.DWORD),
        ("wParamL", wintypes.WORD),
        ("wParamH", wintypes.WORD)
    ]

class INPUT(ctypes.Structure):
    class _INPUT(ctypes.Union):
        _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]
    _anonymous_ = ("_input",)
    _fields_ = [("type", wintypes.DWORD), ("_input", _INPUT)]

def get_desktop_name(hdesk):
    if not hdesk:
        return "NULL"
    name_buf = ctypes.create_string_buffer(256)
    size = wintypes.DWORD()
    if user32.GetUserObjectInformationA(hdesk, 2, name_buf, 256, ctypes.byref(size)):
        return name_buf.value.decode("utf-8", errors="replace")
    return "UNKNOWN"

def enable_debug_privilege():
    hToken = ctypes.c_void_p()
    if advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0028, ctypes.byref(hToken)):
        luid = LUID()
        if advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges[0].Luid = luid
            tp.Privileges[0].Attributes = 0x00000002 # SE_PRIVILEGE_ENABLED
            advapi32.AdjustTokenPrivileges(hToken, False, ctypes.byref(tp), 0, None, None)
        kernel32.CloseHandle(hToken)

def attach_to_winlogon_desktop():
    enable_debug_privilege()
    handles = []
    try:
        session = wintypes.DWORD()
        if not kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session)):
            return False, "Windows sessiyası tapılmadı"
        target = None
        for process in psutil.process_iter(['name']):
            if (process.info['name'] or '').lower() == 'winlogon.exe':
                candidate = wintypes.DWORD()
                if kernel32.ProcessIdToSessionId(process.pid, ctypes.byref(candidate)) and candidate.value == session.value:
                    target = process.pid
                    break
        if target is None:
            return False, "Bu sessiyada winlogon.exe tapılmadı"
        proc = kernel32.OpenProcess(0x0400, False, target)
        if not proc:
            return False, f"OpenProcess xətası: {ctypes.GetLastError()}"
        handles.append(proc)
        token = ctypes.c_void_p()
        if not advapi32.OpenProcessToken(proc, 0x000E, ctypes.byref(token)):
            return False, f"OpenProcessToken xətası: {ctypes.GetLastError()}"
        handles.append(token)
        duplicate = ctypes.c_void_p()
        if not advapi32.DuplicateTokenEx(token, 0x02000000, None, 2, 2, ctypes.byref(duplicate)):
            return False, f"DuplicateTokenEx xətası: {ctypes.GetLastError()}"
        handles.append(duplicate)
        if not advapi32.ImpersonateLoggedOnUser(duplicate):
            return False, f"Impersonate xətası: {ctypes.GetLastError()}"
        desktop = None
        for _ in range(8):
            desktop = user32.OpenInputDesktop(0, False, 0x01FF)
            if desktop:
                name = get_desktop_name(desktop).lower()
                if name == "winlogon":
                    break
                user32.CloseDesktop(desktop)
                desktop = None
            time.sleep(0.08)
        if not desktop:
            desktop = user32.OpenDesktopW("Winlogon", 0, False, 0x01FF)
        if not desktop:
            desktop = user32.OpenInputDesktop(0, False, 0x01FF)
        if not desktop:
            return False, f"OpenInputDesktop xətası: {ctypes.GetLastError()}"
        if not user32.SetThreadDesktop(desktop):
            error = ctypes.GetLastError()
            user32.CloseDesktop(desktop)
            return False, f"SetThreadDesktop xətası: {error}"
        return True, f"Desktop: {get_desktop_name(desktop)}"
    except Exception as exc:
        return False, str(exc)
    finally:
        for handle in reversed(handles):
            kernel32.CloseHandle(handle)


class WTSINFOEX_LEVEL1(ctypes.Structure):
    _fields_ = [("SessionId", wintypes.DWORD), ("SessionState", ctypes.c_int),
                ("SessionFlags", wintypes.LONG), ("WinStationName", wintypes.WCHAR * 33),
                ("UserName", wintypes.WCHAR * 21), ("DomainName", wintypes.WCHAR * 18),
                ("LogonTime", ctypes.c_longlong), ("ConnectTime", ctypes.c_longlong),
                ("DisconnectTime", ctypes.c_longlong), ("LastInputTime", ctypes.c_longlong),
                ("CurrentTime", ctypes.c_longlong), ("IncomingBytes", wintypes.DWORD),
                ("OutgoingBytes", wintypes.DWORD), ("IncomingFrames", wintypes.DWORD),
                ("OutgoingFrames", wintypes.DWORD), ("IncomingCompressedBytes", wintypes.DWORD),
                ("OutgoingCompressedBytes", wintypes.DWORD)]

class WTSINFOEX(ctypes.Structure):
    _fields_ = [("Level", wintypes.DWORD), ("Data", WTSINFOEX_LEVEL1)]


def query_session_state():
    api = ctypes.WinDLL("wtsapi32", use_last_error=True)
    api.WTSQuerySessionInformationW.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
    api.WTSQuerySessionInformationW.restype = wintypes.BOOL
    api.WTSFreeMemory.argtypes = [ctypes.c_void_p]
    session = wintypes.DWORD()
    if not kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session)):
        return {"confirmed": False, "error": "session_id_failed"}
    pointer = ctypes.c_void_p()
    size = wintypes.DWORD()
    if not api.WTSQuerySessionInformationW(None, session.value, 25, ctypes.byref(pointer), ctypes.byref(size)):
        return {"confirmed": False, "session": session.value, "error": ctypes.get_last_error()}
    try:
        if size.value < ctypes.sizeof(WTSINFOEX):
            return {"confirmed": False, "error": "short_WTSINFOEX", "bytes": size.value}
        info = ctypes.cast(pointer, ctypes.POINTER(WTSINFOEX)).contents
        flags = info.Data.SessionFlags
        return {"confirmed": info.Level == 1 and flags in (0, 1),
                "session": info.Data.SessionId, "flags": flags, "connection_state": info.Data.SessionState,
                "locked": flags != 1}
    finally:
        api.WTSFreeMemory(pointer)


def get_lock_state():
    session = query_session_state()
    desktop = user32.OpenInputDesktop(0, False, 0x0001)
    name = "UNAVAILABLE"
    if desktop:
        try:
            name = get_desktop_name(desktop)
        finally:
            user32.CloseDesktop(desktop)
    # An inaccessible/secure desktop or unknown WTS status must never report success.
    locked = name.lower() != "default" or not session.get("confirmed") or session.get("locked", True)
    return {"locked": bool(locked), "desktop": name, "wts": session}


def is_workstation_locked():
    return get_lock_state()["locked"]


def lock_workstation():
    return bool(user32.LockWorkStation())

def wake_screen():
    try:
        kernel32.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED)
        user32.SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, MONITOR_ON)
        # Ekranı oyatmaq üçün kursor hərəkəti
        user32.mouse_event(0x0001, 1, 0, 0, 0)
        time.sleep(0.02)
        user32.mouse_event(0x0001, -1, 0, 0, 0)
        # SAS (Ctrl+Alt+Del) siqnalı ilə Winlogon desktopunu dərhal oyadırıq
        try:
            sas = ctypes.WinDLL("sas.dll")
            sas.SendSAS(0)
        except Exception:
            pass
        return True
    except Exception:
        return False

user32.SendInput.argtypes = [wintypes.UINT, ctypes.POINTER(INPUT), ctypes.c_int]
user32.SendInput.restype = wintypes.UINT


class POINT(ctypes.Structure):
    _fields_ = [("x", wintypes.LONG), ("y", wintypes.LONG)]


def input_context():
    # Capture window metadata only, never window titles, edit contents or credentials.
    user32.GetForegroundWindow.restype = wintypes.HANDLE
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    user32.GetClassNameW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, ctypes.c_int]
    user32.GetCursorPos.argtypes = [ctypes.POINTER(POINT)]
    point = POINT()
    cursor_ok = user32.GetCursorPos(ctypes.byref(point))
    hwnd = user32.GetForegroundWindow()
    foreground_pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(foreground_pid))
    window_class = ctypes.create_unicode_buffer(256)
    user32.GetClassNameW(hwnd, window_class, 256)
    owner = "unknown"
    try:
        owner = psutil.Process(foreground_pid.value).name()
    except psutil.Error:
        pass
    thread_desktop = user32.GetThreadDesktop(kernel32.GetCurrentThreadId())
    return {"thread_desktop": get_desktop_name(thread_desktop), "input": get_lock_state(),
            "foreground_hwnd": hwnd, "foreground_pid": foreground_pid.value, "foreground_process": owner,
            "foreground_class": window_class.value, "cursor_ok": bool(cursor_ok),
            "cursor": [point.x, point.y] if cursor_ok else None}


def log_input_context(logs, phase):
    try:
        logs.append(f"INPUT_CONTEXT {phase}: {input_context()}")
    except Exception as exc:
        logs.append(f"INPUT_CONTEXT_ERROR {phase}: {type(exc).__name__}")


def _send_pair(vk=0, scan=0, flags=0):
    events = (INPUT * 2)()
    for i in range(2):
        events[i].type = 1
        events[i].ki.wVk = vk
        events[i].ki.wScan = scan
        events[i].ki.dwFlags = flags | (KEYEVENTF_KEYUP if i else 0)
    kernel32.SetLastError(0)
    sent = user32.SendInput(2, events, ctypes.sizeof(INPUT))
    last_error = kernel32.GetLastError()
    trace = getattr(_input_stats, "trace", None)
    if trace is not None:
        trace.append(f"KEY_INPUT: phase={getattr(_input_stats, 'phase', 'unknown')}; requested=2; accepted={sent}; win32_error={last_error}; credential_content=omitted")
    _input_stats.calls = getattr(_input_stats, "calls", 0) + 1
    _input_stats.accepted = getattr(_input_stats, "accepted", 0) + sent
    if sent != 2:
        raise RuntimeError(f"SendInput: {sent}/2 siqnal qəbul edildi; win32_error={last_error}; phase={getattr(_input_stats, 'phase', 'unknown')}. Windows giriş siqnalını qəbul etmədi (bu kod təkbaşına səbəbi müəyyən etmir).")


def send_hardware_key(vk_code):
    _send_pair(vk=vk_code, scan=user32.MapVirtualKeyW(vk_code, 0))
    time.sleep(0.045)


def type_credential_char(ch):
    # Windows Hello PIN controls may ignore VK_PACKET (Unicode) events.
    # Use the real top-row virtual keys for ASCII PIN digits, once per digit.
    if "0" <= ch <= "9":
        send_hardware_key(ord(ch))
        return
    encoded = ch.encode("utf-16-le")
    for offset in range(0, len(encoded), 2):
        _send_pair(scan=int.from_bytes(encoded[offset:offset + 2], "little"), flags=KEYEVENTF_UNICODE)




def focus_credential_field(logs):
    script = Path(__file__).with_name("focus_credential.ps1")
    powershell = str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe")
    logs.append("FOCUS_VERIFY_START: UIAutomation; timeout=15s")
    started = time.monotonic()
    completed = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)], capture_output=True, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
    logs.append(f"FOCUS_VERIFY_EXIT: code={completed.returncode}; duration_ms={round((time.monotonic() - started) * 1000)}")
    for line in completed.stdout.decode("utf-8", errors="replace").splitlines()[-120:]:
        logs.append("UIA: " + line)
    for line in completed.stderr.decode("utf-8", errors="replace").splitlines()[-20:]:
        logs.append("UIA_STDERR: " + line)
    if completed.returncode or b"FOCUSED" not in completed.stdout:
        raise RuntimeError("Fokus təsdiqlənmədi; PIN göndərilmədi")
    logs.append("FOCUS_VERIFIED")


def inject_credential_sequence(credential, logs):
    _input_stats.phase = "clear_field"
    logs.append("INPUT_CLEAR_START: Ctrl+A then Backspace")
    events = (INPUT * 4)()
    for index, (vk, flags) in enumerate(((0x11, 0), (0x41, 0), (0x41, KEYEVENTF_KEYUP), (0x11, KEYEVENTF_KEYUP))):
        events[index].type = 1
        events[index].ki.wVk = vk
        events[index].ki.dwFlags = flags
    kernel32.SetLastError(0)
    sent = user32.SendInput(4, events, ctypes.sizeof(INPUT))
    error = kernel32.GetLastError()
    logs.append(f"INPUT_CLEAR_SELECT: requested=4; accepted={sent}; win32_error={error}")
    if sent != 4:
        release = INPUT(type=1)
        release.ki.wVk = 0x11
        release.ki.dwFlags = KEYEVENTF_KEYUP
        user32.SendInput(1, ctypes.byref(release), ctypes.sizeof(INPUT))
        raise RuntimeError(f"INPUT_CLEAR_FAILED: {sent}/4; win32_error={error}")
    send_hardware_key(VK_BACK)
    logs.append("INPUT_CLEAR_END")
    typing_started = time.monotonic()
    logs.append("INPUT_CREDENTIAL_START: credential_present=True; content omitted")
    _input_stats.phase = "credential_typing"
    for char in str(credential):
        type_credential_char(char)
        time.sleep(0.06)
    logs.append(f"INPUT_TYPING_END: duration_ms={round((time.monotonic() - typing_started) * 1000)}")
    time.sleep(0.2)
    _input_stats.phase = "submit_enter"
    if is_workstation_locked():
        logs.append("SUBMIT_START: Enter requested")
        send_hardware_key(VK_RETURN)
    else:
        logs.append("SUBMIT_SKIPPED: Windows auto-submitted credential")
    logs.append("Parol göndərildi; Windows nəticəsi gözlənilir.")


def unlock_direct_in_session(credential, logs=None):
    """
    REM-018 & Reviziya 7: Sessiya daxilində tam in-memory unlock icrası.
    Heç bir mühit dəyişəni (env), komanda sətri (argv), loq və ya disk faylı istifadə edilmir.
    """
    if logs is None:
        logs = Trace()
    initial_locked = is_workstation_locked()
    logs.append(f"DIRECT_UNLOCK_START: locked={initial_locked}")
    if not initial_locked:
        return {"success": True, "status": "ALREADY_UNLOCKED", "logs": logs.snapshot()}
    if not credential:
        raise ValueError("E_EMPTY_CREDENTIAL: PIN və ya parol boşdur")

    original = user32.GetThreadDesktop(kernel32.GetCurrentThreadId())
    attached = None
    try:
        wake_screen()
        current_desk = get_desktop_name(user32.GetThreadDesktop(kernel32.GetCurrentThreadId()))
        logs.append(f"CURRENT_DESKTOP: {current_desk}")
        if current_desk.lower() != "winlogon":
            ok, msg = attach_to_winlogon_desktop()
            logs.append(f"ATTACH_RESULT: ok={ok}; msg={msg}")
            attached = user32.GetThreadDesktop(kernel32.GetCurrentThreadId())

        try:
            focus_credential_field(logs)
        except Exception as f_err:
            logs.append(f"FOCUS_NOTE: {f_err}")

        inject_credential_sequence(credential, logs)

        for _ in range(15):
            time.sleep(0.2)
            if not is_workstation_locked():
                return {"success": True, "status": "SUCCESS_UNLOCKED", "logs": logs.snapshot()}
        return {"success": False, "status": "STILL_LOCKED", "logs": logs.snapshot()}
    finally:
        if original:
            user32.SetThreadDesktop(original)
        advapi32.RevertToSelf()
        if attached and attached != original:
            user32.CloseDesktop(attached)

def _unlock_once(credential, logs):
    initial_locked = is_workstation_locked()
    logs.append("LOCK_EVIDENCE: " + str(get_lock_state()))
    logs.append(f"INITIAL_STATUS: locked={initial_locked}; credential_present={bool(credential)}; system_worker={os.environ.get('WINKEY_SECURE_WORKER') == '1'}")
    if not initial_locked:
        return "ALREADY_UNLOCKED"
    if not credential:
        raise RuntimeError("Əvvəlcə Windows PIN və ya parolunu saxlayın.")
    if os.environ.get("WINKEY_SECURE_WORKER") != "1":
        try:
            from .secure_input_worker import launch
        except ImportError:
            from secure_input_worker import launch
        return launch(credential, logs)
    original = user32.GetThreadDesktop(kernel32.GetCurrentThreadId())
    attached = None
    try:
        logs.append("WAKE_START")
        awake = wake_screen()
        logs.append(f"WAKE_END: success={awake}")
        log_input_context(logs, "before_attach")
        logs.append("DESKTOP_ATTACH_START")
        ok, message = attach_to_winlogon_desktop()
        logs.append(message)
        if not ok:
            raise RuntimeError("Kilid ekranına giriş alınmadı: " + message)
        log_input_context(logs, "after_attach")
        attached = user32.GetThreadDesktop(kernel32.GetCurrentThreadId())
        if get_desktop_name(attached).lower() != "winlogon":
            raise RuntimeError("Winlogon desktopu təsdiqlənmədi; parol göndərilmədi.")

        logs.append("CREDENTIAL_STAGE: Winlogon active; verify PIN field before typing")
        focus_credential_field(logs)
        # 4. Parolu daxil edirik və Enter vururuq
        inject_credential_sequence(credential, logs)

        for _ in range(20):
            time.sleep(0.25)
            locked_now = is_workstation_locked()
            logs.append(f"VERIFY: poll={_ + 1}; locked={locked_now}; evidence={get_lock_state()}")
            if not locked_now:
                return "SUCCESS"
        logs.append("Kilid açılmadı. Windows giriş üsulu saxlanan PIN/parola uyğun olmalıdır. Ctrl+Alt+Del tələb olunursa RustDesk vasitəsilə göndərin.")
        return "STILL_LOCKED"
    finally:
        logs.append("CLEANUP_START")
        restored = user32.SetThreadDesktop(original)
        reverted = advapi32.RevertToSelf()
        logs.append(f"CLEANUP_END: desktop_restored={bool(restored)}; token_reverted={bool(reverted)}")
        if attached and attached != original and restored:
            user32.CloseDesktop(attached)


def unlock_workstation(pin_or_password=None, request_info=None):
    if not _unlock_lock.acquire(blocking=False):
        return {"success": False, "locked": True, "status": "BUSY", "logs": ["Əməliyyat artıq davam edir."]}
    result = {}
    logs = Trace()
    logs.append(f"BEGIN: build={VERSION}; engine_sha={LOADED_ENGINE_SHA}; input_struct_bytes={ctypes.sizeof(INPUT)}; admin={bool(ctypes.windll.shell32.IsUserAnAdmin())}")
    if request_info:
        logs.append("HTTP_UNLOCK_RECEIVED: " + str(request_info))
    def worker():
        try:
            _input_stats.trace = logs
            _input_stats.phase = "startup"
            _input_stats.calls = 0
            _input_stats.accepted = 0
            status = _unlock_once(pin_or_password, logs)
            success = status in ("SUCCESS", "ALREADY_UNLOCKED")
            logs.append("Nəticə: " + status)
            result.update(success=success, locked=not success, status=status)
        except Exception as exc:
            import traceback
            detail = str(exc)
            if pin_or_password:
                detail = detail.replace(str(pin_or_password), "<credential redacted>")
            frames = " > ".join(f"{Path(f.filename).name}:{f.lineno}:{f.name}" for f in traceback.extract_tb(exc.__traceback__))
            logs.append(f"ERROR: type={type(exc).__name__}; winerror={getattr(exc, 'winerror', None)}; detail={detail}; frames={frames}")
            result.update(success=False, locked=True, status="ERROR")
        finally:
            result["logs"] = logs
    try:
        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()
        result["attempt_id"] = logs.attempt_id
        result["build"] = VERSION
        result["logs"] = logs.snapshot()
        return result
    finally:
        _unlock_lock.release()
