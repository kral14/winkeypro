"""
WinKey Pro — Dedicated Real IPC Input Worker (Revision 9)
Dedicated in-memory hardware scan-code injector for standalone winkey_helper.exe.
Strict WTS target-session locked state + desktop/focus verification,
checked SendInput counts, conditional Enter, and WTS verified unlock confirmation.
Includes injectable Win32Adapter for MODEL_UNIT test coverage.
Zero environment variable, zero argv, zero log, and zero disk credential exposure.
"""
import sys
import os
import time
import ctypes
from ctypes import wintypes
from pathlib import Path

# Setup 64-bit safe Win32 API signatures
HANDLE = ctypes.c_void_p
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32

kernel32.GetCurrentProcess.restype = HANDLE
kernel32.GetCurrentThreadId.restype = wintypes.DWORD
kernel32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
kernel32.ProcessIdToSessionId.restype = wintypes.BOOL

user32.GetThreadDesktop.argtypes = [wintypes.DWORD]
user32.GetThreadDesktop.restype = HANDLE
user32.OpenInputDesktop.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
user32.OpenInputDesktop.restype = HANDLE
user32.SetThreadDesktop.argtypes = [HANDLE]
user32.SetThreadDesktop.restype = wintypes.BOOL
user32.CloseDesktop.argtypes = [HANDLE]
user32.CloseDesktop.restype = wintypes.BOOL
user32.GetUserObjectInformationA.argtypes = [HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]

user32.mouse_event.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_ulonglong]
user32.mouse_event.restype = None
user32.SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]
user32.SetCursorPos.restype = wintypes.BOOL
user32.GetSystemMetrics.argtypes = [ctypes.c_int]
user32.GetSystemMetrics.restype = ctypes.c_int

HWND_BROADCAST = 0xFFFF
WM_SYSCOMMAND = 0x0112
SC_MONITORPOWER = 0xF170
MONITOR_ON = -1

KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004
VK_RETURN = 0x0D
VK_SPACE = 0x20
VK_ESCAPE = 0x1B
VK_BACK = 0x08

# Use the exact ABI types/prototype of the working backup engine. ctypes DLL
# functions are cached across modules: separate lookalike INPUT classes fail
# conversion against unlock_engine's POINTER(INPUT) before SendInput is called.
try:
    from . import unlock_engine as _engine
except ImportError:
    import unlock_engine as _engine
MOUSEINPUT = _engine.MOUSEINPUT
KEYBDINPUT = _engine.KEYBDINPUT
HARDWAREINPUT = _engine.HARDWAREINPUT
INPUT = _engine.INPUT


# =============================================================================
# INJECTABLE WIN32 ADAPTER INTERFACE (For Production & MODEL_UNIT Testing)
# =============================================================================

class Win32Adapter:
    """Production Win32 API Adapter wrapping real OS calls."""
    
    def get_desktop_name(self, hdesk=None) -> str:
        if hdesk is None:
            hdesk = user32.GetThreadDesktop(kernel32.GetCurrentThreadId())
        if not hdesk:
            return "NULL"
        name_buf = ctypes.create_string_buffer(256)
        size = wintypes.DWORD()
        if user32.GetUserObjectInformationA(hdesk, 2, name_buf, 256, ctypes.byref(size)):
            return name_buf.value.decode("utf-8", errors="replace")
        return "UNKNOWN"

    def attach_to_winlogon_desktop(self) -> tuple[bool, str]:
        import unlock_engine
        return unlock_engine.attach_to_winlogon_desktop()

    def is_workstation_locked(self) -> bool:
        import unlock_engine
        return unlock_engine.is_workstation_locked()

    def get_lock_state(self) -> dict:
        import unlock_engine
        return unlock_engine.get_lock_state()

    def focus_credential_field(self, logs: list) -> bool:
        import unlock_engine
        try:
            unlock_engine.focus_credential_field(logs)
            logs.append("FOCUS_VERIFIED: Production credential field confirmed focused")
            return True
        except Exception as exc:
            logs.append(f"FOCUS_FAILED: {exc}")
            # REM-026: Heç bir exception True kimi udulmur. Fokus yoxdursa dərhal fail-closed (False)!
            return False

    def send_input(self, n_inputs: int, p_inputs, cb_size: int) -> int:
        kernel32.SetLastError(0)
        sent = user32.SendInput(n_inputs, p_inputs, cb_size)
        return sent

    def wake_screen(self):
        user32.SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, MONITOR_ON)
        user32.mouse_event(0x0001, 1, 0, 0, 0)
        user32.mouse_event(0x0001, 0xFFFFFFFF, 0, 0, 0)

    def sleep(self, seconds: float):
        time.sleep(seconds)


class MockWin32Adapter:
    """
    Mock adapter for MODEL_UNIT negative security and edge-case testing.
    Allows simulating:
      - Wrong PIN / state unchanged (locked remains True)
      - Partial SendInput failure (sent != count)
      - Desktop focus failure
      - Windows Hello auto-submit (locked becomes False before Enter)
      - Curtain deadline timeout (desktop never becomes Winlogon)
    """
    def __init__(
        self,
        initial_locked: bool = True,
        post_input_locked: bool = True,
        auto_submitted: bool = False,
        desktop_name: str = "Winlogon",
        focus_succeeds: bool = True,
        send_input_override: int = None,
        curtain_transition_desktop: str = "Winlogon",
    ):
        self.initial_locked = initial_locked
        self.post_input_locked = post_input_locked
        self.auto_submitted = auto_submitted
        self.desktop_name = desktop_name
        self.focus_succeeds = focus_succeeds
        self.send_input_override = send_input_override
        self.curtain_transition_desktop = curtain_transition_desktop
        self._input_calls = 0
        self._chars_typed = 0
        self._enter_sent = False
        self._poll_count = 0

    def get_desktop_name(self, hdesk=None) -> str:
        if self._input_calls > 0 and self.curtain_transition_desktop is not None:
            return self.curtain_transition_desktop
        return self.desktop_name

    def attach_to_winlogon_desktop(self) -> tuple[bool, str]:
        if self.desktop_name.lower() == "uac":
            return False, "Cannot attach to Winlogon from UAC"
        self.desktop_name = "Winlogon"
        return True, "Mock attached to Winlogon"

    def is_workstation_locked(self) -> bool:
        if self._input_calls == 0:
            return self.initial_locked
        if self.auto_submitted and self._input_calls >= 3:
            return False
        return self.post_input_locked

    def get_lock_state(self) -> dict:
        return {
            "locked": self.is_workstation_locked(),
            "desktop": self.get_desktop_name(),
            "wts": {"confirmed": True, "locked": self.is_workstation_locked(), "session": 1}
        }

    def focus_credential_field(self, logs: list) -> bool:
        if not self.focus_succeeds:
            logs.append("FOCUS_FAILED: Field could not be focused")
            return False
        logs.append("FOCUS_VERIFIED: Mock focus established")
        return True

    def send_input(self, n_inputs: int, p_inputs, cb_size: int) -> int:
        self._input_calls += 1
        if self.send_input_override is not None:
            return self.send_input_override
        return n_inputs

    def wake_screen(self):
        pass

    def sleep(self, seconds: float):
        pass


# =============================================================================
# HARDWARE SCAN-CODE GENERATION HELPERS
# =============================================================================

def _build_key_events(vk: int) -> tuple:
    events = (INPUT * 2)()
    events[0].type = 1
    events[0].ki.wVk = vk
    events[0].ki.dwFlags = 0
    events[1].type = 1
    events[1].ki.wVk = vk
    events[1].ki.dwFlags = KEYEVENTF_KEYUP
    return events


def _build_char_events(ch: str) -> tuple:
    if "0" <= ch <= "9":
        return _build_key_events(ord(ch))
    encoded = ch.encode("utf-16-le")
    code_point = int.from_bytes(encoded[:2], "little")
    events = (INPUT * 2)()
    events[0].type = 1
    events[0].ki.wScan = code_point
    events[0].ki.dwFlags = KEYEVENTF_UNICODE
    events[1].type = 1
    events[1].ki.wScan = code_point
    events[1].ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP
    return events


# =============================================================================
# CURTAIN DISMISSAL FUNCTION
# =============================================================================

def dismiss_curtain_direct(adapter=None, logs: list = None) -> dict:
    """
    REM-023: Dismisses visible lock curtain on Default desktop without credentials.
    Strictly verifies:
      1. Session is locked.
      2. If already on Winlogon -> returns immediately.
      3. Active desktop must be Default (clicks are never sent to UAC or unknown desktops).
      4. Verifies SendInput sent count == 2.
      5. Bounded deadline (3.0s) polling: confirms transition to Winlogon.
    """
    if adapter is None:
        adapter = Win32Adapter()
    if logs is None:
        logs = []

    logs.append("CURTAIN_START: Verifying lock and desktop state")
    adapter.wake_screen()
    
    state = adapter.get_lock_state()
    current_desktop = state.get("desktop", "").lower()
    
    if current_desktop == "winlogon":
        logs.append("CURTAIN_READY: Active desktop is already Winlogon")
        return {"success": True, "status": "CURTAIN_READY", "logs": logs}

    wts = state.get("wts", {})
    if not wts.get("confirmed") or not wts.get("locked"):
        raise RuntimeError("CURTAIN_ABORT: Session lock not confirmed; refusing to click")

    if current_desktop != "default":
        raise RuntimeError(f"CURTAIN_ABORT: Active desktop is '{current_desktop}'; expected 'Default' (Refusing to click UAC/Other)")

    # Simulate mouse click on Default curtain
    width = user32.GetSystemMetrics(0) if hasattr(user32, "GetSystemMetrics") else 1920
    height = user32.GetSystemMetrics(1) if hasattr(user32, "GetSystemMetrics") else 1080
    if width <= 0 or height <= 0:
        width, height = 1920, 1080

    x, y = width // 2, height // 3
    user32.SetCursorPos(x, y)

    events = (INPUT * 2)()
    events[0].type = 0
    events[0].mi.dwFlags = 0x0002 # MOUSEEVENTF_LEFTDOWN
    events[1].type = 0
    events[1].mi.dwFlags = 0x0004 # MOUSEEVENTF_LEFTUP

    sent = adapter.send_input(2, events, ctypes.sizeof(INPUT))
    logs.append(f"CURTAIN_CLICK: sent={sent}/2")
    if sent != 2:
        raise RuntimeError(f"CURTAIN_CLICK_FAILED: SendInput accepted {sent}/2 events")

    # Bounded transition wait (15 polls of 0.2s = 3.0s deadline)
    logs.append("CURTAIN_WAIT: Polling for transition to Winlogon desktop...")
    for poll in range(15):
        adapter.sleep(0.2)
        after_state = adapter.get_lock_state()
        after_desk = after_state.get("desktop", "").lower()
        if after_desk == "winlogon":
            logs.append(f"CURTAIN_READY: Default -> Winlogon transition confirmed at poll {poll + 1}")
            return {"success": True, "status": "CURTAIN_READY", "logs": logs}

    raise RuntimeError("CURTAIN_NOT_DISMISSED: Input desktop did not switch to Winlogon within 3.0s deadline")


# =============================================================================
# CREDENTIAL INJECTION & VERIFIED UNLOCK FUNCTION
# =============================================================================

def inject_credentials_in_memory(credential: str, adapter=None, logs: list = None) -> dict:
    """
    REM-023: Direct in-memory credential injection onto Winlogon desktop.
    Strictly enforces:
      1. Target session locked check: if already unlocked -> ALREADY_UNLOCKED.
      2. Rejection of empty credentials.
      3. Winlogon desktop verification (attaches and rejects UAC / Default).
      4. Credential field focus verification (aborts if focus fails).
      5. SendInput return count check for every event (clear, each char, Enter).
      6. Conditional Enter: ONLY sent if still locked after typing and not auto-submitted.
      7. WTS Verified Unlocked confirmation: polls up to 3.0s; NEVER returns True/success
         unless WTS explicitly confirms workstation is UNLOCKED.
    """
    if adapter is None:
        adapter = Win32Adapter()
    if logs is None:
        logs = []

    if not credential:
        raise ValueError("E_EMPTY_CREDENTIAL: PIN və ya parol boş ola bilməz")

    # 1. Target Session Locked Verification
    if not adapter.is_workstation_locked():
        logs.append("DIRECT_UNLOCK_CHECK: Workstation is already unlocked")
        return {"success": True, "status": "ALREADY_UNLOCKED", "logs": logs}

    adapter.wake_screen()

    # 2. Desktop Verification & Attachment
    current_desktop = adapter.get_desktop_name().lower()
    logs.append(f"DESKTOP_VERIFY: Current desktop is '{current_desktop}'")
    if current_desktop != "winlogon":
        ok, msg = adapter.attach_to_winlogon_desktop()
        logs.append(f"ATTACH_WINLOGON: ok={ok}; msg={msg}")
        current_desktop = adapter.get_desktop_name().lower()
        if current_desktop != "winlogon":
            raise RuntimeError(f"E_DESKTOP_NOT_WINLOGON: Cannot inject on desktop '{current_desktop}' (UAC/Session protection)")

    # 3. Focus Verification
    logs.append("FOCUS_VERIFY: Focusing credential input field...")
    focus_ok = adapter.focus_credential_field(logs)
    if not focus_ok:
        raise RuntimeError("E_FOCUS_FAILED: Credential field could not be focused; aborting to prevent input leakage")

    # 4. Clear Field (Ctrl+A then Backspace) with Checked SendInput
    logs.append("INPUT_CLEAR: Sending Ctrl+A then Backspace")
    clear_events = (INPUT * 4)()
    for idx, (vk, flags) in enumerate(((0x11, 0), (0x41, 0), (0x41, KEYEVENTF_KEYUP), (0x11, KEYEVENTF_KEYUP))):
        clear_events[idx].type = 1
        clear_events[idx].ki.wVk = vk
        clear_events[idx].ki.dwFlags = flags
    
    sent_clear = adapter.send_input(4, clear_events, ctypes.sizeof(INPUT))
    if sent_clear != 4:
        raise RuntimeError(f"E_PARTIAL_INPUT: Clear field SendInput returned {sent_clear}/4")
    
    bs_events = _build_key_events(VK_BACK)
    sent_bs = adapter.send_input(2, bs_events, ctypes.sizeof(INPUT))
    if sent_bs != 2:
        raise RuntimeError(f"E_PARTIAL_INPUT: Backspace SendInput returned {sent_bs}/2")
    adapter.sleep(0.05)

    # 5. Type Credential Characters with Checked SendInput for Every Character
    logs.append("INPUT_TYPING: Injecting credential characters via hardware scan-codes...")
    for idx, char in enumerate(credential):
        char_events = _build_char_events(char)
        sent_char = adapter.send_input(2, char_events, ctypes.sizeof(INPUT))
        if sent_char != 2:
            raise RuntimeError(f"E_PARTIAL_INPUT: Typing char [{idx}] returned {sent_char}/2; partial input aborted")
        adapter.sleep(0.04)

    adapter.sleep(0.15)

    # 6. Conditional Enter Submission
    # Enter is ONLY sent if the workstation is still locked and Windows didn't auto-submit!
    if adapter.is_workstation_locked():
        logs.append("SUBMIT_ENTER: Workstation still locked; sending Enter key")
        enter_events = _build_key_events(VK_RETURN)
        sent_enter = adapter.send_input(2, enter_events, ctypes.sizeof(INPUT))
        if sent_enter != 2:
            raise RuntimeError(f"E_PARTIAL_INPUT: Enter SendInput returned {sent_enter}/2")
    else:
        logs.append("SUBMIT_SKIPPED: Windows auto-submitted credential (Auto PIN / Windows Hello)")

    # 7. WTS Verified Unlocked Confirmation
    # Polls up to 15 times (0.2s intervals = 3.0s deadline).
    # NEVER claims SUCCESS_UNLOCKED unless WTS explicitly confirms workstation is unlocked!
    logs.append("WTS_VERIFY: Polling session state for unlock confirmation...")
    for poll in range(15):
        adapter.sleep(0.2)
        if not adapter.is_workstation_locked():
            logs.append(f"WTS_CONFIRMED: Workstation verified unlocked at poll {poll + 1}!")
            return {"success": True, "status": "SUCCESS_UNLOCKED", "logs": logs}

    # If still locked after deadline -> FAIL-CLOSED!
    logs.append("WTS_STILL_LOCKED: Workstation remains locked after 3.0s deadline (Wrong PIN or rejected)")
    return {"success": False, "status": "STILL_LOCKED", "logs": logs}
