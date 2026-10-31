"""Model fault injection only: no real Win32 calls or service changes."""
import ctypes
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pc_agent.service_supervisor import ServiceSupervisor
from pc_agent.update_rollback_engine import UpdateRollbackEngine


class FakeFunction:
    def __init__(self, result):
        self.result = result
    def __call__(self, *args):
        return self.result


def main():
    fake = SimpleNamespace(**{name: FakeFunction(result) for name, result in {
        'CreateFileW': 123, 'CloseHandle': 1, 'GetNamedPipeServerProcessId': 0,
        'WriteFile': 0, 'ReadFile': 0,
    }.items()})
    original = getattr(ctypes, 'windll', None)
    ctypes.windll = SimpleNamespace(kernel32=fake)
    try:
        supervisor = object.__new__(ServiceSupervisor)
        bad_health = supervisor.check_pipe_health(expected_pid=999, timeout_sec=0.1)
    finally:
        if original is not None:
            ctypes.windll = original
        else:
            del ctypes.windll

    root = Path(__file__).resolve().parents[1] / 'plan/reports/codex'
    with tempfile.TemporaryDirectory(dir=root, prefix='recovery_audit_') as folder:
        engine = UpdateRollbackEngine(folder, '00' * 32)
        (Path(engine.slot_a_dir) / 'winkey_service.exe').write_bytes(b'NOT_A_VALID_EXECUTABLE')
        bad_slot = engine._is_slot_valid('slot_a')
    print(f"{'REPRODUCED' if bad_health else 'NOT_REPRODUCED'}: FAILED_PID_AND_WRITE_ACCEPTED_AS_HEALTHY")
    print(f"{'REPRODUCED' if bad_slot else 'NOT_REPRODUCED'}: UNSIGNED_INVALID_SLOT_ACCEPTED")
    return int(bad_health or bad_slot)


if __name__ == '__main__':
    raise SystemExit(main())
