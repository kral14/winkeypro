"""Credential-free, flushed diagnostics shared by gateway and SYSTEM worker."""
import datetime
import json
import os
from pathlib import Path
import re
import threading
import time
import uuid

ROOT = Path(os.environ.get("WINKEY_DATA_DIR", Path(__file__).resolve().parent))
VERSION = "diag-20261027-6"

class Trace(list):
    def __init__(self):
        super().__init__()
        inherited = os.environ.get("WINKEY_ATTEMPT_ID", "")
        self.attempt_id = inherited if re.fullmatch(r"[a-f0-9]{12}", inherited) else uuid.uuid4().hex[:12]
        self.path = ROOT / "diagnostic_logs" / (self.attempt_id + ".log")
        self.started = time.monotonic()
        self.write_error = None
        try:
            self.path.parent.mkdir(exist_ok=True)
        except OSError as exc:
            self.write_error = type(exc).__name__

    def append(self, message):
        record = {"time": datetime.datetime.now().astimezone().isoformat(timespec="milliseconds"),
                  "attempt": self.attempt_id, "pid": os.getpid(), "thread": threading.get_native_id(),
                  "elapsed_ms": round((time.monotonic() - self.started) * 1000), "message": str(message)}
        line = json.dumps(record, ensure_ascii=False)
        super().append(line)
        # Each line is persisted immediately, including before a blocked API or timeout.
        for destination in (self.path, ROOT / "unlock_debug.log"):
            try:
                with destination.open("a", encoding="utf-8") as stream:
                    stream.write(line + "\n")
            except OSError as exc:
                self.write_error = type(exc).__name__

    def snapshot(self):
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()[-500:]
        except OSError:
            lines = list(self)
        if self.write_error:
            lines.append("LOG_WRITE_ERROR: " + self.write_error)
        return lines
