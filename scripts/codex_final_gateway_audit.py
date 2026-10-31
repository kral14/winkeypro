"""Isolated handler/database audit: no sockets, services or desktop input."""
import io
import json
import sys
import tempfile
import gc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from deploy.gateway_production_server import GatewayHandler, ProductionDatabase


def main():
    audit_root = Path(__file__).resolve().parents[1] / "plan/reports/codex"
    audit_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gateway_audit_", dir=audit_root) as folder:
        database = ProductionDatabase(str(Path(folder) / "audit.db"))

        def post(path, payload):
            handler = object.__new__(GatewayHandler)
            body = json.dumps(payload).encode()
            handler.path = path
            handler.headers = {"Content-Length": str(len(body))}
            handler.rfile = io.BytesIO(body)
            handler.db = database
            result = []
            handler._send_json = lambda status, data: result.append((status, data))
            handler.do_POST()
            return result[0]

        findings = []
        status, _ = post("/agent/register", {"device_id": "audit-device", "public_key_hex": "invalid"})
        findings.append(("UNAUTHENTICATED_INVALID_KEY_REGISTRATION", status == 200))
        status, response = post("/pair", {"device_id": "audit-device", "pair_code": "never-issued"})
        findings.append(("UNISSUED_CODE_GRANTS_MOBILE_SESSION", status == 200 and bool(response.get("session_token"))))
        status, _ = post("/agent/poll", {"device_id": "audit-device", "locked": True})
        with database.get_conn() as conn:
            row = conn.execute("SELECT locked FROM devices WHERE device_id='audit-device'").fetchone()
            changed = row[0] if row else None
        findings.append(("UNAUTHENTICATED_AGENT_STATE_CHANGE", status == 200 and changed == 1))
        for label, reproduced in findings:
            print(f"{'REPRODUCED' if reproduced else 'NOT_REPRODUCED'}: {label}")
        del row
        del conn
        gc.collect()
        return 1 if any(found for _, found in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
