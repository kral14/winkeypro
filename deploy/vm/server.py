"""Container entrypoint; delegates native/mobile contracts to the existing gateway."""
import os
import sqlite3
from pathlib import Path
from http.server import HTTPServer
from urllib.parse import urlsplit
from deploy.gateway_production_server import GatewayHandler, ProductionDatabase


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


class VMDatabase(ProductionDatabase):
    def get_conn(self):
        connection = sqlite3.connect(self.db_path, timeout=10, factory=ClosingConnection)
        connection.row_factory = sqlite3.Row
        return connection


class VMHandler(GatewayHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def do_GET(self):
        if urlsplit(self.path).path == "/healthz":
            try:
                with self.db.get_conn() as connection:
                    connection.execute("SELECT 1").fetchone()
                self._send_json(200, {"status": "ONLINE"})
            except Exception:
                self._send_json(503, {"error": "E_DATABASE_UNAVAILABLE"})
            return
        super().do_GET()

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if self.headers.get("Transfer-Encoding") or not 0 <= length <= 65536:
            self.close_connection = True
            self._send_json(413, {"error": "E_REQUEST_TOO_LARGE_OR_INVALID"})
            return
        super().do_POST()


def main():
    key = os.environ.get("WINKEY_ADMIN_SECRET", "").strip()
    if not key:
        secret_file = Path("/run/secrets/admin_key")
        key = secret_file.read_text(encoding="ascii").strip() if secret_file.is_file() else ""
    if len(key) < 32:
        raise RuntimeError("WINKEY_ADMIN_SECRET minimum 32 simvol olmalıdır; ya da Docker secret/configure.py istifadə edin.")
    os.environ["WINKEY_ADMIN_SECRET"] = key
    port = int(os.environ.get("PORT", "8788"))
    if not 1 <= port <= 65535:
        raise RuntimeError("PORT 1..65535 aralığında olmalıdır.")
    VMHandler.db = VMDatabase(os.environ.get("WINKEY_DB_PATH", "/data/winkey.db"))
    server = HTTPServer((os.environ.get("GATEWAY_HOST", "0.0.0.0"), port), VMHandler)
    print(f"[VM] Gateway hazırdır: port={port}; PIN və giriş açarları loga yazılmır.", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
