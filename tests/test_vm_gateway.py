"""Actual HTTP contract for the VM adapter; never invokes Windows input."""
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from http.server import HTTPServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from deploy.vm.configure import configure
from deploy.vm.server import VMHandler, VMDatabase


class VMContract(unittest.TestCase):
    def test_http_registration_pair_command_result_and_admin(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as folder:
            root = Path(folder)
            configure("winkey.example.com", root)
            key = (root / "deploy/vm/secrets/admin_key").read_text().strip()
            configure("winkey.example.com", root)
            self.assertEqual(key, (root / "deploy/vm/secrets/admin_key").read_text().strip())
            previous = os.environ.get("WINKEY_ADMIN_SECRET")
            os.environ["WINKEY_ADMIN_SECRET"] = key
            VMHandler.db = VMDatabase(str(root / "test.db"))
            server = HTTPServer(("127.0.0.1", 0), VMHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            origin = f"http://127.0.0.1:{server.server_port}"

            def http(path, body=None, token=None, admin=False):
                headers = {"Content-Type": "application/json"}
                if token:
                    headers["Authorization"] = "Bearer " + token
                if admin:
                    headers["X-Owner-Admin-Secret"] = key
                req = Request(origin + path, data=json.dumps(body).encode() if body is not None else None, headers=headers)
                try:
                    response = urlopen(req, timeout=5)
                except HTTPError as error:
                    response = error
                with response:
                    raw = response.read()
                    return response.status, json.loads(raw) if raw.startswith(b"{") else raw

            try:
                self.assertEqual(http("/healthz")[0], 200)
                self.assertEqual(http("/admin/devices")[0], 403)
                self.assertIn(b"<html", http("/mobile")[1].lower())
                device = "pc_vm_test"
                private = Ed25519PrivateKey.generate()
                public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
                _, challenge = http("/agent/challenge", {"device_id": device})
                nonce = challenge["nonce"]
                status, registration = http("/agent/register", {
                    "device_id": device, "computer_name": "VM contract",
                    "public_key_hex": public, "nonce": nonce,
                    "proof_signature_hex": private.sign(f"WINKEY_REGISTER:{nonce}:{device}".encode()).hex(),
                })
                self.assertEqual(status, 200)
                agent = registration["device_secret"]
                status, pairing = http("/devices/pair-request", {"device_id": device}, agent)
                self.assertEqual(status, 200)
                status, session = http("/pair", {"pair_code": pairing["pair_code"]})
                self.assertEqual(status, 200)
                mobile = session["session_token"]
                self.assertNotEqual(http("/pair", {"pair_code": pairing["pair_code"]})[0], 200)
                status, command = http("/commands", {"device_id": device, "action": "mock"}, mobile)
                self.assertEqual(status, 200)
                status, poll = http("/agent/poll", {"device_id": device}, agent)
                self.assertEqual(status, 200)
                self.assertEqual(poll["command"]["id"], command["command_id"])
                self.assertEqual(http("/agent/result", {"device_id": device, "command_id": command["command_id"], "success": True, "status": "MOCK_ONLY"}, agent)[0], 200)
                self.assertEqual(http("/commands/" + command["command_id"], token=mobile)[1]["status"], "completed")
                self.assertEqual(len(http("/admin/devices", admin=True)[1]["devices"]), 1)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(5)
                if previous is None:
                    os.environ.pop("WINKEY_ADMIN_SECRET", None)
                else:
                    os.environ["WINKEY_ADMIN_SECRET"] = previous
                os.chmod(root / "deploy/vm/secrets/admin_key", 0o600)


if __name__ == "__main__":
    unittest.main()
