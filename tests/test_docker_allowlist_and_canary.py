"""
WinKey Pro — Docker Allowlist and Canary Secret Exclusion Test
Spesifikasiya: plan/GEMINI_WEBSOCKET_REVISION_2.md (R2-06)

Bu test Codex-in Docker allowlist və .dockerignore qaydalarını avtomatik yoxlayır:
1. Host mühitində FAKE canary sirləri və faylları yaradılır (deploy/vm/secrets/canary_secret.txt, .env.canary, canary.db).
2. Docker image yığılır (winkey-vm:canary-allowlist-test).
3. Image daxilində canary fayllarının VƏ host sirlərinin (secrets, keys, .env, *.db) OLMAMASI təsdiq edilir.
4. Runtime import və health yoxlanışı icra olunur.
5. Konteyner daxilində qeyri-root (uid=10001) istifadəçi və autentifikasiyalı WebSocket sınaqdan keçirilir.
6. Real istehsal açarlarına heç vaxt toxunulmur və loglanmır.
"""

import os
from pathlib import Path
import secrets
import subprocess
import time
import unittest
import urllib.request
import json
import websockets
import asyncio

ROOT_DIR = Path(__file__).resolve().parents[1]


def run_docker(*args, check=True):
    return subprocess.run(["docker", *args], capture_output=True, text=True, encoding='utf-8', errors='replace', check=check, timeout=120)


class DockerAllowlistAndCanaryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # 1. Host mühitində FAKE canary faylları yaradırıq
        cls.canary_secret_file = ROOT_DIR / "deploy/vm/secrets/canary_test_secret.txt"
        cls.canary_secret_file.parent.mkdir(parents=True, exist_ok=True)
        cls.canary_secret_file.write_text("FAKE_CANARY_SECRET_LEAK_DETECTION_VAL", encoding="utf-8")

        cls.canary_env_file = ROOT_DIR / ".env.canary"
        cls.canary_env_file.write_text("FAKE_CANARY_ENV_VAL=1", encoding="utf-8")

        cls.canary_db_file = ROOT_DIR / "canary_test.db"
        cls.canary_db_file.write_text("FAKE_CANARY_DB_CONTENT", encoding="utf-8")

        cls.image_tag = "winkey-vm:canary-allowlist-test"

        # 2. Docker image yığırıq
        build_res = subprocess.run(
            ["docker", "build", "-t", cls.image_tag, "."],
            cwd=str(ROOT_DIR),
            capture_output=True,
            text=True,
            timeout=180
        )
        if build_res.returncode != 0:
            print("Docker build stdout:", build_res.stdout)
            print("Docker build stderr:", build_res.stderr)
            raise RuntimeError(f"Docker build failed with code {build_res.returncode}")

    @classmethod
    def tearDownClass(cls):
        # Canary fayllarını təmizləyirik
        for f in [cls.canary_secret_file, cls.canary_env_file, cls.canary_db_file]:
            if f.exists():
                try:
                    f.unlink()
                except Exception:
                    pass

    def test_01_canary_secrets_excluded_from_image(self):
        """Image daxilində heç bir canary sirr və ya qeyri-qanuni fayl olmamalıdır."""
        find_res = run_docker("run", "--rm", self.image_tag, "find", "/app", "-iname", "*canary*")
        self.assertEqual(find_res.stdout.strip(), "", "Canary faylı Docker image-nə sızıb!")

        # Yoxlayırıq ki, /app/deploy/vm/secrets və ya /app/keys mövcud deyil
        chk_res = run_docker("run", "--rm", self.image_tag, "python", "-c", """
import os
forbidden = ['/app/deploy/vm/secrets', '/app/secrets', '/app/keys', '/app/.env', '/app/canary_test.db']
leaked = [p for p in forbidden if os.path.exists(p)]
if leaked:
    print('LEAKED:', leaked)
    exit(1)
print('CLEAN')
""")
        self.assertEqual(chk_res.stdout.strip(), "CLEAN")

    def test_02_runtime_imports_healthy(self):
        """Bütün tələb olunan python modulları xətasız import olunmalıdır."""
        import_res = run_docker("run", "--rm", self.image_tag, "python", "-c", """
import deploy.gateway_production_server
import deploy.gateway_service
import deploy.asgi_app
import deploy.websocket_hub
import deploy.postgres_database
import server
print('RUNTIME_IMPORTS_OK')
""")
        self.assertEqual(import_res.stdout.strip(), "RUNTIME_IMPORTS_OK")

    def test_03_nonroot_and_authenticated_ws_in_container(self):
        """Konteyner non-root (uid=10001) kimi işləməli, healthz və autentifikasiyalı WS qəbul etməlidir."""
        container_name = f"winkey-canary-test-{secrets.token_hex(4)}"
        admin_secret = secrets.token_hex(32)
        port = "5498"

        try:
            # Konteyneri başladırıq
            run_docker(
                "run", "-d", "--rm",
                "--name", container_name,
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "--tmpfs", "/data:uid=10001,gid=10001,mode=0700",
                "--tmpfs", "/tmp:mode=1777",
                "-e", f"WINKEY_ADMIN_SECRET={admin_secret}",
                "-p", f"127.0.0.1:{port}:8788",
                self.image_tag
            )

            # Healthz probe
            url = f"http://127.0.0.1:{port}/healthz"
            online = False
            for _ in range(30):
                try:
                    with urllib.request.urlopen(url, timeout=1) as resp:
                        if resp.status == 200:
                            data = json.loads(resp.read())
                            if data.get("status") == "ONLINE":
                                online = True
                                break
                except Exception:
                    time.sleep(0.2)
            self.assertTrue(online, "Konteyner /healthz cavab vermədi")

            # Qeyri-root yoxlanışı
            uid_res = run_docker("exec", container_name, "id", "-u")
            self.assertEqual(uid_res.stdout.strip(), "10001", "Konteyner root istifadəçisi ilə işləyir!")

            # WebSocket autentifikasiyası (Admin və Agent)
            async def test_ws():
                ws_url = f"ws://127.0.0.1:{port}/ws"
                # Admin WS auth
                async with websockets.connect(ws_url) as ws:
                    await ws.send(json.dumps({"type": "auth", "role": "admin", "admin_secret": admin_secret}))
                    ack = json.loads(await ws.recv())
                    self.assertEqual(ack.get("type"), "auth_ok")

            asyncio.run(test_ws())

        finally:
            run_docker("rm", "-f", container_name, check=False)


if __name__ == "__main__":
    unittest.main()
