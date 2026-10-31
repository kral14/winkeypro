"""Smoke the actual Linux image with the same read-only/nonroot setup as Compose."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def run(*args, check=True):
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check, timeout=45)


def main():
    name = "winkey-smoke-" + secrets.token_hex(6)
    with tempfile.TemporaryDirectory(dir=ROOT) as folder:
        key = Path(folder) / "admin_key"
        key.write_text(secrets.token_hex(32), encoding="ascii")
        try:
            run("run", "--detach", "--name", name, "--read-only", "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "--tmpfs", "/data:uid=10001,gid=10001,mode=0700",
                "--tmpfs", "/tmp:mode=1777",
                "--mount", f"type=bind,source={key},target=/run/secrets/admin_key,readonly",
                "winkey-vm:local-test")
            probe = "import os,urllib.request,json; assert os.getuid()==10001; r=urllib.request.urlopen('http://127.0.0.1:8788/healthz',timeout=3); assert json.load(r)['status']=='ONLINE'; print('PASS nonroot Linux container + mounted secret + SQLite health')"
            for attempt in range(15):
                result = run("exec", name, "python", "-c", probe, check=False)
                if result.returncode == 0:
                    print(result.stdout.strip())
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError("Container health failed; inspect the test container locally.")
            config = json.loads(run("inspect", name).stdout)[0]
            assert config["HostConfig"]["ReadonlyRootfs"]
            assert not config["HostConfig"]["PortBindings"]
            print("PASS read-only rootfs; gateway has no public host port")
        finally:
            run("rm", "--force", name, check=False)


if __name__ == "__main__":
    main()
