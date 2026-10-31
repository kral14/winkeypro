"""Create VM-local configuration without placing credentials in Git or stdout."""
import argparse
import os
from pathlib import Path
import re
import secrets

ROOT = Path(__file__).resolve().parents[2]


def configure(domain, root=ROOT):
    domain = domain.strip().lower()
    if len(domain) > 253 or not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
        raise ValueError("HTTPS üçün yalnız domen yazın, məsələn winkey.example.com (URL və port deyil).")
    folder = root / "deploy/vm/secrets"
    folder.mkdir(parents=True, exist_ok=True)
    # The gateway runs as UID 10001; Docker mounts this one file read-only.
    # The enclosing 0700 directory prevents other host users reading it.
    os.chmod(folder, 0o700)
    key = folder / "admin_key"
    if not key.exists():
        with key.open("x", encoding="ascii") as handle:
            handle.write(secrets.token_hex(32) + "\n")
    os.chmod(key, 0o444)
    env = root / ".env"
    if env.exists() and env.read_text(encoding="utf-8").strip() != f"WINKEY_DOMAIN={domain}":
        raise ValueError(".env mövcuddur; onu avtomatik əvəz etmirəm. WINKEY_DOMAIN sətrini əl ilə yeniləyin.")
    if not env.exists():
        env.write_text(f"WINKEY_DOMAIN={domain}\n", encoding="utf-8")
    print(f"Hazırdır: https://{domain}/admin — mövcud admin açarı qorundu, stdout-a yazılmadı.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", required=True)
    args = parser.parse_args()
    configure(args.domain)
