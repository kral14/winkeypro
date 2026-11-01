"""Create a source-only first-push checkout; never copies runtime credentials."""
from pathlib import Path
import json
import shutil

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / ".github-publish"
DIRECTORIES = [".github", "apps", "deploy", "installer", "pc_agent", "legacy", "experiments", "scripts", "tests", "docs", "plan"]
SKIP_DIRS = {".git", "rustdesk", "node_modules", "target", "dist", "build", "__pycache__", "keys", "secrets", "backups", "reports", "diagnostic_logs", ".next", ".wrangler", ".vinext", ".sites-runtime", ".sites-checkout", ".openai", "release", "release2", "release3", "smoke-test", "smoke-final"}
SUFFIXES = {".py", ".rs", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".html", ".css", ".json", ".toml", ".lock", ".sql", ".md", ".ps1", ".bat", ".vbs", ".nsi", ".svg", ".png", ".ico", ".txt", ".yml", ".yaml", ".spec"}
SKIP_FILES = {"config.json", "package-credential.json", "unlock_engine.before_fix.txt", "desktop_err.txt", "desktop_out.txt"}
SPECIAL = {"Dockerfile", "Caddyfile", ".gitignore", ".dockerignore", ".npmrc"}


def copy_file(source):
    rel = source.relative_to(ROOT)
    if source.name.startswith(".env") or source.name in SKIP_FILES:
        return
    if source.suffix.lower() not in SUFFIXES and source.name not in SPECIAL:
        return
    target = DEST / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def main():
    if DEST.exists():
        raise SystemExit("Export folder already exists; preserve it and inspect before repeating.")
    DEST.mkdir()
    for source in ROOT.iterdir():
        if source.is_file():
            copy_file(source)
    for name in DIRECTORIES:
        source_root = ROOT / name
        if not source_root.exists():
            continue
        for parent, dirs, files in __import__("os").walk(source_root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith("tmp")]
            for name in files:
                source = Path(parent) / name
                if not source.is_symlink():
                    copy_file(source)
    # Retain local frontend storage bindings, without another host's Site ID.
    hosting = DEST / "legacy/web_remote/.openai/hosting.json"
    hosting.parent.mkdir(parents=True, exist_ok=True)
    hosting.write_text(json.dumps({"d1": "DB", "r2": None}, indent=2) + "\n", encoding="utf-8")
    files = [p for p in DEST.rglob("*") if p.is_file()]
    print(f"Source export: {len(files)} files; {sum(p.stat().st_size for p in files)} bytes; no runtime or release binaries.")


if __name__ == "__main__":
    main()
