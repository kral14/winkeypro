import sys
import os
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
import build

def main():
    if len(sys.argv) < 5:
        sys.exit(2)
    mode = sys.argv[1]
    staging_dir = Path(sys.argv[2])
    target_dir = Path(sys.argv[3])
    pub_key_hex = sys.argv[4]

    def hook(transition):
        if mode == "crash_after_backup" and transition == "after_backup_before_candidate_swap":
            print(f"[CHILD_CRASH] Exiting at {transition} with code 77", flush=True)
            os._exit(77)
        elif mode == "crash_after_swap" and transition == "after_candidate_swap_before_backup_cleanup":
            print(f"[CHILD_CRASH] Exiting at {transition} with code 77", flush=True)
            os._exit(77)

    if mode == "crash_mid_write":
        backup_dir = target_dir.parent / (target_dir.name + ".backup")
        if backup_dir.exists():
            import shutil
            shutil.rmtree(backup_dir, ignore_errors=True)
        target_dir.rename(backup_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        (target_dir / "manifest.json").write_text('{"version": "partial"}', encoding="utf-8")
        print("[CHILD_CRASH] Exiting mid-write with partial target, code 77", flush=True)
        os._exit(77)

    build.commit_staged_release(
        staging_dir=staging_dir,
        target_dir=target_dir,
        pub_key_hex=pub_key_hex,
        transition_hook=hook
    )

if __name__ == "__main__":
    main()

