#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WinKey Pro - Avtomatlaşdırılmış Git Push Skripti (Python)
Bütün yerli dəyişiklikləri yoxlayır, indeksləyir və GitHub 'main' qoluna göndərir.
"""

import sys
import subprocess
import shutil
from pathlib import Path

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# Terminal rəngləri (ANSI)
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

ROOT_DIR = Path(__file__).resolve().parent

def main():
    import argparse
    import re
    import tempfile
    from scripts.release_pipeline import checkout_for, source_files, verify_package, push_release
    parser = argparse.ArgumentParser(description='Safe source export and existing signed release push; no build.')
    parser.add_argument('--check', action='store_true', help='Local validation only; no push')
    args = parser.parse_args()
    packages = [p for p in (ROOT_DIR / 'dist').glob('WinKeyUpdate-*.zip')
                if re.fullmatch(r'WinKeyUpdate-\d+\.\d+\.\d+\.zip', p.name)]
    if packages:
        package = max(packages, key=lambda p: tuple(map(int, p.stem.removeprefix('WinKeyUpdate-').split('.'))))
    else:
        package = ROOT_DIR / 'deploy/windows_release/WinKeyUpdate.zip'
    version = verify_package(package)
    checkout = checkout_for(ROOT_DIR)
    files = list(source_files(ROOT_DIR))
    print(f'[REPO] {checkout}', flush=True)
    print(f'[PACKAGE] {version}; safe source files={len(files)}', flush=True)
    if args.check:
        print('[PASS] Local validation complete; no push performed.')
        return
    # Avoid SameFileError when exporting the fallback package.
    with tempfile.TemporaryDirectory(prefix='winkey_push_') as td:
        copied = Path(td) / 'WinKeyUpdate.zip'
        shutil.copy2(package, copied)
        push_release(ROOT_DIR, copied, resume=True)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Əməliyyat istifadəçi tərəfindən dayandırıldı.{RESET}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{RED}[XƏTA] {e}{RESET}")
        sys.exit(1)

