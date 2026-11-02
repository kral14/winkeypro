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

# Terminal rəngləri (ANSI)
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

ROOT_DIR = Path(__file__).resolve().parent

def run_git_command(args, check=True):
    """Git əmrini icra edir və çıxışı qaytarır."""
    try:
        res = subprocess.run(
            ["git"] + args,
            cwd=ROOT_DIR,
            text=True,
            capture_output=True,
            encoding="utf-8",
            errors="replace"
        )
        if check and res.returncode != 0:
            raise RuntimeError(f"Git {' '.join(args)} xətası (Exit={res.returncode}):\n{res.stderr.strip()}")
        return res
    except FileNotFoundError:
        print(f"{RED}[XƏTA] Sistemdə 'git' tapılmadı! Zəhmət olmasa Git-in quraşdırıldığından əmin olun.{RESET}")
        sys.exit(1)

def main():
    # Windows konsolunda UTF-8 və ANSI rənglərini aktivləşdiririk
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleOutputCP(65001)
            # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            h_out = kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(h_out, ctypes.byref(mode))
            kernel32.SetConsoleMode(h_out, mode.value | 0x0004)
        except Exception:
            pass

    print(f"\n{CYAN}{BOLD}============================================================{RESET}")
    print(f"{CYAN}{BOLD}          WinKey Pro - GitHub-a Göndərmə Skripti            {RESET}")
    print(f"{CYAN}{BOLD}============================================================{RESET}\n")

    # 1. Git mövcudluğunu və qolu yoxlayırıq
    branch_res = run_git_command(["branch", "--show-current"])
    current_branch = branch_res.stdout.strip()
    if not current_branch:
        current_branch = "main"

    print(f"{YELLOW}[1/3] Cari qol: '{current_branch}' | Status yoxlanılır...{RESET}")
    status_res = run_git_command(["status", "--short"])
    if status_res.stdout.strip():
        print(status_res.stdout)
    else:
        print("  Dəyişilmiş fayl yoxdur (iş ağacı təmizdir).")

    # 2. Qalan dəyişiklikləri indeksləyirik və commit edirik
    print(f"\n{YELLOW}[2/3] Dəyişikliklər indekslənir (git add -A)...{RESET}")
    run_git_command(["add", "-A"])

    diff_cached = run_git_command(["diff", "--cached", "--quiet"], check=False)
    if diff_cached.returncode != 0:
        print(f"{GREEN}[MƏLUMAT] İndekslənmiş yeni dəyişikliklər commit olunur...{RESET}")
        commit_res = run_git_command(["commit", "-m", "fix(admin): resolve JS syntax errors, add device delete in admin panel and auto-unregister on revoke"])
        print(f"  {commit_res.stdout.strip()}")
    else:
        print(f"{GREEN}[MƏLUMAT] Əlavə commit tələb olunmur; commitlər göndərilməyə hazırdır.{RESET}")

    # 3. GitHub-a göndəririk (git push origin <branch>)
    print(f"\n{YELLOW}[3/3] GitHub-a göndərilir: git push origin {current_branch}...{RESET}")
    push_process = subprocess.Popen(
        ["git", "push", "origin", current_branch],
        cwd=ROOT_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    for line in push_process.stdout:
        print("  " + line, end="")

    push_process.wait()

    print()
    if push_process.returncode == 0:
        print(f"{GREEN}{BOLD}============================================================{RESET}")
        print(f"{GREEN}{BOLD}[✓ UĞURLU] Bütün dəyişikliklər GitHub repozitoriyasına göndərildi!{RESET}")
        print(f"{GREEN}{BOLD}============================================================{RESET}\n")
    else:
        print(f"{RED}{BOLD}============================================================{RESET}")
        print(f"{RED}{BOLD}[XƏTA] Push zamanı problem yarandı! Exit={push_process.returncode}{RESET}")
        print(f"{RED}İnternet bağlantınızı və ya GitHub icazələrinizi yoxlayın.{RESET}")
        print(f"{RED}{BOLD}============================================================{RESET}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Əməliyyat istifadəçi tərəfindən dayandırıldı.{RESET}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{RED}[XƏTA] {e}{RESET}")
        sys.exit(1)

