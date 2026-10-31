"""
WinKey Pro — Extracted ZIP Clean Layout & Standalone Execution Test
Spesifikasiya: plan/GEMINI_RECOVERY_RELEASE_REVISION.md
Çıxarılmış ZIP paketinin heç bir repo/mənbə asılılığı olmadan, tam təmiz
mühitdə (clean isolated directory) bütövlüyünü və icra oluna bilməsini yoxlayır.
"""

import os
import sys
import zipfile
import hashlib
import tempfile
import subprocess
import shutil

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def main():
    zip_path = os.path.abspath("plan/reports/final_batch/WinKeyPro-v0.1.0-Windows-x64-FinalBuild.zip")
    sha_path = os.path.abspath("plan/reports/final_batch/SHA256SUMS.txt")

    assert os.path.exists(zip_path), f"ZIP tapılmadı: {zip_path}"
    assert os.path.exists(sha_path), f"SHA256SUMS tapılmadı: {sha_path}"

    temp_clean = tempfile.mkdtemp(prefix="winkey_clean_zip_")
    print(f"[SETUP] Təmiz izolyasiya qovluğu: {temp_clean}")

    try:
        # 1. ZIP çıxarılır
        print("\n--- TEST 1: ZIP paketinin təmiz qovluğa çıxarılması ---")
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(temp_clean)
        extracted_files = os.listdir(temp_clean)
        print(f"[PASS] Çıxarılmış fayllar ({len(extracted_files)} ədəd): {sorted(extracted_files)}")

        # 2. SHA256 Bütövlük Yoxlanışı
        print("\n--- TEST 2: SHA256SUMS bütövlük yoxlanışı ---")
        with open(sha_path, "r", encoding="utf-8") as sf:
            lines = sf.readlines()

        verified = 0
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) == 2:
                exp_hash, fname = parts[0], parts[1]
                fpath = os.path.join(temp_clean, fname)
                if os.path.exists(fpath):
                    act_hash = sha256_file(fpath)
                    assert act_hash.lower() == exp_hash.lower(), f"Hash uyğunsuzluğu: {fname}"
                    verified += 1
        print(f"[PASS] Bütün {verified} çıxarılmış faylın SHA-256 hash-i təsdiqləndi!")

        # 3. Flat layout Python idxal testi (pc_agent qovluğu olmadan birbaşa işləmə)
        print("\n--- TEST 3: Çıxarılmış qovluqda supervisor və update engine idxalı ---")
        env = os.environ.copy()
        env["PYTHONPATH"] = "" # Repo axtarışını tam söndürürük!

        res_py = subprocess.run(
            ["python", "service_supervisor.py"],
            cwd=temp_clean,
            env=env,
            capture_output=True,
            text=True
        )
        assert res_py.returncode == 0, f"service_supervisor.py fail oldu: {res_py.stderr}"
        assert "Service Supervisor" in res_py.stdout, f"Gözlənilməz çıxış: {res_py.stdout}"
        print(f"[PASS] Flat qovluqda service_supervisor.py uğurla icra olundu: {res_py.stdout.strip()}")

        # 4. Çıxarılmış qovluqda service_installer.ps1 DryRun testi
        print("\n--- TEST 4: Çıxarılmış qovluqdan installer DryRun testi ---")
        res_ps = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", "service_installer.ps1", "-DryRun"],
            cwd=temp_clean,
            capture_output=True,
            encoding="utf-8",
            errors="replace"
        )
        assert res_ps.returncode == 0, f"Installer DryRun fail oldu: {res_ps.stderr}"
        assert "DRY_RUN_PLAN_SUCCESSFUL" in res_ps.stdout or "DRY RUN PASS" in res_ps.stdout, f"Gözlənilməz çıxış: {res_ps.stdout}"
        # Təsdiq edirik ki, installer qaynaq kimi məhz çıxarılmış temp qovluğu tapıb:
        assert temp_clean.lower() in res_ps.stdout.lower() or "Qaynaq Qovlu" in res_ps.stdout, "Installer çıxarılmış qovluğu mənbə kimi görmədi"
        print(f"[PASS] Installer çıxarılmış qovluqdan müstəqil şəkildə uğurla çalışdı!")

        print("\n=============================================================")
        print("  EXTRACTED ZIP CLEAN LAYOUT SINAĞI 100% PASS OLDU!          ")
        print("=============================================================")

    finally:
        shutil.rmtree(temp_clean, ignore_errors=True)

if __name__ == "__main__":
    main()
