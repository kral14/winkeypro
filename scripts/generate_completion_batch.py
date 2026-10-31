import os
import sys
import zipfile
import hashlib
import subprocess

BATCH_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "plan", "reports", "completion_batch"))
os.makedirs(BATCH_DIR, exist_ok=True)

# 1. Run Singleton Test and capture log
print("[1/5] Running and capturing Singleton & Tray Lifecycle Test...")
p1 = subprocess.run([sys.executable, "scripts/test_desktop_tray_singleton.py"], capture_output=True, encoding="utf-8", errors="replace")
with open(os.path.join(BATCH_DIR, "singleton_tray_lifecycle.log"), "w", encoding="utf-8") as f:
    f.write(p1.stdout + "\n" + p1.stderr)
assert p1.returncode == 0, f"Singleton test failed: {p1.stderr}"

# 2. Run Mobile Gateway Flow Test and capture log
print("[2/5] Running and capturing Mobile Gateway Flow Test...")
p2 = subprocess.run([sys.executable, "tests/test_mobile_gateway_flow.py"], capture_output=True, encoding="utf-8", errors="replace")
with open(os.path.join(BATCH_DIR, "mobile_gateway_flow.log"), "w", encoding="utf-8") as f:
    f.write(p2.stdout + "\n" + p2.stderr)
assert p2.returncode == 0, f"Mobile flow test failed: {p2.stderr}"

# 3. Run Codex Non-Physical E2E Test and capture log
print("[3/5] Running and capturing Codex Non-Physical E2E Test...")
p3 = subprocess.run([sys.executable, "scripts/codex_run_nonphysical_e2e.py"], capture_output=True, encoding="utf-8", errors="replace")
with open(os.path.join(BATCH_DIR, "nonphysical_e2e.log"), "w", encoding="utf-8") as f:
    f.write(p3.stdout + "\n" + p3.stderr)
assert p3.returncode == 0, f"Codex E2E test failed: {p3.stderr}"

# 4. Run Helper Pipe Access Regression Test
print("[4/5] Running and capturing Helper Pipe Access Regression Test...")
p4 = subprocess.run([sys.executable, "scripts/test_helper_pipe_access.py"], capture_output=True, encoding="utf-8", errors="replace")
with open(os.path.join(BATCH_DIR, "helper_pipe_access.log"), "w", encoding="utf-8") as f:
    f.write(p4.stdout + "\n" + p4.stderr)
assert p4.returncode == 0, f"Helper pipe access test failed: {p4.stderr}"

# 5. Build Complete Bundle ZIP
print("[5/5] Building WinKeyPro-v0.1.0-Windows-x64-CompleteBuild.zip...")
zip_out = os.path.join(BATCH_DIR, "WinKeyPro-v0.1.0-Windows-x64-CompleteBuild.zip")

items = [
    ("apps/winkey_service/target/release/winkey_service.exe", "winkey_service.exe"),
    ("apps/winkey_service/target/release/winkey_helper.exe", "winkey_helper.exe"),
    ("apps/desktop_tauri/src-tauri/target/release/winkey_desktop.exe", "winkey_desktop.exe"),
    ("scripts/service_installer.ps1", "service_installer.ps1"),
    ("scripts/service_uninstaller.ps1", "service_uninstaller.ps1"),
]

sha_lines = []
for src, arc in items:
    data = open(src, "rb").read()
    h = hashlib.sha256(data).hexdigest()
    sha_lines.append(f"{h}  {arc}")

readme_content = """# WinKey Pro — Tam Tamamlanmış Windows x64 Məhsul Paketi
Versiya: v0.1.0-CompleteBuild
Klassifikasiya: PRODUCTION_CANDIDATE | COMPLETED_BATCH | SINGLETON_VERIFIED | SCM_TRUSTED_BINDING

## Paketin Məzmunu:
- `winkey_service.exe`: Windows SCM Xidməti, Service-Owned DPAPI Vault, Narrow DACL, Unenrolled Idle Bootstrap.
- `winkey_helper.exe`: Winlogon Session Köməkçi Prosesi, PIPE_MIN_CREDENTIAL_ACCESS (0x0012008B), Hardened Scan-Code Injection, Strict Focus Verification.
- `winkey_desktop.exe`: Desktop GUI Paneli, Tray Menyu (Open/Status/Exit), Session-Scoped Named Mutex Singleton, SCM Server Process/Identity/PID Verification, Stdin PIN Provisioning.
- `service_installer.ps1`: Qorunan ProgramFiles ACL, Service ProgramData, Enrolled Owner SID & 10s Bounded Health Check Quraşdırıcısı.
- `service_uninstaller.ps1`: SCM Silmə, ProgramFiles Təmizlənməsi & Opsional PurgeData Təmizləyicisi.
- `SHA256SUMS.txt`: Kriptoqrafik Bütövlük Heşləri.

## Beş Əsas Təhlükəsizlik və Funksional Zəmanət:
1. **Singleton və Tray İdarəetməsi:** Tək proses, təkrarlanan launch zamanı mövcud pəncərənin bərpası, sağ klik menyusundan tam çıxış və təmiz bağlanma.
2. **Avant-Garde Mobil İnterfeys (/remote və /mobile):** Cütləşmə, canlı status (Onlayn/Oflayn), Kilidləmə, Kilid Açma, canlı komanda nəticəsi və revoke axını.
3. **Sıfır PIN Sızması (Zero PIN Leak):** Telefonda və ya serverdə heç vaxt Windows PIN saxlanılmır və daşınmır; PIN yalnız PC-də təhlükəsiz DPAPI anbarında saxlanılır.
4. **Helper Minimum Mask Uyğunluğu:** Helper xidmətin dar DACL-inə `PIPE_MIN_CREDENTIAL_ACCESS` (0x0012008B) ilə qoşulur; OS AccessDenied (5) və connection timeout tam aradan qaldırılıb.
5. **Dürüst Test Təsnifatı:** Standart testlərdə real ekran kilidlənmir (non-physical mock); fiziki canlı unlock testi açıq opt-in (`--allow-real-input`) tələb edir və əl ilə operator tərəfindən icra edilənə qədər NOT_TESTED saxlanılır.

## Bir Səhifəlik Operator Təlimatı:
Bax: `plan/reports/COMPLETION_BATCH_REPORT.md`
"""

sha_lines.append(f"{hashlib.sha256(readme_content.encode('utf-8')).hexdigest()}  README.md")
sha_text = "\n".join(sha_lines) + "\n"

with open(os.path.join(BATCH_DIR, "SHA256SUMS.txt"), "w", encoding="utf-8") as f:
    f.write(sha_text)

with zipfile.ZipFile(zip_out, "w", compression=zipfile.ZIP_DEFLATED) as z:
    for src, arc in items:
        z.write(src, arc)
    z.writestr("SHA256SUMS.txt", sha_text)
    z.writestr("README.md", readme_content)

zip_bytes = open(zip_out, "rb").read()
zip_sha = hashlib.sha256(zip_bytes).hexdigest()
zip_size_mb = len(zip_bytes) / (1024*1024)
print(f"Created {zip_out}: Size={zip_size_mb:.2f} MB, SHA256={zip_sha}")
print("\n[SUCCESS] All batch test logs and release bundle generated successfully in plan/reports/completion_batch/")
