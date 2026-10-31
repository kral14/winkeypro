import os
import zipfile
import hashlib

dist_dir = 'plan/reports/remaining/revision10'
os.makedirs(dist_dir, exist_ok=True)
zip_out = os.path.join(dist_dir, 'WinKeyPro-v0.1.0-Windows-x64-Rev10Build.zip')

items = [
    ('apps/winkey_service/target/release/winkey_service.exe', 'winkey_service.exe'),
    ('apps/winkey_service/target/release/winkey_helper.exe', 'winkey_helper.exe'),
    ('apps/desktop_tauri/src-tauri/target/release/winkey_desktop.exe', 'winkey_desktop.exe'),
    ('scripts/service_installer.ps1', 'service_installer.ps1'),
    ('scripts/service_uninstaller.ps1', 'service_uninstaller.ps1'),
]

sha_lines = []
for src, arc in items:
    data = open(src, 'rb').read()
    h = hashlib.sha256(data).hexdigest()
    sha_lines.append(f"{h}  {arc}")

readme_content = """# WinKey Pro — Windows x64 Buraxılış Paketi (Reviziya 10)
Versiya: v0.1.0-Rev10
Klassifikasiya: RELEASE_PILOT_CANDIDATE | MODEL_UNIT_VERIFIED | SCM_TRUSTED_BINDING

## Paketin Məzmunu:
- `winkey_service.exe` (Windows SCM Xidməti, Service-Owned DPAPI Vault, Narrow DACL & Unenrolled Idle Bootstrap)
- `winkey_helper.exe` (Winlogon Session Köməkçi Prosesi, PIPE_MIN_CREDENTIAL_ACCESS, Strict Focus Check, Hardened Scan-Code Injection)
- `winkey_desktop.exe` (İdarəetmə GUI Paneli, SCM Server Process/Identity/PID Verification, Stdin PIN Provisioning)
- `service_installer.ps1` (Protected ProgramFiles ACL, Service ProgramData, Enrolled Owner SID & 10s Health Check)
- `service_uninstaller.ps1` (SCM Silmə, ProgramFiles Təmizlənməsi & Opsional PurgeData)
- `SHA256SUMS.txt` (Kriptoqrafik Bütövlük Heşləri)

## Pilot Öncesi Əsas Təhlükəsizlik Zəmanətləri (Reviziya 10 + Codex Fixes):
1. **Helper Minimum Credential Mask (Codex Fix):**
   - Helper boru açarkən `GENERIC_WRITE` əvəzinə `PIPE_MIN_CREDENTIAL_ACCESS = 0x0012008B` istifadə edir.
   - Xidmətin dar DACL-i ilə tam uyğundur; OS AccessDenied (5) və helper connection timeout aradan qaldırılmışdır.

2. **REM-026: Production Fokus və Desktop Yoxlaması:**
   - Heç bir focus istisnası True kimi udulmur. Fokus təsdiqlənmədikdə dərhal fail-closed (False) qaytarılır.
   - `inject_credentials_in_memory` dərhal `E_FOCUS_FAILED` qaldırır və SendInput çağırışı dəqiq 0 olur.
   - UAC və ya auth pəncərəsi olmayan masaüstündə input sızması 100% əngəllənir.

3. **REM-027: Trusted SCM Server Binding və Zero Payload Leak:**
   - Desktop provisioning müştərisi Named Pipe açdıqdan dərhal sonra serverin PID-sini, icra faylının `winkey_service.exe` olmasını və LocalSystem (`S-1-5-18`) tokenini yoxlayır.
   - Saxta boru serverinə (rogue process) və ya eyni istifadəçi hüququ ilə çalışan yad prosesə SIFIR bayt PIN/gizli məlumat ötürülür (`assert read_bytes == 0`).
   - Standalone test rejimi üçün yalnız explicit PID təsdiqi tələb olunur.

4. **REM-028: Qorunan Quraşdırma, Servis Bootstrap və 10s Sağlamlıq Yoxlanışı:**
   - Binary validation (>500KB), qorunan Program Files kopyalanması və dar ACL (SYSTEM/Admin Full, Users Read&Execute).
   - Xidmətə məxsus ProgramData, `owner.sid` bağlanması və təmiz maşınlarda `UNENROLLED_IDLE` vəziyyətində təhlükəsiz gözləmə.
   - SCM qeydiyyatı, auto-recovery və 10 saniyəlik məhdud zamanlı sağlamlıq yoxlanışı (Service Running + IPC Named Pipe).

5. **Test İcrası və Təhlükəsizlik Sərhədləri:**
   - Avtomatik testlərdə real ekran kilidlənmir (non-physical / mock action).
   - Fiziki unlock testi açıq opt-in (`--allow-real-input`) tələb edir və avtomatik işə salınmır.

## Bir Səhifəlik Fiziki Test Təlimatı:
Bax: `plan/reports/REMAINING_WORK_REVISION_10.md`
"""

sha_lines.append(f"{hashlib.sha256(readme_content.encode('utf-8')).hexdigest()}  README.md")
sha_text = '\n'.join(sha_lines) + '\n'

with open(os.path.join(dist_dir, 'SHA256SUMS.txt'), 'w', encoding='utf-8') as f:
    f.write(sha_text)

with zipfile.ZipFile(zip_out, 'w', compression=zipfile.ZIP_DEFLATED) as z:
    for src, arc in items:
        z.write(src, arc)
    z.writestr('SHA256SUMS.txt', sha_text)
    z.writestr('README.md', readme_content)

zip_bytes = open(zip_out, 'rb').read()
zip_sha = hashlib.sha256(zip_bytes).hexdigest()
zip_size_mb = len(zip_bytes) / (1024*1024)
print(f"Created {zip_out}: Size={zip_size_mb:.2f} MB ({len(zip_bytes)} bytes), SHA256={zip_sha}")
