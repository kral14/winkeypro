import os
import zipfile
import hashlib

dist_dir = 'plan/reports/remaining/revision9'
os.makedirs(dist_dir, exist_ok=True)
zip_out = os.path.join(dist_dir, 'WinKeyPro-v0.1.0-Windows-x64-Rev9Build.zip')

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

readme_content = """# WinKey Pro — Windows x64 Buraxılış Paketi (Reviziya 9)
Versiya: v0.1.0-Rev9
Klassifikasiya: RELEASE_PRODUCTION_CANDIDATE | MODEL_UNIT_VERIFIED | STRICT_BOUNDARIES

## Paketin Məzmunu:
- `winkey_service.exe` (Windows SCM Xidməti, Local PIN DPAPI Vault, Narrow DACL & LocalSystem Token Engine)
- `winkey_helper.exe` (Winlogon & Default Session Köməkçi Prosesi, Overlapped In-Memory Scan-Code Injection)
- `winkey_desktop.exe` (İdarəetmə GUI Paneli, Tray İnteqrasiyası, QR/Ed25519 Cütləşdirmə, argv-prohibited PIN Provisioning)
- `service_installer.ps1` (SCM Quraşdırma Skripti)
- `service_uninstaller.ps1` (SCM Silmə Skripti)
- `SHA256SUMS.txt` (Kriptoqrafik Bütövlük Heşləri)

## Üç Əsas Təhlükəsizlik Zəmanəti (Reviziya 9):
1. **REM-023: Gerçək Nəticə və Heç Vaxt Saxta Uğur Olmaması (Fail-Closed Unlocked Verification):**
   - Helper heç vaxt sadəcə SendInput göndərib exit 0 vermir. Hədəf sessiyanın WTS unlock vəziyyəti təsdiqlənməlidir.
   - Wrong PIN / desktop dəyişmədikdə exit 3 (`UNLOCK_FAILED`) qaytarılır.
   - SendInput hər bir klaviş üçün yoxlanılır (partial input abort).
   - Windows Hello və ya auto-submit aşkarlandıqda Enter ötürülmür.
   - UAC və ya Default masaüstündə parol sızmasının qarşısı tam alınır.

2. **REM-024: Lokal PIN API və Sıfır Komanda Sətri/Mühit Dəyişəni Sızması:**
   - `--store-pin <PIN>` komanda sətrində parametr kimi verildikdə dərhal exit code 2 və `E_ARGV_CREDENTIAL_PROHIBITED` ilə rədd edilir.
   - PIN yalnız stdin (`--store-pin-stdin`) və ya konsol maskalanmış prompt (`--store-pin-prompt`) vasitəsilə daxil edilir.
   - Xidmət işləmədikdə heç bir saxta lokal user vault faylı yaradılmır; xidmətin təsdiqi (ACK) olmadıqda exit 1 ilə imtina edilir.
   - Yeganə qanuni vault xidmətə məxsus `user_credential.dpapi` faylıdır.

3. **REM-025: Actual Service Provisioning IPC & Strict Access Mask (B.2b):**
   - Xidmət pipe DACL-i qeydiyyatdan keçmiş sahib SID-inə (`S-1-5-21-...`) bağlanır; IU fallback çıxarılıb.
   - Müştəri (Desktop) minimum icazə maskası (`PIPE_MIN_USER_CHANNEL_MASK` = 0x0012008B) və `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` ilə qoşulur.
   - `GENERIC_WRITE` istəyi Windows OS təhlükəsizlik alt sistemi tərəfindən `ERROR_ACCESS_DENIED (5)` ilə rədd edilir.

## Pilot Operator Sınaq Təlimatı:
Bax: `plan/reports/REMAINING_WORK_REVISION_9.md`
"""

sha_lines.append(f"{hashlib.sha256(readme_content.encode('utf-8')).hexdigest()}  README.md")
sha_text = '\n'.join(sha_lines) + '\n'

with zipfile.ZipFile(zip_out, 'w', compression=zipfile.ZIP_DEFLATED) as z:
    for src, arc in items:
        z.write(src, arc)
    z.writestr('SHA256SUMS.txt', sha_text)
    z.writestr('README.md', readme_content)

zip_bytes = open(zip_out, 'rb').read()
zip_sha = hashlib.sha256(zip_bytes).hexdigest()
zip_size_mb = len(zip_bytes) / (1024*1024)
print(f"Created {zip_out}: Size={zip_size_mb:.2f} MB ({len(zip_bytes)} bytes), SHA256={zip_sha}")

# SHA256 heşlərini həm də qovluqda saxla
with open(os.path.join(dist_dir, 'SHA256SUMS.txt'), 'w', encoding='utf-8') as f:
    f.write(sha_text)
    f.write(f"{zip_sha}  WinKeyPro-v0.1.0-Windows-x64-Rev9Build.zip\n")
