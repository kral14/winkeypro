import os
import zipfile
import hashlib

dist_dir = 'plan/reports/remaining/revision8'
os.makedirs(dist_dir, exist_ok=True)
zip_out = os.path.join(dist_dir, 'WinKeyPro-v0.1.0-Windows-x64-Rev8Build.zip')

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

readme_content = """# WinKey Pro — Windows x64 Buraxılış Paketi (Reviziya 8)
Versiya: v0.1.0-Rev8
Klassifikasiya: RELEASE_TEST_BUILD | LOCAL_PIN_VAULT | ED25519_BOUNDED

## Paketin Məzmunu:
- `winkey_service.exe` (Windows SCM Xidməti, Local PIN DPAPI Vault & LocalSystem Token Engine)
- `winkey_helper.exe` (Winlogon & Default Session Köməkçi Prosesi, Ephemeral Overlapped IPC)
- `winkey_desktop.exe` (İdarəetmə GUI Paneli, Tray İnteqrasiyası, QR/Ed25519 Cütləşdirmə və Lokal PIN Setup)
- `service_installer.ps1` (SCM Quraşdırma Skripti)
- `service_uninstaller.ps1` (SCM Silmə Skripti)
- `SHA256SUMS.txt` (Kriptoqrafik Bütövlük Heşləri)

## Təhlükəsizlik və Lokal PIN Qaydası (REM-020):
1. **Şəbəkədə Sıfır Credential:** Mobil telefon və ya Gateway server heç vaxt PIN daşımır və qəbul etmir. Server sorğuları PIN/parol göndərildikdə HTTP 400 ilə rədd edilir.
2. **Lokal Saxlanma:** PIN yalnız kompüterdə `winkey_desktop.exe` vasitəsilə daxil edilir və xidmətin `user_credential.dpapi` şifrəli vault-unda saxlanılır.
3. **Winlogon Token Təhlükəsizliyi (REM-019):** Winlogon masaüstündə köməkçi yalnız LocalSystem tokeni ilə icra oluna bilər; standart istifadəçi tokenləri fail-closed rədd edilir.

## Pilot Operator Sınaq Təlimatı:
Bax: `plan/reports/REMAINING_WORK_REVISION_8.md`
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
