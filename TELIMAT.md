# 📱 WinKey Pro — Rəsmi İstifadəçi və Operator Təlimatı

WinKey Pro — mobil telefon vasitəsilə Windows kompüterinizin kilidini uzaqdan açmaq və kilidləmək üçün hazırlanmış təhlükəsizlik sistemidir.

---

## 🛡️ Təhlükəsizlik Fəlsəfəsi: "Sıfır PIN Sızması" (Zero-PIN)
* **Telefonunuzda HEÇ VAXT Windows PIN və ya şifrəsi yazılmır.**
* PIN kodu yalnız kompüterinizin daxilində **Windows DPAPI** şifrələməsi ilə yerli anbarında saxlanır.
* Şəbəkəyə, serverə və ya internetə heç bir halda PIN və ya şifrə ötürülmür.

---

## 🚀 1. Gateway Serverinin Başladılması

WinKey Pro telefon ilə kompüter arasında əlaqə qurmaq üçün təhlükəsiz Gateway serverindən istifadə edir:

### A) Lokal Şəbəkə və ya Sınaq üçün:
Qovluqda terminalı açın və icra edin:
```powershell
python deploy\gateway_production_server.py 8089
```
Server `http://127.0.0.1:8089` (və ya kompüterinizin lokal IP-si ilə) fəaliyyətə başlayacaq.

### B) İctimai İnternet (Sites / Cloudflare / VPS) üçün:
`deploy/` qovluğundakı Dockerfile və ya server skriptini istənilən ictimai HTTPS serverinə yerləşdirin (məsələn: `https://winkey-gateway.misal.com`).

---

## 💻 2. Windows Xidmətinin Quraşdırılması (Administrator)

Windows kilid ekranına müdaxilə etmək üçün xidmət Administrator hüququ ilə SCM-də qeydiyyata alınmalıdır:

1. PowerShell-i **Administrator** olaraq açın.
2. Bu əmri icra edin:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\service_installer.ps1
```
* Xidmət avtomatik olaraq `C:\Program Files\WinKey Pro` qovluğuna dar icazələrlə (SYSTEM + Admins) kopyalanır və işə salınır.
* Məhdud sağlamlıq yoxlanışı (10 saniyə) xidmətin və Named Pipe kanalının aktivliyini təsdiqləyir.

---

## 🔑 3. Desktop Proqramı və Yerli PIN Təyini

1. `winkey_desktop.exe` proqramını işə salın.
2. **"Cihaz Statusu"** bölməsində:
   - Gateway Server ünvanını təyin edin (məsələn `http://127.0.0.1:8089`).
3. **"Təhlükəsizlik və PIN"** bölməsində:
   - Windows PIN kodunuzu daxil edib **"PIN-i Təhlükəsiz Saxla"** düyməsini sıxın.
   - Bu kod dərhal yerli Windows DPAPI anbarına (`user_credential.dpapi`) yazılır və ekrandan silinir (Zeroize). Gateway cihaz açarından (`device_secret.dpapi`) tamamilə təcrid olunub.

---

## 📲 4. Telefon ilə Cütləşdirmə (QR Kod)

1. Desktop pəncərəsində **"Mobil QR Cütləşmə"** bölməsinə keçin.
2. Göstərilən QR kodu telefonunuzun kamerası ilə oxudun.
3. Brauzerdə açılan zümrüd yaşıl Dark interfeysdə **"Qoşul"** toxunun.
   - QR kod Ed25519 kriptoqrafik imzası ilə 120 saniyəlik qorunur.
   - Bir dəfə cütləşdikdən sonra həmin kod dərhal ləğv edilir (Anti-Replay).

---

## 🔒 5. Kilidləmə və Kilidi Açma

* **Kilidlə:** Telefonda "Kompüteri Kilidlə" düyməsinə toxunun. Windows dərhal kilidlənir.
* **Kilidi Aç:** Telefonda "Kilidi Aç" düyməsinə toxunun. Kompüter arxa planda yerli DPAPI anbarındakı PIN ilə Winlogon ekranını açır.

---

## ⏸️ 6. İdarəetmə, Dayandırma və Silinmə

* **Pəncərəni bağlamaq (✕):** Proqramı söndürmür, arxa plana (saat yanındakı Tray ikonuna) gizlədir.
* **Tepsidən İdarə:** Tray ikonuna sağ klikləyərək menyunu aça bilərsiniz:
  - *Proqramı aç*: Pəncərəni önə gətirir.
  - *Mobil İdarəni Dayandır*: Uzaqdan gələn əmrləri müvəqqəti dondurur.
  - *Mobil İdarəni Bərpa Et*: Uzaqdan idarəni yenidən aktivləşdirir.
  - *Desktop tətbiqindən çıxış*: Yalnız qrafik interfeysi bağlayır; xidmət arxa planda qalır.
* **Sistemdən Tam Silmək (Uninstall):**
  Administrator PowerShell pəncərəsində icra edin:
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\scripts\service_uninstaller.ps1
  ```
