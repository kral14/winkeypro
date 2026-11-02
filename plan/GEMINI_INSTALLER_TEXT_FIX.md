# Installer mətnləri: Azərbaycan dili və Unicode düzəlişi

Şəkildə Setup loglarında Azərbaycan hərfləri korlanır: məsələn “Mövcud”, “xidmət”, “istifadəçi”, “yaradılır” əvəzinə anlaşılmaz simvollar görünür. Bu, əsasən encoding/decoder problemidir; yalnız font dəyişmək və ya hərfləri ASCII ilə əvəzləmək həll deyil.

## Tapşırıq

1. installer/WinKeySetup.nsi, onun çağırdığı scripts/service_installer.ps1, service_uninstaller.ps1, prepare_upgrade.ps1, launch_desktop_user.ps1 və faktiki əlaqəli proses çıxışlarını araşdır. Mənbə faylının encoding-i, Windows PowerShell 5.1-in onu oxuması, stdout/stderr encoding-i və NSIS plugin-in çıxışı decode etməsi mərhələlərinin hər birini yoxla. build.py-nin NSIS /INPUTCHARSET UTF8 parametrini qoru.
2. Mənbələrdə əvvəlcədən korlanmış mətnləri düzəlt və düzgün Azərbaycan dilində yaz: ə, ı, İ, ö, ü, ş, ç, ğ. PowerShell 5.1 üçün lazım olan UTF-8 BOM və child stdout/stderr siyasətini açıq qur; Python/Rust/NSIS oxuyucularını həmin müqaviləyə uyğunlaşdır. Bütün fayllara kor-koranə BOM əlavə etmə; Cargo.toml, imzalı manifest və binarlara toxunma.
3. NSIS proses-output plugin-i Unicode-u dəstəkləmirsə, düzgün UTF-8→Unicode decode edən çıxış yolu seç. Windows region/code page dəyişdirmə. Standart Windows-da Azərbaycan hərflərini göstərən oxunaqlı font istifadə et, amma encoding xətasını fontla gizlətmə. Xəta pəncərələri, installer başlıqları və detal logları eyni qaydada düzgün görünsün.
4. Eyni sözlər və terminlər düzgün və ardıcıl olsun. Texniki xəta kodları, yol adları, parametrlər dəyişməsin. Mövcud iş məntiqini, unlock/update/DPAPI/pairing axınlarını dəyişmə.

## Qəbul və test

- İstehsalat Setup-da istifadə olunan eyni çıxış zənciri ilə təhlükəsiz disposable test/harness qur. Nümunə: “Mövcud xidmət dayandırılır. İstifadəçi adı: Nəsib. Quraşdırma uğurla tamamlandı. Əə Iı İi Öö Üü Şş Çç Ğğ”. Stdout və stderr ayrıca yoxlansın.
- PowerShell 5.1 və faktiki NSIS Unicode build üçün yoxla; PowerShell 7 nəticəsini 5.1 sübutu kimi göstərmə.
- Canlı xidməti dayandırma, installer-i real quraşdırma rejimində işlətmə, kompüteri kilidləmə. Mətn-only preview/test pəncərəsi mümkündür. Installer vizual testini etməmisənsə NOT_TESTED yaz, yalnız source text testini vizual sübut sayma.
- Xam log faylları və mümkünsə preview screenshot ver. Çıxışda sual işarəsi/əvəzedici simvol və mojibake qalmamalıdır. Fontu/encoding-i hansı mərhələdə düzəltdiyini konkret göstər.
- Hesabat: plan/reports/INSTALLER_TEXT_FIX_REPORT.md. Dəyişən fayllar, səbəb, test əmrləri/exit code və qalan məhdudiyyətləri yaz.

Build/push/deploy etmə. Mövcud Codex build.py düzəlişlərini (sətirsonu, vaxt ölçümü, WebView2 loader staging, açar yoxlaması) qoru. Tapşırığı bir paketdə bitirib Codex yoxlaması üçün dayan.
