# Sahib üçün tək Python build scripti: build.py -> WinKeySetup.exe

Sahib build və quraşdırma sınağını özü edəcək. Mövcud kod/NSIS/build_one_setup_exe.py əsasında kökdə bir `build.py` hazırla. Məqsəd: sahibi `python build.py` və ya IDE Run basır, son mənbədən bir `dist/WinKeySetup.exe` yaranır. Aralıq audit gözləmə, bütün build zəncirini birlikdə tamamla.

## Məcburi actual build ardıcıllığı
1. İş qovluğundan asılı olmadan scriptin root yolunu tap. Cargo/NSIS və lazımi alətləri preflight et; çatışmayanı aydın göstər. Workspace toolchain mövcuddursa istifadə et. Adi incremental build saxla; hər dəfə cargo clean etmə.
2. Son Rust service/recovery və Tauri desktop release build. Python helper source dəyişibsə PyInstaller ilə bundled helper-i yenilə; runtime Python tələb etməsin. Son Codex SYSTEM-token fail-fast, QR register/pair müqaviləsi, UI singleton/tab/PIN show/status və log düzəlişləri qorunsun.
3. Release public key native pinned key ilə uyğun olsun. Manifest BÜTÜN son binary build-lərdən SONRA exact hash/size/version/target ilə yaradılsın və build-time imzalansın. Private key yalnız build mühitində owner-controlled path/env vasitəsilə, paketə/loga/source hesabatına daxil edilməsin. Açar yoxdursa təhlükəsiz dayansın; səssiz yeni production trust yaratmasın. Köhnə compromised test açarı qəbul deyil.
4. Signed baseline native verifier ilə təsdiqlə. NSIS payload source düzgün olsun: yenilənmiş service/helper/desktop+manifest/sig+runtime/installer komponentləri. Bir actual Windows x64 `dist/WinKeySetup.exe` yarat. Saxta renamed ZIP və manual PS təlimatı yoxdur.
5. Installer UAC istəyib native SYSTEM SCM xidmətini və recovery-ni qurur, bounded real IPC health yoxlayır. Desktop normal interaktiv istifadəçi kimi açılır. OwnerSid alternativ admin hesabına səhv bağlanmır. Quraşdırma/repair konfiqurasiya və DPAPI-ni korlamır; root protected ACL qalır.
6. Son `--check`/verify-only rejimi: EXE mövcudluğu, PE/installer payload, private-key yoxluğu, baseline signature/hash/version uyğunluğu. Setup-u avtomatik işlətmə, xidmət quraşdırma, ekrana input/lock/unlock/reboot etmə. Başqasının açıq tətbiqini kill etmə; file-lock varsa konkret path və tray-dən çıxış təlimatı ilə dayandır. Sahib özü setup-u açacaq.

## İstifadə rahatlığı
- Terminalda mərhələ/progress, işləyən build əmri, xəta səbəbi; exit code nonzero olduqda növbəti mərhələyə keçmə, köhnə EXE-ni yeni uğur kimi göstərmə.
- Build log `plan/reports/build/` altında redacted saxlanılsın, private key/PIN/auth secret çap edilməsin. Download/tooling uğursuzdursa konkret səbəb; OS/AV-ni deaktiv etmə.
- IDE Run üçün sys.argv-sız normal build; `--check` ayrıca. Yekunda bir actual EXE linki/yolu+ölçü+SHA256, versioned immutable copy və dist/SHA256SUMS.txt. Signed manifestlə uyğun olmayan köhnə artefaktı overwrite edib success göstərmə.
- Backend endpoint real build config-dan gəlsin, localhost/uydurma URL online məhsul kimi verilməsin. WAN endpoint yoxdursa dəqiq TEST/OFFLINE etiketi və bir cümlə blocker ver; buildi dayandırmadan installer hazırlansın. SYSTEM xidmətinin qurulması yalnız səlahiyyət məsələsini həll edir, fiziki unlock hələ operator testi tələb edir.
- Son istifadəçi təlimatı: `python build.py` -> `dist/WinKeySetup.exe` aç -> UAC Bəli -> proqramda lokal PIN saxla -> yeni QR qoş. Source fayllarını əl ilə köçürmək tələb olunmasın.

## Təhvil
Kökdə actual `build.py`, onun çağırdığı installer/build source dəyişiklikləri, uyğun compile/preflight test nəticələri və `plan/reports/PYTHON_BUILD_SETUP_REPORT.md` ver. Mümkünsə buildi bir dəfə sona qədər yoxla; sahibin hostuna install etmə. 'Hazır skript' deyib yalnız plan yazma. Installer hazırdır və real unlock uğurludur iddialarını ayır. Mövcud audit təhlükəsizlik qorunmaları zəiflədilməsin.
