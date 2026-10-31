# Sahibin prioriteti: tək WinKeySetup.exe — indi sınaq üçün hazırla

Sahib texniki ZIP/PowerShell/fayl köçürmə təlimatını rədd etdi. İstədiyi məhsul: bir EXE açır, Windows UAC administrator icazəsi istəyir, hər şeyi özü qurur, sonra proqramda PC adı/PIN/QR göstərilir. Bu tapşırıq əvvəlki batch-lərdən üstün cari prioritetdir. Aralıq audit gözləmə; bütün mümkün implementasiya/build/testi bitir və actual installer ver. Yeni uzun arxitektura/audit dövrəsi açma, işləyən təhlükəsizlik düzəlişlərini saxla.

## 1. Məcburi təhvil
- `dist/WinKeySetup.exe` — actual Windows x64 installer, yalnız bu bir fayl son istifadəçiyə verilir. Mövcud Tauri/Rust desktop/service/helper qorunsun; UI/framework yenidən yazılmasın.
- Installer texnologiyası olaraq mövcud Tauri NSIS və ya uyğun NSIS/Inno Setup seç; source və reproducible build script repoda olsun. Sadəcə EXE adlandırılmış ZIP/self-extract və ardından manual PS təlimatı qəbul deyil. Installer lazımi native/script addımları özü təhlükəsiz çağırmalıdır.
- Faylı build et; yalnız installer scripti və ya 'sonra build etmək olar' nəticəsi vermə. Build tool yoxdursa icazəli workspace tooling ilə hazırlamağa çalış, qalan blocker-i dəqiq göstər, hazır EXE uydurma.

## 2. İstifadəçinin görəcəyi yol
1. WinKeySetup.exe-ni açır, standart Windows UAC 'Bəli' icazəsini verir.
2. Qısa AZ quraşdırma ekranı/progress: komponentlər yoxlanır, qurulur, bağlantı hazırlanır; texniki CLI pəncərələri açılmır.
3. Proqram quraşdırılıb normal istifadəçi hesabında açılır. Avtomatik PC adı (dəyişmək mümkündür), maskalanmış yerli Windows PIN sahəsi, telefonu qoşmaq üçün QR. PIN installerə/serverə göndərilmir.
4. Telefon QR-ni oxudur, həmin PC-yə bağlı mobil Kilidlə/Kilidi aç səhifəsini açır. Local PC approval təsdiqi tələb olunursa proqramın özündə sadə göstərilir.
5. X tray-ə gizlədir; təkrar EXE bir pəncərə; tray aç/çıx; Windows boot service, user login desktop tray avtomatik. İdarənin statusu actual service/gateway vəziyyətidir.

Son istifadəçi ZIP açmır, fayl daşımır, terminal/PowerShell/Python/Node/Rust işlətmir, admin panelə daxil olmur, server/origin/config.json əl ilə düzəltmir.

## 3. Installer hər şeyi özü etsin
- Machine-wide protected ProgramFiles payload; signed slot manifest+signature+service/helper; service-owned protected state/credential və owner SID. UAC yüksəldilmiş alternativ adminin SID-ni səhvən sahib kimi qeyd etmə: ilkin interaktiv istifadəçi/target session doğrulansın.
- WebView2 detection+zəruri Microsoft runtime quraşdırılması. İnternet yoxdursa aydın retry; offline paket seçilərsə bütün runtime daxil olsun. End-user Python/Node tələb etməsin.
- Actual SCM native recovery/service install+auto-start+bounded PID-bound IPC health, baseline initialization, owner binding, DPAPI provisioning; uğursuz addım UI-da dəqiq AZ mətn+incident ID, protected logs.
- Windows Start menyusu/Apps & Features qeydiyyatı; per-user login tray autostart; desktop shortcut seçimi; uninstall və repair. Repair/upgrade əvvəlki işləyən versiya/config/DPAPI-ni korlamasın. Invoke-Rollback mövcud işləyən installı kor-koranə silməsin; transaction/snapshot ilə geri qaytarsın.
- Uninstall service/worker/helper lifecycle-ni bounded dayandırsın, autostart və qısayolları təmizləsin; istifadəçi data/log silinməsi aydın seçim olsun.
- Quraşdırma işi UAC ilə yüksəlir; renderer/normal desktop lazımsız admin kimi işləməsin. Installed path/service/image/hash/ACL/reparse və credential trust qorunmaları zəiflədilməsin.

## 4. Serveri istifadəçiyə qurdurma
- Backend ayrıca operator məhsuludur. Existing authorized gateway endpoint build configuration-da verilsin; clientdə private key/admin secret/Sites bypass olmasın.
- Hazır real public HTTPS endpoint varsa onboarding/QR həmin endpoint ilə işləsin; localhost və ya placeholder URL olan build 'hər şəbəkədə hazırdır' adlandırılmasın.
- Endpoint hələ yoxdursa mövcud audience/production dəyişmədən deploy-ready adapter/artefaktı hazırla və owner üçün tək konkret deploy/hesab blocker-i qeyd et; installer/build işini saxlamadan tamamla. Uydurma Google Sites/VPS göstərişi ilə operator işini end-userə ötürmə. Local test endpoint yalnız açıq TEST build etiketilə və telefonun çatdığı ünvanla sınaq üçündür.
- Backend yoxdursa proqram bunu aydın 'Server bağlantısı hazır deyil' kimi göstərsin; saxta online/QR success yoxdur. Ownerə tək EXE-ni test etmək üçün ver, remote phone funksiyasının blockerini ayrı bir cümlə göstər.

## 5. Sonlu, məqsədli yoxlama
- Actual çıxmış EXE-ni Windows11 x64 clean VM-də Python/Node olmayan mühitdə install -> service health -> normal-user desktop -> repair/reinstall -> reboot/login singleton/tray -> uninstall yoxla. VM yoxdursa NOT_TESTED göstər; şəxsi hostda səssiz xidmət install/reboot/lock etmə.
- Real operatorun manual UAC/install testi üçün bütün build hazır olsun. Son təlimat maksimum 5 sadə addım, bir EXE linki; texniki source/dev commands son istifadəçi təlimatına düşməsin.
- EXE payload private-key yoxluğu, signed baseline native verify, manifest/source+installer hash uyğunluğu. Mövcud audit regression-ləri yalnız dəyişən sahəyə uyğun işlət; hər xırda iş üçün bütün test paketini səbəbsiz təkrarlama.
- Fiziki LOCK/UNLOCK avtomatik testlərdə yoxdur; operator yerli PIN daxil edib manual başladır. Input olmadan health preflight uğursuzdursa ekran kilidlənməsin.
- Authenticode sertifikatı yoxdursa 'unsigned pilot installer' dürüst qeyd et, sertifikat və SmartScreen reputasiyası uydurma; private release signing açarı EXE/ZIP/source report-a daxil olmasın.

## 6. Sonda ver və dayan
- Bir clickable actual `dist/WinKeySetup.exe`, ölçü, SHA256 və build source/script yolu.
- `plan/reports/ONE_SETUP_REPORT.md`: quraşdırılan actual komponentlər, actual test command/exit/raw log, VM/manual/WAN statusu, qalan yalnız real blockers. Eyni vaxtda 'hamısı tamamlandı' və endpoint hazır deyil iddiası olmasın.
- Maksimum 5 addımlıq AZ `dist/NECE_QURULUR.txt`: EXE aç -> UAC Bəli -> Quraşdır -> PC PIN lokal -> QR. Server blocker varsa bu addımı dürüst qeyd et.
- Versioned immutable installer artefaktı da saxla; test/paket yaratma testləri onu səssiz dəyişməsin. STATUS/KNOWN_ISSUES cari məqsəd üzrə yenilə, Codex acceptance qeydlərini dəyişmə.

Məqsəd yeni hesabat dövrəsi deyil: sahibin bir EXE-ni açıb sınaqdan keçirə bilməsidir.
