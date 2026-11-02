# WinKey Pro — növbəti iş günü üçün təhvil

Tarix: 2026-11-03, Asia/Baku. İstifadəçi bu günlük işi bitirib. Növbəti agent əvvəl bu sənədi oxusun; köhnə Gemini reviziyalarını yeni tapşırıq kimi yenidən icra etməsin.

## 1. Ən vacib nəticə

**İlk real worker OTA keçidi logda təsdiqləndi: 0.1.14 → 0.1.15.**

Mənbə: `C:\ProgramData\WinKey\logs\worker_stages.log`:

```text
1793655489 pid=35628 stage=UPDATE_DOWNLOAD_DONE code=rel_id=rel_0.1.15 prev_ver=0.1.14 new_ver=0.1.15 dur_ms=22342
1793655489 pid=35628 stage=UPDATE_STAGE_DONE code=rel_id=rel_0.1.15 prev_ver=0.1.14 new_ver=0.1.15 dur_ms=410
1793655489 pid=35628 stage=UPDATE_ACTIVATE_DONE code=rel_id=rel_0.1.15 slot=slot_b ver=0.1.15 dur_ms=50
1793655495 pid=35628 stage=UPDATE_PROBATION_PASSED code=rel_id=rel_0.1.15 ver=0.1.15 dur_ms=5128
1793655495 pid=35628 stage=UPDATE_COMMIT_DONE code=rel_id=rel_0.1.15 slot=slot_b ver=0.1.15 dur_ms=5
```

Yükləmə 22.342 s, staging 410 ms, aktivləşmə 50 ms, sağlamlıq sınağı təxminən 5.1 s. Bu rəqəmlər bir konkret cəhddir, performans zəmanəti deyil.

**Desktop GUI-nin 0.1.15-ə keçməsi hələ istifadəçi və ya proses yoxlaması ilə təsdiqlənməyib.** Son screenshot desktop/worker 0.1.14, server 0.1.15 idi və yuxarıdakı uğurlu loglardan əvvəl çəkilmişdi. Yalnız worker commit-ini bütün məhsulun tam qəbulu sayma.

## 2. Layihə və Git

- Əsas iş qovluğu: `D:\rust desk mobil kilid acma` — özü Git repo DEYİL.
- Sanitizasiya edilmiş repo: `.github-publish`; remote `https://github.com/kral14/winkeypro.git`, branch main.
- Təhvil hazırlananda checkout təmiz idi, son commit: `e948e28 Release WinKey Pro 0.1.15`.
- Kökdəki dəyişikliklərin hamısının son commit-də olduğunu fərz etmə. Xüsusən son `scripts/prepare_upgrade.ps1` düzəlişi daha yeni ola bilər; source ilə checkout-u müqayisə et. Kor overwrite/pull etmə.
- İstifadəçi Gemini-yə böyük işi gördürür, Codex audit və kiçik düzəlişləri edir. Minimum token, konkret nəticə istəyir. Təkrar natamam audit/build dövrlərindən narazıdır.

## 3. Qorunmalı düzəlişlər

### Build və push

- `build.py`: metadata yazılması LF baytları ilədir; əvvəl CRLF üzərinə write_text Windows CR əlavə edib Cargo.toml-u korlayırdı.
- `build_started_at = time.perf_counter()` müddət ölçür; silinmiş t0 səbəbindən final NameError düzəldildi. Faktiki main yolu mock build/no push ilə yoxlanıldı.
- `stage_webview2_loader`: Cargo `build/webview2-com-sys-*/out/x64/WebView2Loader.dll` çıxışından DLL-i release EXE yanına köçürür. EXE və DLL PE machine uyğunluğu yoxlanır. Manifest/NSIS/ZIP eyni DLL-i alır.
- `push_to_git.py`: root-da git add/push əvəzinə `scripts.release_pipeline` istifadə edir, `.github-publish` checkout-a təhlükəsiz export edir, hazır imzalı ZIP-i təkrar istifadə edir. `--check` yerli yoxlama, push yoxdur.
- `.gitattributes` və `push_to_git.py` export ROOT_FILES siyahısındadır. Keys/config/runtime data Git-ə çıxmamalıdır.
- `build.py` susmaya görə **build + Git push** edir; VM auto-deploy-a səbəb ola bilər. `--local-only` build edir, push etmir; `--check` preflight; `--push-only` hazır paketi göndərir.

### Server paketi

- `deploy/update_repository.py` allowlist-ə dəqiq `WebView2Loader.dll` əlavə olundu. Əks halda signed 0.1.11 ZIP `E_PACKAGE_UNEXPECTED_FILE` ilə rədd edilirdi.
- Eyni real imzalı ZIP disposable repository-də əvvəl rədd, düzəlişdən sonra qəbul və loader download PASS verdi. Lokal `test_update_push_delivery.py`: 7 PASS.
- Server `[BUNDLED_UPDATE_READY] version=...` yazdıqda paket qəbul olunub; bu müştərinin quraşdırdığı demək deyil.

### Native host/worker — əsas OTA səbəbləri

`apps/winkey_service/src/main.rs`:

1. LKG worker spawn edildikdə `committed=false`, `start_instant=Instant::now()` yenilənir. Sağlamlıq yolu yalnız `!committed` şərtindədir; əvvəl `!switched_to_lkg` əlavə şərti bərpa olunmuş worker-i yoxlamadan kənarda saxlayırdı.
2. Host SYSTEM/Session 0-dan worker IPC-sinə STATUS göndərirdi, interaktiv policy Session 0-ı rədd edirdi. Yeni dar yol yalnız OS tokeni uğurla alınan SID `S-1-5-18`, sessiya 0 üçün **STATUS/PAUSE/RESUME/STOP** qəbul edir. Credential/pairing/provision/input və digər əmrlər bu yolda qadağandır. İstifadəçi policy-si zəiflədilməyib.
3. `supervisor_channel_tests`: dar command siyahısı və OS identity mənfi hallarını yoxlayır. Service testləri son bu düzəlişdə **25 PASS** idi. Əvvəlki Gemini hesabatındakı 24 sayı köhnədir.

Bu host düzəlişləri installer ilə bir dəfə tətbiq edilməli idi. İstifadəçi 0.1.14 qurdu; sonra 0.1.15 üçün yuxarıdakı real worker OTA təsdiqi alındı. Yenidən səbəbsiz Setup quraşdırma istəmə.

### Installer file-lock düzəlişi — son yerli iş

`scripts/prepare_upgrade.ps1` əvvəl Stop/Wait/taskkill xətalarını udub uğur qaytarırdı; Setup `Program Files\WinKey Pro\winkey_service.exe` üzərinə yaza bilmirdi.

Codex:
- yolu məlum olmayan prosesi ad əsasında öldürməyi çıxardı;
- yalnız təsdiqlənmiş install/versions yolu olan proses üçün taskkill nəticəsi və prosesin çıxışı yoxlanır;
- EXE-lər və WebView2Loader üçün 15 saniyəlik FileAccess.ReadWrite/FileShare.None yoxlaması əlavə etdi;
- kilid qalırsa `E_UPGRADE_FILES_LOCKED` ilə fail-closed çıxır;
- PowerShell parser PASS, UTF-8 BOM qorundu. **Canlı installer təkrar sınağı edilmədi.**

Avtomatik xidmət/proses dayandırma və fiziki lock/unlock testini istifadəçinin aktiv kompüterində icra etmə. Quraşdırma xətasında “Ignore/Yoxsay” tövsiyə etmə.

## 4. Növbəti işlərin prioriteti

1. **Əvvəl nəticəni bağla:** desktop və worker həqiqətən 0.1.15-dir? GUI slot_b-yə keçib? “Yenilənmə təsdiqləndi” görünür? Desktop köhnədirsə signed slot selection/handoff/singleton yolunu yoxla. Əvvəl real log/proses sübutu topla, build istəmə.
2. **Update statusunu doğru və canlı göstər:** requested → downloading → verifying/staging → activating → probation → committed/rollback/deferred/error; son error, səbəb, versiya və vaxt. İndiki UI əvvəlki rollback mesajını yeni cəhd boyunca göstərərək istifadəçini çaşdırır. Worker qəbul olunması ilə GUI və ümumi məhsul qəbulunu ayır. Proqres üçün faktiki telemetriya istifadə et, uydurma faiz yox.
3. **Windows release ilə server deploy-u ayır:** istifadəçi hər Windows build-də VM deploy istəmir. Hazırda ZIP Git-də Docker image-a daxil olur; bu OTA üçün server deploy yaradır. Mövcud `/admin/updates/publish` endpoint-i ilə hazır imzalı paketi işləyən serverə göndərmə axını hazırlanmalıdır. `build.py --publish SERVER` mövcuddur, lakin istifadəçinin tələb etdiyi sadə/default axına inteqrasiya TAMAMLANMAYIB. Server kodu dəyişəndə deploy, yalnız Windows paketi dəyişəndə upload+WS bildirişi. Admin açarını Git/loga çıxarma; mövcud HTTP üzərindən admin secret göndərməni səssiz başlatma, əvvəl təhlükəsiz transport/config planı qur.
4. **UI dizaynı:** istifadəçi Gemini-nin dizaynını daha səliqəli görmək istəyir. Tapşırıq `plan/GEMINI_DESKTOP_UI_REDESIGN.md`, hesabat `plan/reports/DESKTOP_UI_REDESIGN_REPORT.md`. Navbar və profil var; scrollbarsız səhifələr tələb olunur. Sadəcə overflow:hidden və 10px şriftlə gizlətmək qəbul deyil. Daha aydın status iyerarxiyası və kompakt update kartı lazımdır; çox böyük boş kart görünürdü. İstifadəçi screenshot İSTƏMİR, işlək preview linki istəyir. Link 127.0.0.1:5175 idi, Gemini verdikdə server artıq dayanmışdı. Codex serveri başlatmağa cəhd etdi, IAB connection refused verdi; aktual işləkliyi yenidən yoxla, görünüşü görmədən bəyəndiyini iddia etmə.
5. **Installer mətnləri:** Gemini UTF8 BOM + -UnicodeOutput UTF16LE/nsExec + Segoe UI əlavə edib. `scratch/test_ps51_streams.py` Codex tərəfindən işləndi: PS5.1 stdout/stderr UTF8 və UTF16 Azərbaycan hərfləri PASS. Dörd .ps1 BOM PASS. Real installed Setup görüntüsü/axını Codex tərəfindən təsdiqlənməyib. Hesabat `plan/reports/INSTALLER_TEXT_FIX_REPORT.md`. Köhnə screenshot-lar və əvvəlki UI sözləri encoding problemini göstərirdi.

## 5. Açarlar və təhlükəsizlik

- Runtime pinned public key: `56524c1040e3a8309e938332037d0a0167cc2da30761abcfb77c93a899ad61da`.
- Açarın tapılmadığı əvvəlki BLOCKED hesabatları köhnəlib: istifadəçi digər iş kompüterindəki uyğun açarı verdi. Codex uyğunluğu kriptoqrafik yoxlayıb `deploy/keys/prod_release_ed25519_key.bin` və public hex faylını bərpa etdi; əvvəlki fayllar eyni keys qovluğunda backup-dadır.
- Private key burada və ya başqa hesabatda təkrar yazılmasın. İstifadəçi onu söhbətdə açıq paylaşıb: uzunmüddətli təhlükəsiz key rotation hələ görülməlidir. İndi pinned key-i səssiz dəyişib işlək OTA-nı pozma.
- DB URL və admin secret də session tarixində mövcuddur; onları oxuma/çap etmə. Production PIN/DPAPI vault/config/token fayllarını kopyalama və loga çıxarma.
- GitHub Actions bir cəhddə billing/account-lock səbəbindən job başlamadan dayanmışdı. Bu Windows kod compile xətası deyildi. VM deploy paneli ayrıca işləyir.

## 6. Test sərhədləri və davam etmə qaydası

- Production lock/unlock axını işləyən etalondur; bu sessiyada fiziki lock/unlock testi icra edilməyib. Yeni host ilə bütün fiziki funksiyaların sınağını “PASS” kimi yazma.
- Unit/mock/harness testi bütün SCM/OTA sübutu deyil. Real worker OTA yuxarıdakı konkret logla sübut olunub; desktop hələ açıqdır.
- `tests/test_signing_publication_contract.py` başlıq/hesabatı Codex tərəfindən düzəldildi: Python verifier + test ZIP helper + repository testidir. Production NSIS/packager/Rust staging/desktop selection zəncirini çağırmır. 6 testi və trust-boundary 2 testi keçmişdi; “full end-to-end” adı ilə təqdim etmə.
- C:\ProgramData\WinKey\update_journal.json SYSTEM/Admin ACL ilə qorunur; tool escalation belə real UAC admin token vermədiyi üçün AccessDenied ola bilər. ACL-i boşaltma. User admin PowerShell-də yalnız jurnal mətnini çıxara bilər. Oxuna bilən logs/worker_stages.log-dan başla.
- Quraşdırılmış xidmətə toxunmadan Rust testləri apar; sandbox temp WinError5 verirsə bunu code failure sayma, isolated test-i normal icazə ilə təkrarla.
- Əvvəl yeni user mesajını nəzərə al, bu sənəd köhnəlmiş statusdan üstündür. İşi dayandırmaq, əlavə build, real push/deploy barədə user-in cari icazəsinə əməl et. İstifadəçi bu günlük işi bitirib: hesabatdan sonra aktiv dəyişikliklərə davam etmə.

## 7. Əlavə: terminal Copy ikonu

`tools/terminal-copy-all`, paket `dist/TerminalCopyAll-1.0.1.vsix`. Antigravity IDE `.antigravity-ide` profilinə rəsmi CLI ilə quraşdırılıb. Əvvəl səhv `.antigravity` profilinə və unsupported terminal/title menyusuna yazılmışdı. 1.0.1 view/title (view==terminal) və terminal/title/context istifadə edir. İkonun son istifadəçi təsdiqi yoxdur. Bu WinKey backend işindən ayrıdır.
