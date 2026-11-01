# Qəbul vəziyyəti və son inteqrasiya tapşırığı

2026-10-29 Codex üç audit harness-i müstəqil işlətdi: hamısı exit 0, əvvəlki səkkiz dar reproduksiya artıq yoxdur. Bu təhlükəsizlik alt-düzəlişləri qəbul edilir. Tam məhsul/boot recovery hələ qəbul edilmir.

## İndi əsas işi tamamla, yeni dar helper testləri ilə yekunlaşdırma
1. Installer native SCM dispatcher-ə qaytarılıb: yaxşıdır, ancaq native xidmət supervisor-u çağırmır. apps/winkey_service/src/main.rs-də real recovery/update launch yolu yoxdur. Python skriptini paketə qoymaq avtomatik boot recovery deyil. Sabit native recovery host + signed slot initialization/pinned key + candidate probation + reboot/kill checkpoint + validated LKG start actual installer/SCM yoluna bağlanmalıdır. Python/Node-suz yeni PC tələbi qalır.
2. service_supervisor.py check_pipe_health CreateFileW/WriteFile/ReadFile-i sinxron çağırır. timeout_sec bloklayan ReadFile-i dayandıra bilməz. Bounded overlapped I/O/cancel/drain və fault-injection nonreply server testi, partial-write/read framing tələb olunur. LKG health və sonrakı crash monitor da işləməlidir.
3. test_extracted_zip_clean_layout.py istifadəçinin mövcud `python` və `cryptography` paketindən istifadə edir; yalnız import/banner və installer DryRun yoxlayır. Bu clean-PC runtime və SCM testi deyil. Mövcud sübutu REAL_PROCESS_IMPORT/DRY_RUN adlandır; Windows11 clean VM no-Python install/start/stop/reboot/repair/uninstall sübutu və ya NOT_TESTED təqdim et.
4. Qalan end-to-end müqavilə: yeni production gateway ilə actual native register/proof/QR/phone claim/local PC approval/agent polling/result/revoke; mock gateway testi yeni gateway inteqrasiyasının əvəzi deyil. Owner-only admin və public mobile Sites/HTTPS deploy, installer-first telemetry actual sender, app/service/helper update delivery əvvəlki əsas tapşırıq üzrə source+integration sübutları ilə tamamlanmalıdır.

## Dürüst təhvil
17/17 PASS yalnız sadalanan testləri təsdiq edir. Yalnız fiziki unlock qalıb demə. FINAL_BATCH_REPORT-də hər əsas tələb üçün actual product entrypoint, source, integration test və IMPLEMENTED/PARTIAL/BLOCKED göstər. Mövcud ZIP-i test/pilot artefaktı kimi etiketlə. Repo/installer native service dəyişiklikləri compile/build/test edilsin; şəxsi hostda install/lock/reboot yoxdur. Bütün mümkün qalıqları bir toplu icrada tamamla; yalnız maneənin adını yazıb digər mümkün işləri saxlamamalısan.
