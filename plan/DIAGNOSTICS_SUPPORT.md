# Diaqnostika, quraşdırma izləməsi və admin dəstək sistemi

Tələb sahibi tərəfindən 2026-10-28 tarixində əlavə edilib. Status: məcburi məhsul tələbi; hələ implementasiya yoxdur.

## Məqsəd və real vaxt sərhədi
İstifadəçi installerə başladığı andan hər addım üçün start/finish/error hadisəsi yaradılır. Sağlam internet/server olduqda kritik hadisə dərhal göndərilməyə çalışılır; ilkin qəbul hədəfi admin panelində P95 <=5 saniyə, idarə olunan sınaq şəbəkəsində ölçülür. Bu, bütün şəbəkələr üçün zəmanət deyil.
Offline olduqda hadisə əvvəl yerli davamlı outbox-a yazılır, bağlantı gələndə avtomatik göndərilir. İnternet/elektrik yoxdursa və ya OS proqramı başlamadan bloklayıbsa anında göndərmək mümkün deyil.
SmartScreen/antivirus EXE-ni heç işə salmayıbsa proqram daxili hadisə yarada bilməz. Serverdə yalnız download müşahidəsi ola bilər; bunu install_started və ya konkret antivirus xətası kimi təqdim etmə.
Watchdog son heartbeat/stage vaxtından yalnız SUSPECTED_STALL çıxara bilər; sübut olmayan səbəbi dəqiq xəta kimi yazmamalıdır.

## Quraşdırma addımları
1. bootstrap_started — installer kodu həqiqətən işləməyə başlayıb.
2. requirements_check — OS/build/arxitektura, disk, dəstəklənən imkanlar.
3. runtime_check / webview2_install — runtime hazırdırmı, quraşdırma başladı/bitdi/exit code.
4. elevation_requested / elevation_result — UAC mərhələsi, rədd edilmə və cancel ayrıca.
5. package_verify — signature/hash.
6. files_install — mərhələ və müddət.
7. service_install / service_start / service_health — SCM və IPC nəticələri.
8. credential_storage_ready — yalnız nəticə; PIN, məzmun və uzunluq yoxdur.
9. device_registration — gateway nəticəsi, status/trace.
10. pairing_ready / pairing_completed — QR məzmunu və session tokeni yoxdur.
11. install_completed — yalnız bütün məcburi addımlar təsdiqlənəndə.
12. install_failed / cancelled / interrupted / suspected_stall — fərqli vəziyyətlər.

Qeydiyyatdan əvvəl device_id yoxdur: random install_run_id və məhdud anonymous bootstrap trace istifadə olunur. Qeydiyyatdan sonra authenticated proof ilə install trace cihaza bağlanır. Ad/username/IP cihaz identity-si sayılmır.

## Proqram işləyərkən
- Service/worker/UI/helper startup, version və lokal health.
- Windows session/desktop keçidi, fokus təsdiqi, command mərhələsi, icra nəticəsi; input simvolları yoxdur.
- Network disconnect/reconnect, backend status sinfi, timeout, retry sayı.
- Crash marker, exit code və son təhlükəsiz mərhələ.
- Update check/download/verify/stage/activate/health/rollback/quarantine hadisələri.
- Quraşdırıcı, service və UI üçün vahid event sxemi və correlation.
- Collector xidmət başlayana qədər bootstrapperdə, sonra sabit supervisor/ayrı reporter prosesində işləyir. Təkcə çökən GUI-nin exception handler-inə etibar edilmir.

## Hadisə müqaviləsi
Məcburi: schema_version, event_id, install_run_id, device_id(nullable), operation_id, component, version, stage, event_type, severity, local_time, sequence_no, error_code(nullable), native_exit_code(nullable), duration_ms(nullable).
Server qəbul vaxtını ayrıca əlavə edir. OS build/architecture/runtime compatibility yalnız allowlist edilmiş sahələrdir.
error_code sabit maşın kodudur, məsələn E_WEBVIEW2_INSTALL, E_SERVICE_START, E_INPUT_DESKTOP, E_GATEWAY_TIMEOUT. Raw exception/URL/config mətnini birbaşa serverə göndərmə.

## Outbox və göndərilmə
- Hadisə əvvəl durable bounded queue-a yazılır, sonra göndərilir.
- At-least-once delivery; server event_id ilə deduplicate edir.
- Sequence/local timestamp + server received_at ilə hadisə sırası saxlanır.
- Kritik hadisəyə sürətli flush; adi loglara batch/rate-limit və backoff.
- Disk limiti/retention: ölçülən məhsul qərarı; ilkin təklif hər install/PC üçün 20 MB və 14 günlük yerli queue. Kritik records üçün rezerv və dropped_count.
- Disk dolu, process kill və abrupt power loss test edilir; collector əsas tətbiqi bloklamamalıdır.
- Ack olmayan hadisə silinmir. Restartdan sonra queue bərpa olunur.
- Telemetry outage mövcud təhlükəsiz local operation və recovery-ni dayandırmır; update health xətası ilə qarışdırılmır.
- Token expiry/revoke zamanı sübutlu refresh yolu olmalıdır; hamıya eyni telemetry private key paylanmır.

## Endpoint və məlumat qorunması
- Pre-registration endpoint yalnız append-only, ölçü/müddət/tezlik məhdud bootstrap session verir; heç bir command/admin/read hüququ yoxdur.
- Anonymous əvvəlki hadisələr unverified kimi işarələnir; saxta paket verisi ilə etibarlı cihaz kimi qəbul edilmir.
- Qeydiyyatlı device yalnız öz hadisələrini fərdi credential/proof ilə göndərir.
- Device-scope token admin error siyahısını və başqa cihazın logunu oxuya bilmir.
- Collector yalnız konkret HTTPS gateway endpointinə qoşulur; redirectlə secret başqa hosta göndərilmir.
- PIN/password, QR pairing secret, device private key, Sites bypass, cookies, access/recovery/signing tokenləri göndərilmir.
- Raw memory dump avtomatik upload edilmir: PIN/token yaddaşda ola bilər. Standart avtomatik hesabat redacted structured event/stack metadata-dır. Əlavə dump yalnız ayrıca idarə olunan, məlumatı aydın göstərən dəstək prosesi ilə.
- Windows username, email, tam şəxsi fayl yolları, serial/MAC/hardware fingerprint və ekran məzmunu default toplanmır.
- Installer ilk telemetriyadan əvvəl qısa disclosure/razılıq seçimi verir. İstifadəçi üçün local-only diaqnostika seçimi varsa, admin həmin cihaz barədə uzaqdan hesabatın məhdud olduğunu dürüst görür.
- Retention/delete/audit siyasəti owner-private admin tərəfində tətbiq olunur.

## Admin paneli
Quraşdırmalar → install run seç → canlı mərhələ timeline, son hadisə, müddət, versiya və dəqiq error_code.
Mövcud statuslar: not_started/started/in_progress/completed/failed/cancelled/interrupted/suspected_stall/offline. Müşahidə olunmayan installı failed/completed kimi uydurma.
Filtrlər: versiya, Windows build/arxitektura, mərhələ, xəta kodu, vaxt və cihaz. Repeat incidents deduplicate/group edilir.
Kritik problem üçün paneldə incident; email/push xarici bildirişləri ayrıca sahib seçimi ilə, özbaşına mesaj göndərmə.
Support package yalnız redacted export; kim baxdı/kim qərar verdi audit olunur.

## Problemin həlli dövrü
1. Admin error_code, tətbiq/Windows versiyası, timeline və son düzgün mərhələni görür.
2. Məlum xəta üçün versiyalı knowledge-base təlimatı hazırlayır, təsdiqləyir və həmin uyğun cihaz/versiyalara göstərir.
3. Tətbiq təlimatı yerli göstərir; istifadəçi təhlükəsiz addımları yerinə yetirir.
4. Kod problemi varsa admin/komanda düzəliş hazırlayır → test/audit → imzalı release → canary/stable update.
5. Yeni hadisə ilə problemin həll olunduğu təsdiqlənir; incident bağlanır.

Təlimat alma remote shell/PowerShell icra icazəsi deyil. Admin qeydinə yazılan mətn avtomatik komanda kimi icra edilmir. Avtomatik remediation gələcəkdə lazım olarsa ayrıca məhdud, imzalı əməliyyat siyahısı və audit gate-i tələb edir.

## Gemini üçün test və qəbul
- Installer service-dən əvvəl bilərəkdən fail olur; admin son mərhələ və kodu görür.
- GUI/worker crash zamanı ayrı collector hadisəni və son stage-i çatdırır.
- Offline install xətası → reboot → internet: hadisələr itmir, təkrar görünmür.
- Dəqiq native failure ilə inferred suspected_stall UI-də ayrı görünür.
- Sağlam sınaq şəbəkəsində event→admin P95 ölçülür; ölçülməyibsə real-time qəbul olunmur.
- Token/PIN canary dəyərləri event payload, local log, DB, export və release artifactlərində aşkar edilmir.
- Rate-limit/oversize/forged bootstrap/device isolation testləri.
- Telemetry endpoint 5xx/offline və disk dolması lock/unlock və rollback sistemini çökdürmür.
- Admin təlimat→tətbiqdə göstərilmə→həll təsdiqi dövrü.
- İlk EXE launch-dan əvvəl bloklanan ssenari üçün dürüst məhdudiyyət və lokal troubleshooting təlimatı.

Mərhələlər: B minimal before-service proof; D bootstrapper/service collector; E gateway ingest/admin timeline; F qeydiyyata trace bağlama; H/I release/crash/rollback correlation; J fault/privacy/end-to-end audit. Sonradan əlavə dekorativ log işi deyil, ilk installer spike-dan arxitekturaya daxildir.

