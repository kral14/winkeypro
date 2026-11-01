# Gemini — WinKey qalan bütün işlər: yekun toplu implementasiya

## Sahibin son təsdiqi və məqsəd

Sahib yeni desktop-u yoxladı: əvvəl şikayət etdiyi tray/singleton/pəncərə açılışı yerindədir. Bu UI lifecycle təsdiqidir, Windows unlock/Sites/update qəbulu deyil. Tray/dizaynı yenidən qurma. İndi bütün qalıqları bir dəfəyə işləməyini istəyir; alt-tapşırıqdan sonra audit gözləyib dayanma. Codex xırda düzəliş/testlərə yardım edir, sonda toplu audit edəcək.

Əvvəl oxu: STATUS.json, KNOWN_ISSUES.md, reports/codex/COMPLETION_BATCH_REVIEW.md, CODEX_FIXES_HANDOFF.md, ARCHITECTURE.md, DIAGNOSTICS_SUPPORT.md, UPDATE_ROLLBACK.md, TEST_MATRIX.md və stage B–K. Report “complete” sözünə yox, source/faktiki testə əsaslan. Əvvəlki tək-alt-tapşırıq stop-ları bu sənədlə əvəz edilir. Production publish/signing alışları/şəxsi host sistem dəyişiklikləri üçün konkret native/owner icazə sərhədi qalır.

## 1. Quraşdır→qeydiyyat→telefon→real nəticə zənciri

- Qorunan installer/WebView2/ProgramFiles payload/helper/ProgramData ACL/owner SID/service-start/real IPC health/repair/uninstall bütöv olsun. Yeni PC-də Python/Node quraşdırmaq tələb olunmasın; yalnız user EXE/setup və telefon browseri.
- Gateway origin və əlaqə qurulması GUI/setup-da mümkün olsun, manual JSON/CLI edit tələb olunmasın. Hazır mobil frontend actual API-yə bağlı qalsın. Sadəcə ZIP-ə EXE qoymaq server provisioning sübutu deyil.
- Device register/proof/QR→phone claim→native pending approval→local PC approval→device-scoped mobile session→LOCK/UNLOCK→actual WTS result→revoke bütün native UI/API yolunda işləsin. Login/resume/expiry/offline/failure halları aydın olsun.
- PIN yalnız PC masked input→trusted service IPC→service-owned DPAPI→ephemeral verified helper yolu ilə istifadə edilir. No argv/env/server/log/plain disk credentials. PC adı dəyişməsi registration deyil; status actual gateway/service/session state-dən gəlsin.
- Existing reference engine/backupı qoru. SYSTEM token və doğru user session/owner SID, ayrı Default curtain və Winlogon worker, focus/UAC/Hello/one-attempt/WTS verify guard-lar saxlanılsın. Wrong PIN üzrə avtomatik retry yoxdur. Bütün kernel I/O və child lifecycle timeout/cleanup-u real error yollarda işləsin.
- Əsas real unlock hələ işləmirsə onun səbəbini isolate et: credential fetch/SCM identity/token/session/desktop/curtain/focus/input/verification üçün redacted stage timeline yaz. Saxta success və ya error-u functional PASS kimi təqdim etmə.

## 2. Tray/startup qalanları

- Sahibin təsdiqlədiyi singleton/show/exit qorunsun. Sabit disabled “Aktiv” yazısı real service statusuna bağlansın; idarəni dayandır/başlat action-u authenticated service command ilə işləsin. UI exit və service stop/uninstall fərqi aydın olsun.
- Windows boot service və user-login tray auto-start; duplicate login/EXE launch 1 instance; sleep/wake/reconnect/stop/resume. Installer restart/repair bu davranışları pozmasın.
- Tray testsinin exact-path/no-kill Codex düzəlişini qoru; başqasının açıq prosesi kill edilmir. Status və real runtime screenshot/log sübutu saxla.

## 3. İnternetdən public mobil + owner-only admin

- İki Sites layihəsi arxitekturasını actual platforma imkanları ilə uyğunlaşdır. Public/mobile gateway consumer üçün ChatGPT sahib hesabı istəməsin, private admin yalnız sahib hesabına bağlı qalsın. Shared Sites bypass/admin key client/EXE/QR-a düşməsin.
- Register/heartbeat/command/result/telemetry/admin üçün deploy edilə bilən backend və DB migrations hazırla. Local Python test gateway istehsal Sites backend-i əvəz etmir.
- Ayrı test layihəsi/preview deploy mümkündürsə həmin mühitdə real HTTPS/mobile/native inteqrasiya testlərini tamamla. Mövcud production audience/private açar dəyişməsin. Deploy connector/hesab icazəsi yoxdursa onun dəqiq adını və hazır artifact-i göstər; qalan kod/build/testləri işləməyə davam et.
- Session/auth/CSRF/CORS/CSP/expiry/revoke/rate limit/atomic claim/replay/durable state, 2 tenant IDOR və owner admin access mənfi testləri. Test account/key source/log/release-ə qoyulmasın. QR secret URL tarixçəsindən təmizlənsin, PWA cache command/token sızdırmasın.
- Android/iPhone manifest/icons/install təlimatı; ayrı şəbəkədə endpoint reachability. Localhost emulyasiya WAN və fiziki telefon testi adlandırılmasın.

## 4. Avtomatik update, rollback və release

- Git source/CI build/test/release artifact/manifest işi hazır olsun. Repo/host sahibi seçilməyibsə workflow və local pipeline hazırla, qərarı açıq siyahıya yaz; owner təsdiqi olmadan remote repo/push/public release yoxdur.
- Real app/service/helper bundle update check/download/verify/stage/activate/health/commit/rollback məhsula bağlansın. Signature pinned release public key, tüm binary hashes/version/target binding; tamper/traversal/reparse/old-invalid bundle fail-closed.
- Sabit boot recovery launcher candidate-dən əvvəl jurnal+known-good təsdiqi ilə xidmət başladıb izləsin. Wrong PIN/offline/gateway5xx rollback səbəbi deyil. User data backward compatibility və update zamanı credential qalıqları qorunsun.
- Real child-process launch və checkpoint process-kill/restart: interrupted download/slot switch, corrupted journal/slot, invalid signer, candidate crash-loop, no-valid-slot. String/model testini boot recovery kimi təqdim etmə.
- Recovery self-update ayrı installer repair yoludur. Authenticode/provider sahibi təsdiqlənməyibsə unsigned test label, ready signing pipeline və owner action list ver; private signing key source-a qoyulmasın.

## 5. Installer-dən adminə diaqnostika

- Bootstrap first code→stage start/finish/error; ayrı reporter/collector; bounded durable outbox (məhsul retention/size policy); sender/retry/ACK/persistent dedup və crash/offline replay real məhsula bağlı olsun.
- UI/service/installer crash, early installer error, disk limit və gateway offline hallarında hadisələr sonradan gəlsin. UAC denial vs no-code-before-execution fərqi; suspected stall səbəb kimi uydurulmasın.
- Owner admin: device/version/install stage/incident timeline, support təlimatı/known issue, signed-fix release ilə əlaqə. Arbitrary remote shell yoxdur.
- Localhost HTTP P95-ni internet event-to-admin SLA kimi təqdim etmə. Actual HTTPS sender→ingest→admin readback latency seriyası mövcud test mühitində ölçülsün; secrets/raw memory dumps yığılmasın.

## 6. Uyğunluq, manual pilot və sənədlər

- Windows11 x64 standard user/new install/WebView2/reboot/login tray/sleep-wake/language/focus/uninstall/reinstall test matrisi. Win10/ARM dəstəyi ayrı real sertifikasiya yoxdursa vəd edilməsin.
- Test VM varsa quraşdırma/SCM/SYSTEM və repair/update testlərini orada icra et. Şəxsi hostu səssiz kilidləmə/reboot/service install etmə. Fiziki LOCK/UNLOCK yalnız konkret operator opt-in və recovery planı ilə; defaults nonphysical qalır. PIN-i mesajla istəmə.
- Fiziki operator addımı lazım olduqda bütün source/build hazır və preflight edilmiş olsun: local gateway/HTTPS origin, service health, owner binding, vault ready, phone approved/online, logs. PIN-less preflight uğursuzdursa ekran kilidlənməsin.
- Read-only/sandbox test əvəzi real privileged test deyil. NOT_TESTED ilə NOT_IMPLEMENTED ayrı. Security rejection PASS real unlock PASS deyil. Poll loop nəticə gəlməzsə FAIL, daimi error PASS deyil.
- İstifadəçi üçün 1 səhifə AZ təlimat: hansı bir setup faylını açsın, PC PIN lokal harada yazılır, telefon QR necə qoşulur, real result necə görünür, pause/quit/uninstall/recovery nə edir. Local dev commands son istifadəçi setup tələbini əvəz etməsin.

## İcra qaydası və sonda təhvil

Əvvəl qısa qalanlar checklist-i yarat və implementasiyaya davam et. Hər kiçik addımdan sonra “hazırdır, dayanırıq” demə. Kompilyasiya/test xətalarını özün düzəlt. Bir permission/account/physical maneəsi digər source/build/test işlərini saxlamasın. Tam code hazır deyil deyə bunu “yalnız fiziki test qalıb” adlandırma.

Codex-in hazır minimal maska helper build/source və nonphysical test düzəlişlərini geri yazma. Eyni faylda yeni Codex dəyişiklikləri varsa read-before-edit ilə qoruyub konfliktləri bildir. Mövcud evidence-ni overwrite etmə: plan/reports/final_batch/ qovluğundan istifadə et.

Sonda plan/reports/FINAL_BATCH_REPORT.md:
- B–K üzrə dəqiq IMPLEMENTED/PARTIAL/BLOCKED və artifact/source/test linkləri; acceptance yalnız Codexindir.
- Real istifadəçi yolunun actual nəticəsi, qalan mock və operator-only addımlar.
- Command/exit/redacted raw logs/hash; model/API/process/VM/physical/WAN kateqoriyaları.
- Yeni bir installer/test ZIP+SHA256, lazım olan backend/mobile/admin deploy artifact-ləri.
- Real P0/P1, account/deploy/signing qərarları və test edilməyən mühitlər; owner-ə verilməli minimum konkret addımlar.
- KNOWN_ISSUES və STATUS yenilə, köhnə qəbul qeydlərinə toxunma. Qəbul edilməyən sistemi PRODUCTION_READY/COMPLETE kimi adlandırma.

Bütün mümkün source/build/test işləri bitəndə toplu nəticə təqdim et və dayan. Sonra Codex ümumi auditi edib qalan konkret səhvlərin düzəlişinə özü də qoşulacaq.
