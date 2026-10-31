# Cari əsas tapşırıq: Sites server + əvvəlki dashboard + native PC + işlək QR + iki rejim

## Sahibin dəqiq qərarı — əvvəlki dar task-lardan üstündür
Sahib lokal run.py serverindən və onun bağlananda admin/telefonun dayanmasından imtina edir. İndi əsas nəticə real deploy edilmiş Sites serveri, daim açılan əvvəlki admin dashboard, quraşdırılmış native proqramın serverə qoşulması və real telefon QR pairing-dir. Bu zənciri birlikdə tamamla; xırda kosmetik qalıqları qeyd et, aralıq audit üçün dayanma. Təhlükəsizlik trust/PIN qorunmalarını zəiflətmə. Sahib bu tapşırıq çərçivəsində lazımi server deploy və proqram bağlantısının hazırlanmasını istəyir; tələb olunan connector/hesab imkanı yoxdursa faktiki maneəni göstər, deploy uydurma.

## 1. Actual Sites deploy — lokal Python serveri deyil
- Mövcud sayt: https://winkey-remote-nesib.beigesong32770.chatgpt.site
- Əsas mənbə `web_remote/`: əvvəl repository/AGENTS/yerli Sites instructions oxu. Platformaya uyğun Worker/backend+DB migrations+auth+assets deploy et. `deploy/gateway_production_server.py` HTTPServer-i Sites-də işləyəcək kimi göstərmə; onun müqaviləsini platformanın native backend-inə port et.
- Mövcud sahib panelinin mənbəyi `web_remote/app/dashboard.tsx`, route `/admin`-dir. Əvvəlki peşəkar dizaynı qoru, demo fixture cihazlar/timeline/action-ları real server DB/API-yə bağla. 8788-dəki sadə HTML paneli əsas dashboard əvəzi deyil.
- Private owner admin və public mobile/API sərhədləri actual Sites imkanına uyğun olsun. Lazımdırsa public gateway/mobile və private admin iki ayrı Sites layihəsi kimi deploy edilsin. Native EXE ilə mobil istehlakçıdan sahibin ChatGPT loginini istəmə; bypass/service admin secret-i EXE/QR/client JS-ə qoyma.
- Admin yalnız sahib `nesib20@gmail.com` üçün; istifadəçilər PC proqramından qeydiyyat/telefon pairing edir, hamının adminə girişi yoxdur. Public/private audience-ni qarışdırma, admin API-ni açma. Sayt sahibi hesabına giriş/deploy icazəsi yoxdursa konkret connector/action tələbini bildir; domain və ya sertifikat alma.
- Server native proqramdan asılı deyil: run.py/PC bağlı olanda da admin HTTPS səhifəsi işləyir. Serverdə PC offline görünür; PC sönükdürsə unlock mümkün olduğu kimi təqdim edilməsin.

## 2. Vahid proqram, GUI-dən iki rejim
Proqramda aydın iki seçim:
**İnternet:** Telefon istənilən internet şəbəkəsindən public HTTPS mobil səhifəyə qoşulur; server authenticated PC outbound polling/relay ilə lock/unlock verir, actual nəticə qayıdır. Port forwarding/router sazlaması yoxdur.
**Eyni Wi‑Fi (Lokal):** Telefon PC-nin lokal xidmətinə qoşulub həmin PC-ni idarə edir. Lokal endpoint Run/Python deyil, əsas quraşdırılmış WinKey native xidmətinin həyat dövrünə bağlıdır. UI bağlansa da xidmət/yerli endpoint işləyir. Local transport da eyni cihaz identity/ownership/PIN/service broker qorunmalarından istifadə edir.
- İstifadəçi terminal/server/origin/config yazmır. Rejimi GUI-dən dəyişir; actual endpoint/QR/status yenilənir. Gizli automatic mode fallback ilə başqa cihaz/rejimə əmr getməsin.
- Hər iki rejim eyni mərkəzi cihaz qeydiyyatına/admin dashboard-a bağlıdır. Eyni PC üçün ayrı mode-a görə yeni cihaz ID/key yaradılmır. Yenidən quraşdırma/repair və release/dev identity sərhədi açıq olsun.
- Lokal rejimdə internet yoxdursa əvvəlcədən etibarlı pairing ilə LAN işləməsi mümkündür; mərkəzi dashboard həmin anda yeni hadisə ala bilməz. Signed/authenticated durable outbox sonradan sync edir. İlk online enrollment tələbi və offline başlanğıc qaydası açıq olsun; internetsiz anda cloud-da 'canlı log' uydurma.
- LAN endpoint üçün public səhifədən private IP fetch-in secure-context/PNA/CORS/TLS real browser məhdudiyyətlərini nəzərə al. Telefonun sadəcə QR ilə açdığı actual URL+transport işləsin; iPhone/Android yolu fiziki yoxlanmayıbsa NOT_TESTED göstər. LAN auth-suz command/PIN ötürmək və firewall-u ümumi söndürmək olmaz. Lazımi dar private-network firewall qaydası yalnız installer UAC zamanı tətbiq edilsin.

## 3. Native startup -> registration -> QR -> phone -> actual result
- PC tətbiqi açılan kimi actual HTTPS serverə qoşulur, yerli public/private key identity qorunur; server nonce + device-bound proof ilə register/reconnect olur. Key rotation/revoke/restore müqaviləsi dəqiqdir; 401-i offline sayıb saxta key/QR yaratma.
- Revoke edilmiş cihaz yalnız sahibin explicit reactivate/re-enrollment əməliyyatı ilə bərpa edilir. Native GUI konkret vəziyyəti göstərsin, QR yaratmadan əvvəl autentifikasiya uğuru təsdiqlənsin. PIN və səlahiyyət yoxdur deyə saxta 'hazırdır' yazma.
- QR yalnız serverdə/yerli trusted endpoint-də həqiqətən yaranmış 120s one-use enrollment məlumatından hazırlansın; code->device->mode binding, expiry/replay/local-PC-confirmation və mobil device-scoped session məcburidir. QR/history/logda PIN/admin/bypass/private key yoxdur.
- Telefon expired/revoked/wrong-device köhnə sessiyanı aydın göstərsin; yeni QR claim uğurlu olanda əvvəlki cached target-dən çıxıb yeni confirmed target-ə keçsin. Səhifə açılmadı, pairing rədd edildi, PC offline, worker cavabı gəlmədi ayrı mesajlardır.
- PC SYSTEM native xidmətinin actual çalışması, owner/session binding, service-owned credential DPAPI, helper signature/ACL, Default curtain->Winlogon focus/input və actual WTS unlock verification qorunsun. Normal user dev worker Secure Desktop unlock deyil; UAC ilə SYSTEM xidməti actual setup-da qurulur. Səlahiyyət problemi həll edilmədən real unlock success yazma.
- Proqram X ilə tray-ə keçir; tək instance və autostart qorunsun. Admin server UI singleton çıxışından və build/run-dan asılı deyil.

## 4. Real admin dashboard və diaqnostika
- Əvvəlki dashboard real bütün qeydiyyatlı cihazları, son heartbeat, rejim, versiya, actual PIN-ready boolean, online/offline, command queued/delivered/completed/failed və redacted incident timeline göstərsin. PIN-in özü görünmür.
- Native UI/service/helper/installer/pairing/reconnect/command failures serverə authenticated hadisə göndərsin; gateway request error-ları da eyni device/command correlation-a bağlansın. İstifadəçi token və QR tam mətnini loglama.
- Crash/offline üçün bounded durable-before-send outbox, ACK dequeue/dedup və restart retry actual native service-dən işləsin. Admin cihazın hansı mərhələdə dayandığını görsün. PC/telefon serverə heç çatmayıbsa onu təsdiqlənmiş server xətası kimi uydurma; local incident sonra sync olunsun.
- Server səviyyəsində namespace/tenant/device ownership, CSRF/CORS/rate limit, replay, auth və admin trust əvvəlki auditlərdən qorunsun. Debug bypass və compromised signing açarı deploy/build artefaktına keçməsin.

## 5. Yeni istifadəçiyə bir setup/build yolu
- Kök `build.py`: son source -> release service/helper/desktop -> pre-signed manifest -> installer -> `dist/WinKeySetup.exe`. Server public endpoint-i safe build configuration-da olsun, son istifadəçi ünvan yazmasın. End-user Python/Node tələb olunmasın.
- Setup UAC ilə SYSTEM service, recovery/signed slots, WebView2, autostart, dar ACL/LAN qaydasını özü qursun; desktop normal owner hesabında açılsın. Düzgün production payload ilə repair/upgrade/uninstall qorunsun.
- Owner özü build və real setup testini edəcək. Şəxsi hostda səssiz install/reboot/lock/unlock yoxdur. Run dev yalnız optional developer rahatlığıdır, məhsul/server asılılığı deyil.

## 6. Sonda işlək nəticəni sübut et — test sayını yox
Bir toplu icrada deploy+native/build+integration işlərini bitir. Sadəcə arxitektura planı/dar CLI testləri/əvvəlki PASS siyahısını təkrar təqdim etmə.
- Actual public HTTPS mobile/API və actual private admin URL; Sites deploy revision və real health DB roundtrip sübutu. Deploy yoxdursa BLOCKED, 'deployed' deyil.
- Actual native PC -> deployed gateway register -> server-confirmed QR -> telefon/mobile claim -> PC local approval -> nonphysical command -> native worker result -> admin timeline -> revoke/reconnect integration. Test client-in success=True göndərməsi native sübutu deyil.
- İnternet və LAN rejim dəyişməsi eyni device identity ilə; PC UI bağlansa service qalır; Run tam bağlı olanda cloud admin açılır. Ayrı şəbəkə/fiziki telefon/VM yoxdursa test sərhədlərini dürüst qeyd et.
- Real LOCK/UNLOCK yalnız operator opt-in ilə; bu mərhələ üçün bir setup + maksimum 5 addım təlimat hazırla. Sandbox testini fiziki unlock qəbuluna çevirmə.
- Yeni immutable installer/build hashları; `plan/reports/CLOUD_LAN_DELIVERY_REPORT.md` actual IMPLEMENTED/PARTIAL/BLOCKED matrisi və raw evidence. Kosmetik kiçik məsələləri ayrıca saxla; təhlükəsizlik bloklarını gizlətmə.

Sahibin prioriteti: real deploy edilmiş sayt/dashboard + proqramın ona qoşulması + telefonda işlək QR. Bu nəticəyə çatmadan 'bütün işlər tamamlandı' deyib dayanma; mümkün qalan işləri paralel olaraq özündə davam et, yalnız həqiqi hesab/platforma maneəsini dəqiq bildir.
