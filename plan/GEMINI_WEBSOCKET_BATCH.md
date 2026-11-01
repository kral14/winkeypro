# Aktiv tapşırıq: WebSocket ilə çoxistifadəçili WinKey

Tarix: 2026-11-01. İcraçı Gemini, son auditor Codex. Sahib bu işi bir batch
kimi icazələndirib: aşağıdakı A–F paketlərini aralıq təsdiq gözləmədən bitir.
Köhnə A–K stage qapıları bu tapşırığı saxlamır. Sonda READY_FOR_AUDIT hesabatı ver.
Gemini-ni sahibi ayrıca işə salır; bu fayl özü heç bir agentə dispatch deyil.

## 0. Əvvəl oxu və işlək vəziyyəti qoru

- `docs/PROJECT_LAYOUT.md`, `README.md`, `deploy/vm/README.md`.
- `plan/GEMINI_RULES.md` təhlükəsizlik/sübut qaydaları; scope üçün BU fayl üstündür.
- Aktiv məhsul: `apps/desktop_tauri`, `apps/winkey_service`, `pc_agent`, `deploy`.
- `legacy/` və `experiments/` arxiv/istinaddır; aktiv məhsul kimi yenidən qoşma.
- GitHub-a sanitizasiya edilmiş checkout `.github-publish/`-dır; kök ayrıca Git repo deyil.
- Son Windows quraşdırıcısı `dist/WinKeySetup.exe`; işlək əvvəlki versiyalar
  `backups/installers/`, ilk işlək unlock ZIP-i `backups/` altındadır.
- Hazır PIN, Default→Winlogon, UIAutomation, ctypes INPUT paylaşımı, SYSTEM/session
  yoxlamaları, dar IPC ACL, trusted helper PID, tray singleton və recovery-ni qoru.
- Helper onedir + `helper_runtime` formatındadır; hər runtime faylı imzalı
  manifestlə yoxlanır. `installer/winkey_helper.spec` yerini və bu modeli qoru.
- `run.py` və `build.py` gündəlik girişlərdir. Yeni run faylları yaratma.
- PIN/private key/admin secret/DATABASE_URL/token payload-u prompta, koda,
  screenshot-a və loqa daxil etmə. Connection string environment-də qalır.

## A. Server: daimi WebSocket transportu

1. Eyni Docker portunda (paneldə PORT=8080) HTTP + WebSocket işləsin. İkinci
   ictimai port və ayrıca əl ilə başladılan server tələb etmə.
2. Müştəri sayı artımına uyğun async server seç (məsələn ASGI/uvicorn + Starlette).
   Uzunömürlü socket başına blocking HTTP thread saxlayan yarımçıq həll etmə.
3. Mövcud registration/challenge/pairing, admin, mobil səhifə, diagnostics,
   healthz, update və HTTP müqavilələrini saxla. Biznes/auth məntiqini HTTP və WS
   üçün iki ayrı fərqli versiyada təkrarlama; ortaq service qatına ayır.
4. PostgreSQL source of truth qalır. Blocking DB/Win32 işlərini event loop-da
   işlətmə. Connection pool, transaction sərhədləri, UTC epoch double precision
   və SQLite lokal/test uyğunluğunu saxla. Səssiz boş SQLite fallback olmasın.
5. Agent device_secret ilə, telefon mövcud cihazla məhdud mobile session ilə
   autentifikasiya olunur. Brauzer auth mesajını ilk WS frame-də göndərə bilər;
   URL/query-də token olmaz. Auth deadline, message-size limit, rate/backpressure
   və Origin yoxlamaları olsun. Naməlum rola/admin səlahiyyətinə yol vermə.
6. HTTP üçün ws, HTTPS üçün wss avtomatik seçilsin; TLS certificate yoxlamasını
   söndürmə. Reverse proxy upgrade üçün konfiqurasiya/təlimat əlavə et.
7. Server çoxsaylı agent/telefon bağlantılarını device/session üzrə ayrı saxlasın.
   Bir ləng müştəri başqalarının event loop/queue-sunu bloklamasın.

## B. Əmr və nəticənin çatdırılması

1. PC socket-ə qoşulur; əmr PostgreSQL-də commit olunduqdan sonra ona push edilir.
   Telefon da command accepted/delivered/executing/result/status dəyişikliklərini
   push alır. Hər saniyə DB/HTTP yoxlaması etmə.
2. Son istifadəçi istəyi üstün olsun: yalnız hələ icraya verilməmiş köhnə əmrlər
   superseded edilir. İcradakı unlock-u yarıda kəsmə; sonra ən son istəyi tətbiq et.
3. Intent ardıcıllığı/sequence və idempotency ID-ləri ilə gecikmiş/out-of-order
   frame və HTTP retry köhnə istəyi yenidən üstün etməsin. Yeni tap ayrı intentdir;
   transport retry eyni ID-dir. Bir neçə telefon üçün sıra qaydasını sənədləşdir.
4. Eyni əmr reconnect/retry zamanı iki dəfə icra olunmasın. Agent nəticəni lokal
   məxfi məlumatsız durable outbox-da saxlasın, server ACK-dən sonra silsin.
   Server commit olub cavab itərsə, eyni nəticə retry-si zərərsiz qəbul edilsin.
5. Delivered/executing əmri əlaqə qopdu deyə kor-koranə yenidən PIN yazdırma.
   Agent restart/naməlum nəticə ssenarisinin açıq state machine-i olsun.
6. Admin və telefondan revoke WS bağlantılarına da dərhal tətbiq olunsun.
   Daimi cütləşmə expires_at=0 qaydası və IDOR sərhədləri qalsın.

## C. Native agent və desktop

1. `apps/winkey_service` yeni transportu işlətməlidir: yalnız server/frontend-də
   WS əlavə edib köhnə 600ms agent HTTP poll-unu aktiv saxlamaq qəbul deyil.
2. WS receive/heartbeat işi uzun Win32 unlock əməliyyatının arxasında dayanmasın.
   Əmrlər tək execution worker-də ardıcıl, şəbəkə loop-u ayrıca işləsin.
3. Stop/pause/reconfigure zamanı bounded shutdown; paralel iki aktiv agent loop-u
   və dublikat WS/proses/tray yaranmasın. Qoşulma ayarı dəyişəndə köhnəsi bağlansın.
4. Reconnect exponential backoff+jitter, təxminən 1–30s. Heartbeat 25–30s,
   hər heartbeat üçün DB auth/write etmə; state dəyişikliklərini push et.
5. Köhnə EXE üçün HTTP endpointləri keçid uyğunluğu olaraq qalır. Yeni EXE
   sağlam WS vaxtı /agent/poll çağırmır. WS qırılanda gizli 1s HTTP fırtınası
   yaratma; HTTP fallback varsa məhdud, ölçülə bilən və açıq şəkildə göstərilsin.

## D. Mobil, admin və avtomatik diaqnostika

1. Yeni mobil UI sağlam WS vaxtı /status və /commands nəticəsini periodik HTTP
   soruşmasın. Son tap saxlanır; offline/connecting vəziyyəti dürüst göstərilir.
2. Telefon yenidən görünəndə/şəbəkə dəyişəndə socket bərpa edilir. Token URL-də
   olmur; mövcud pairing yaddaşı və daimi sessiyalar itməsin.
3. Mövcud mobil offline diagnostics outbox-ı qoru və WS ilə uyğunlaşdır.
   Telefon və admin ekranda ms/xəta ilə yanaşı eyni correlation ID göstərsin.
4. Tap→socket send→server receive→DB commit→agent receive→execute start/end→
   result commit→phone render mərhələləri ölçülsün. Müxtəlif host saatlarını
   birbaşa çıxıb saxta dəqiqlik yaratma: monotonic müddət + host-local timestamps.
5. Connection/reconnect/heartbeat timeout/queue superseded/dedup/revoke/error
   hadisələri redacted loglarda olsun. PIN, token, QR query, raw stack/payload yox.
6. Admin real online/offline, cihaz/socket sayı, queue və error timeline göstərsin.
   Admin özü hər saniyə bütün DB-ni oxuyan yeni yük mənbəyi olmasın.

## E. Məcburi real test və yük sübutu

- Mövcud `tests/test_vm_gateway.py`, `tests/test_gateway_concurrency.py`,
  `tests/test_postgres_gateway.py`, `tests/test_mobile_transport.cjs` müqavilələrini
  yeni quruluşa uyğun saxla və işlət; HTTP uyğunluğu səssiz itməsin.
- Real WS handshake/auth; saxta/expired/revoked token; cross-device IDOR;
  invalid JSON, oversize message və auth-before-command bloklanması.
- Real telefon-simulator→gateway→agent-simulator→result zənciri. Yalnız `mock`
  action! Gerçək hostu avtomatik kilidləmə/PIN yazma. Fiziki nəticə NOT_TESTED.
- Eyni ID-nin təkrarı, out-of-order intents, son istək, artıq icradakı əmrin
  qorunması; iki telefon və paralel agent/reconnect ssenariləri.
- Qəbuldan, DB commit-dən, icradan və result commit-dən əvvəl/sonra disconnect;
  server restart və agent restart; ACK itməsi; nəticə outbox-ının bərpası.
- Slow reader, bounded queues, heartbeat timeout, backoff storm, pause/stop.
- İzolyasiya edilmiş lokal testdə əvvəl 100, imkan varsa 500–1000 socket.
  Faktiki N/müddət, CPU/RAM, p50/p95/p99 dispatch və end-to-end ms göstər.
  Yük testini sahibin production VM/bazasına göndərmə.
- Sağlam idle WS-də agent və telefon HTTP poll sayı sıfır olsun; DB query/write
  sayı və heartbeat tezliyi ölçülsün. Sadəcə HTTP 200/compile PASS kifayət deyil.
- Yeni native service release compile, helper resource/ABI və imzalı runtime
  preflight, Docker build + real PostgreSQL testləri. Gizli açar tələb edən
  addımı açıq blocker kimi yaz; saxta imza/ACL bypass tətbiq etmə.

## F. Təhvil

1. Bütün paketləri bir batch-də tamamla; orta mərhələdə audit cavabı gözləmə.
2. `plan/reports/WEBSOCKET_BATCH_REPORT.md` yaz: dəyişən fayllar, arxitektura,
   protocol/state machine, test əmrləri+exit code, real/mock/fiziki ayrımı,
   yük nəticələri, açıq qüsurlar və deploy/EXE keçid qaydası.
3. Xam redacted sübutları `plan/reports/websocket/` altında saxla. Auditdən
   keçməyən işi ACCEPTED və ya production-ready adlandırma.
4. Bir həqiqi işlək lokal/dev/demo başlatma yolu ver. Windows istifadəçisi üçün
   nəticə yenə tək setup olmalıdır; onlarla faylı əl ilə köçürmə tələb etmə.
5. Kod/build/test lokal icrasına icazə var. Codex auditindən əvvəl public deploy,
   stable release, GitHub push və hostda service/installer/real input icrası etmə.
   Mənbə yollarını yenidən qarışdırma; kökə yeni launch/test/prototip faylı səpmə.
6. Sonda READY_FOR_AUDIT və konkret hesabat yolunu ver; Codex müstəqil yoxlayacaq.
