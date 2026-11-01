# WebSocket batch — Codex müstəqil audit

Tarix: 2026-11-01. Qərar: **CHANGES_REQUESTED**. Deploy/setup qəbulu verilmir.
Bu audit production kodunu dəyişmir. Yalnız izolyasiya edilmiş lokal probe və
Docker build/start işlədildi; native service, fiziki kilid və PIN testi edilmədi.

## Faktiki sübut

- `python scripts/codex_ws_batch_audit.py`: **exit 1, 3/3 regression FAIL**.
  Real ASGI/HTTP/WebSocket, ayrıca SQLite fixture, yalnız mock əmrlər.
  Xam çıxış: `plan/reports/websocket/codex_audit_probes.log`.
- `node scripts/codex_mobile_ws_audit.cjs`: **exit 1**. Serverin verdiyi real
  mobile HTML işlədildi. Authenticated WS açıldıqdan sonra 0 command WS frame,
  1 HTTP command POST müşahidə edildi. Idle timerin təkcə mövcudluğu traffic
  sübutu deyil: `wsConnected` guard-ı var; finding əmr göndərilməsinə aiddir.
- `docker build -t winkey-ws-audit:local .`: **exit 0**.
  Image start: **exit 1 — ModuleNotFoundError: deploy.gateway_service**.
- Gemini load JSON-un cari ölçüsü: 200 socket, dispatch p95 təxminən 2718 ms,
  p99 təxminən 2881 ms. Bu, actual browser/client və PostgreSQL yük sübutu deyil.
  Hesabatdakı köhnə rəqəmlərlə cari evidence fərqlidir; son run-a uyğunlaşdırılmalıdır.
- PostgreSQL testinin skip edilməsi PASS qəbul edilmir. Əvvəlki HTTP handler
  testlərinin keçməsi yeni ASGI routing/WS müqaviləsini ayrıca təsdiqləmir.

## Tapıntılar

### WS-01 / P1 — Docker image başlamır
`Dockerfile` yeni `gateway_service.py`, `asgi_app.py`, `websocket_hub.py` fayllarını
COPY etmir. `deploy/vm/server.py` onları import edir. Image build-in PASS olması
runtime start demək deyil. Lokal Linux container start ilə xəta təsdiqləndi.

### WS-02 / P1 — Eyni əmr birdən çox agentə və retry zamanı yenidən verilir
`websocket_hub.py:136` bütün agent socket-lərinə broadcast edir. Eyni cihaz üçün
iki authenticated agent eyni command ID-ni aldı (real probe FAIL).
`asgi_app.py:209,552` enqueue nəticəsinin yeni/tamamlanmış olmasını ayırmadan
push edir; `UPDATE ... delivered` şərtsizdir. Completed əmri eyni request ID ilə
retry etdikdə yenidən command frame gəldi (real probe FAIL). State regressiyası
və HTTP poll/WS/reconnect yarışları üçün atomik claim/lease yoxdur.

### WS-03 / P1 — Son istək və nəticə təsdiqi tam deyil
Dispatch ilə hər şey dərhal delivered olur, native unbounded FIFO-ya yığılır;
həqiqi execution start/claim/sequence yoxdur. Artıq agent növbəsində olan, amma
başlamamış köhnə istəklər coalesce edilmir. `asgi_app.py:532-534` DB commit
nəticəsi `ok` False olsa da result push/ACK edir. ACK bütün agentlərə gedir.
Mobil `command_result` handler-i command ID-ni yoxlamadan pending-i silir;
köhnə nəticə yeni istəyi silə bilər.

### WS-04 / P1 — Mobil transport və diaqnostika geriləyib
Sağlam WS olsa da sendCommand HTTP POST edir; WS yalnız auth üçün send olunur.
Nəticə gözləməsi `wsConnected` olduqda dərhal return edir, mövcud busy/finally
axını ilə WS state machine vahid deyil. Browser testi sağlam WS halında HTTP
command POST-u təsdiqlədi.
`asgi_app.py:319` telemetry üçün accepted=integer qaytarır, telefon isə event-ID
array gözləyir. Probe `1 != [event_id]` ilə FAIL. Client `id/code/action/request_id`
sxemi serverdə başqa field adları ilə oxunur; ID yoxdursa hər retry yeni random
event yaradır. Offline outbox silinmir, hadisə çoxalır, real error məlumatı itir.

### WS-05 / P1 — Native outbox və dedup crash-safe deyil
`ws_transport.rs:59,70,81`: korlanmış oxunuş boş list olur; yazı xətası udulur;
fs::write atomik/durable deyil. Execution save və network ACK remove eyni JSON-da
kilidsiz read-modify-write edir: ACK yeni nəticəni itirə bilər.
`handled_commands` yalnız RAM-dadır, restartda itir və limitsiz böyüyür.
`channel()` unbounded-dır. Crash-before/after-execute recovery states yoxdur.

### WS-06 / P1 — Native lifecycle və əlaqə sağlamlığı boşluqları
`connect()` üçün bounded DNS/connect/handshake yoxdur; timeout yalnız bağlantıdan
sonra qoyulur. Sleep 30s-dək stop-u saxlayır. Aktiv loop config/secret dəyişməsini
yenidən oxumur. Execution worker queue-dakı işlərə pause yoxlamır.
Heartbeat timeout/pong tracking olmadığı üçün blackhole bağlantı diri qala bilər.
Fallback-da nəticənin HTTP ilə etibarlı göndərilməsi də ayrıca sübut edilməyib.

### WS-07 / P1 — Server WS sərhədləri və slow-consumer teardown natamamdır
Origin/rate/heartbeat deadline yoxlamaları görünmür. App 64KB yoxlaması frame
tam qəbul edildikdən sonradır; Uvicorn transport limiti təyin edilməyib.
QueueFull yalnız is_active=False edir, amma bloklanmış writer/receiver-i bounded
bağlamır. Reconnect/idle görünüşündə liveness və backpressure testləri yetərli deyil.

### WS-08 / P1 — Real PostgreSQL/artefakt və test müqavilələri tamamlanmayıb
PG skip nəticəsi hesabatda PASS kimi təqdim olunub. Yeni ASGI+WS ilə real PG,
Docker runtime, reconnect/ACK loss/agent restart, native queue/dedup/outbox və
stop/pause/config dəyişməsi üçün sübut yoxdur. 200 socket sınağı faydalıdır,
amma bütün A–F paketlərinin bitdiyini sübut etmir.

## Qəbul üçün

`plan/GEMINI_WEBSOCKET_REVISION.md` bir batch-də icra edilməli, regression-lar
istehsal kodunu həqiqətən çağıran testlərlə bağlanmalıdır. Testi silmək, assertion-u
zəiflətmək, problemi sadəcə mock ilə örtmək və ya FAIL/SKIP-i PASS adlandırmaq olmaz.
Fiziki Windows unlock hələ NOT_TESTED-dir; backend testləri bunu əvəz etmir.
