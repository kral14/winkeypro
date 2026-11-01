# WebSocket audit reviziyası — hamısı bir batch

Əvvəl `plan/audit/WEBSOCKET_BATCH_ACCEPTANCE.md` və oradakı xam probe loqlarını oxu.
Başlanğıc spesifikasiya `plan/GEMINI_WEBSOCKET_BATCH.md` qüvvədədir.
Qərar CHANGES_REQUESTED-dir. WS-01–08-i aralıq audit gözləmədən birlikdə bağla.

1. Dockerfile/context bütün yeni runtime modullarını götürsün. Real Linux image
   ilə HTTP health + real WS auth/mock E2E işlət; import-only/build-only kifayət deyil.
2. Bir cihaz üçün tək aktiv agent/claim sahibi və atomik DB dispatch qur. Yeni
   command insert, pending→claimed→executing→terminal keçidləri WS/HTTP/reconnect
   üçün ortaq olsun. Completed/failed/superseded retry-si yenidən dispatch olmasın.
   Agent socket-i qopanda enqueue edilən frame-i uğurlu çatdırılma sayma.
3. Queue-da başlamamış əmrləri son intentlə coalesce et. Delayed/out-of-order
   request/frame üçün sequence qaydasını həqiqətən implement et. İcradakı əmri
   yarıda kəsmə. Result yalnız həmin claim/device və DB commit doğrulandıqdan sonra
   ACK alsın. Duplicate terminal result state-i və timestamp-i dəyişməsin.
4. Mobil sendCommand/nəticə/status vahid WS state machine olsun. Healthy WS-də
   command HTTP POST=0, status/result HTTP polling=0. Pending yalnız matching
   command/intent result ilə silinsin; köhnə result son intenti silməsin.
5. `/mobile/telemetry` əvvəlki id/code/action/request_id schema-sını, allowlist,
   uzunluq/duration limitlərini, IDs array ACK və DB dedup-u qorusun. Offline
   outbox testini yeni ASGI serverə qarşı da işlət, sərbəst payload/secret yazma.
6. Native journal/outbox atomik davamlı yazı, synchronization, yazı xətasına
   açıq fail-closed davranış və restart-safe bounded dedup ilə qurulsun. ACK/save
   race, truncated file, process kill nöqtələri real disposable child-lərdə sınansın.
   Unbounded channel yerinə bounded/coalescing icra növbəsi olsun.
7. Connect/DNS/handshake/read/write və shutdown bounded olsun; interruptible
   backoff+jitter; config/credential switch köhnə socket-i bağlasın; pause yeni
   queued işi başlamasın. Heartbeat/pong timeout + slow-reader cancellation olsun.
   Origin, auth-before-message, message/rate limitlərini transportda da tətbiq et.
8. `scripts/codex_ws_batch_audit.py` regression-larını düzəldilmiş kodda PASS et.
   İlk duplicate-agent probe-u iki agent varsa yalnız birinin frame almasını
   gözləyir; iki frame aldığı üçün FAIL-dir. Bu invariantı çıxarma. Completed retry və telemetry ACK
   assertion-larını zəiflətmə. Mobil audit script-i healthy WS command frame=1,
   command HTTP POST=0 gözləyir. Testə actual rendered HTML verilir.
9. Real lokal PostgreSQL konteynerində yeni ASGI/WS testlərini işlət; env yoxdursa
   test nəticəsi SKIP/NOT_TESTED-dir, PASS deyil. Production bazasına yük göndərmə.
10. Yeni browser, native, server və Docker testlərini source hash-ləri ilə bağla.
    Load test üçün actual N, idle traffic, DB ops, CPU/RAM və p50/p95/p99 saxla.
    Hazırkı p95~2.7s səbəbini ölç; tək medianı seçib sürət iddiası etmə.

Təhvil: `plan/reports/WEBSOCKET_REVISION_REPORT.md` + yeni xam sübutlar
`plan/reports/websocket/revision1/`. Hər WS-01–08 üçün dəyişən kod, real test,
exit code, qalan risk yaz. Əvvəlki evidence-i üzərinə yazma.
Son status READY_FOR_AUDIT; public push/deploy, installer/service quraşdırması,
gerçək lock/unlock/PIN və geniş process/service kill etmə. Host xidməti portu
məşğuldursa test namespace/port/process izolyasiyasını düzəlt, xidməti söndürmə.
