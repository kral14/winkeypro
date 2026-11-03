# WinKey Pro — admin idarəetmə mərkəzinin genişləndirilməsi

## Məqsəd və mövcud vəziyyət

İstifadəçi mövcud admin panelinin araşdırılmasını və lazımi genişləndirməni istəyir. Tam hazır işlək lokal önizləmə linki ver; screenshot tələb olunmur. İş böyük vahid paketdə tamamlansın, hər kiçik hissədən sonra dayanma.

Codex kod baxışı (2026-11-03):
- Faktiki `/admin` HTML: `deploy/gateway_production_server.py::get_admin_html`; root dashboard: `deploy/vm/dashboard.html`.
- Production ASGI route-ları: `deploy/asgi_app.py`; DB/business qaydaları: `deploy/gateway_service.py` və PostgreSQL adapteri.
- Mövcud imkanlar: admin secret girişi, cihazlar, worker/latest versiyası, lock/PIN readiness, revoke/activate/delete, son 100 telemetry hadisəsi.
- `/admin/devices` bütün cihazları bir dəfəyə, `/admin/telemetry` yalnız ən son 100 hadisəni verir. UI 5 saniyəlik setInterval ilə yenilənir.
- Admin WebSocket auth/metrics infrastrukturu var; mövcud imkanları yenidən araşdırıb istifadə et.
- `apps/winkey_service/src/diagnostics.rs` update mərhələlərini yerli `logs/worker_stages.log` faylına yazır. Bu faylın avtomatik serverə çatdığını fərz etmə; faktiki transport-u sübut et.

## 1. Aydın və peşəkar panel

Mövcud real admin backend-i üstündə bölmələr: Ümumi baxış, Cihazlar, Yenilənmələr, Hadisələr/Diaqnostika. Sabit navbar/sidebar, aydın başlıqlar, uyğun boşluqlar və oxunaqlı mətn. Desktop tətbiqinin “heç vaxt scrollbar olmasın” tələbi bu böyük admin cədvəllərinə kor tətbiq edilməsin: pagination və lazım olan sahədə normal əlçatan scroll istifadə et. Mobil/dar ekran da işləsin.

Ümumi baxış: qeydiyyatlı/online/offline/revoked cihaz sayı, son dövrün xəta sayı, son imzalı release, pending/failed/completed update sayı. ACTIVE qeydiyyat statusunu ONLINE adlandırma. “Son 100 qeyd” sayını bütün sistem statistikası kimi göstərmə. Verilənlər yoxdursa dürüst empty/unknown/stale vəziyyəti göstər.

## 2. Cihazlar və detal səhifəsi

- Server-side axtarış: ad/device ID; filtr: online/offline, status, versiya, xəta/update vəziyyəti; stabil sort və bounded pagination.
- Online: aktiv WS bağlantısı və son heartbeat vaxtı əsasında, freshness qaydası ilə. Son görünmə tam tarix+saat və zaman zonası ilə göstərilsin.
- Desktop, worker və mövcud olarsa host versiyasını ayrı göstər. Bildirilməyən dəyəri worker-dən uydurma. PIN yalnız “hazır/yoxdur/naməlum” metadata-sı olsun.
- Cihaz detalı: son command-lar, real nəticə, cihazın telemetry timeline-ı, update cəhdləri, pairing metadata sayı/statusu və son əlaqə. Token/QR/private key/PIN göstərmə.
- Mövcud revoke/activate/delete davranışlarını qoru. Revoke ilə delete fərqi izah edilsin; təsdiq dialoqu və actual HTTP response/error işlənməsi olsun. Uğursuz əməliyyatdan sonra saxta uğur göstərmə. Adminə avtomatik lock/unlock və gizli uzaq kod icrası əlavə etmə.

## 3. Yenilənmələr — əsas prioritet

- Cari server release version/id/yayım vaxtı, imza yoxlanmış metadata və paket mövcudluğunu göstər.
- Cihaz başına queued/requested/download/stage/activate/probation/commit/rollback/deferred/error; hədəf/əvvəlki/aktiv versiya, son event/freshness, konkret səbəb/error code və müddətlər.
- `BUNDLED_UPDATE_READY` və ya package upload cihazın quraşdırdığı demək deyil. Worker COMMITTED ilə desktop keçidini ayrı göstər. Köhnə rollback mesajı son uğurlu update-i örtməsin; history saxlanılsın.
- Yerli host update diaqnostikasını təhlükəsiz schema ilə serverə çatdır. SYSTEM host → qorunan yerli bounded outbox → enrolled worker transport → authenticated server ingest kimi mövcud arxitekturaya uyğun yol seç; session/ACL sərhədini zəiflətmə. Restart/offline sonrası retry+dedup və bounded retention olsun. Durations yalnız faktiki ölçü olsun, uydurma faiz göstərmə.
- Son həqiqi sübut: worker 0.1.14→0.1.15 COMMITTED (təhvil sənədində log var). Bunu fixture/demo məlumatı kimi canlı serverə yazma.
- Mövcud `/admin/updates/publish` üçün UI upload bölməsi əlavə oluna bilər: yalnız admin, ölçü limitləri, pinned imza/hash/version yoxlaması, progress və aydın publish nəticəsi. Cari trusted package qaydalarını zəiflətmə. Admin secret-i URL-ə/loga salma. Paket dəyişməyəndə server deploy tələb etməyən yayınlama axını saxla. Canlı serverə test publish etmə.

## 4. Hadisələr və performans diaqnostikası

- Server-side zaman aralığı, device, severity, component, error code və correlation/command/update ID filtrləri, cursor/pagination və indekslər.
- Əmr timeline-ı: telefon tap/request/server acceptance/worker receipt/execution/result/display. Müxtəlif cihaz saatlarını çıxıb səhv network duration hesablama; server receipt vaxtı və eyni clock-un measured duration-larını düzgün ayır.
- Installer install_run_id üzrə mərhələlər və konkret xəta. Hadisə payload-ına limit/allowlist, redaction və XSS-safe render.
- “Yenilənmə yoxdur”, favicon 404 və internet skanlarını real kilid/update uğursuzluqları ilə qarışdırma; raw hadisəni saxlamaqla filtr/collapse tətbiq et.
- Redaktə edilmiş JSON/CSV export və copy; yalnız mövcud authorized filtr nəticələri, pagination/ölçü limiti və CSV formula-injection qoruması. PIN/token/session secret/DB URL daxil edilməsin.

## 5. Backend, canlı yenilənmə və təhlükəsizlik

- Admin sahibə məxsusdur; ordinary account/mobile/agent admin API və WS datalarına giriş ala bilməz. Bütün yeni endpoint-lər serverdə autentifikasiya yoxlasın, UI düyməsini gizlətməklə kifayətlənmə. XSS, injection və cross-device access mənfi testləri daxil olsun.
- Mövcud admin secret modelini səbəbsiz yenidən yazma. Frontend storage/loglarda sirlərin yayılmasını artırma. Logout yaddaşı/WS bağlantısını təmizləsin; 401/403 sessiya xətası kimi göstərilsin.
- Daimi full-table 5s polling əvəzinə auth WS ilə kiçik event/invalidation, debounced/batched refresh istifadə et; bounded backoff fallback yalnız WS bağlı olmayanda. Gizli tab interval/poll yükünü azalt. Birdən çox panel/cihaz üçün bounded queue, query limit və indekslərlə işləsin.
- PostgreSQL production və SQLite lokal test üçün schema migration-ları idempotent və geriyə uyğun olsun. Cihazlar/pairing/sessiyalar silinməsin. Admin audit hadisələri actor/action/time/target/outcome saxlasın, secret saxlamasın.
- HTML içində böyük JS mətnini idarəolunan static modullara çıxarmaq olar, amma Docker COPY/.dockerignore və static route allowlist-i birlikdə yenilə; mövcud deploy path-larını qırma.

## 6. Test və təhvil

- Əvvəl `plan/NEXT_WORKDAY_HANDOFF_2026-11-03.md`, `docs/PROJECT_LAYOUT.md`, `plan/GEMINI_RULES.md` oxu. Köhnə reviziyaları təkrar icra etmə. Codex host IPC/LKG, build newline/timer/WebView2, release/push/installer düzəlişlərini qoru.
- Faktiki API/DB/WS funksiyaları ilə disposable integration testləri: unauthorized rollar, filtered pagination/sort, online freshness, command/update correlation, offline replay+dedup, redaction, revoke response, bad signed package. Sadəcə mock UI və HTTP200 bütün sistem qəbulu deyil.
- UI bütün bölmələrdə loading/empty/error/stale, reconnect, uzun ad/mətn və pagination yoxlamaları. Real məlumat varsa yalnız read-only bax, heç bir real cihazı revoke/delete/lock/unlock etmə.
- Lokal fixture-lər sintetik olaraq aydın işarələnsin; server data-sını mock saylarla əvəz etmə. Preview serveri arxa planda işlək saxla, GET+interaktiv nav yoxlaması et və yekunda **dəqiq kliklənən link ver**. Screenshot hazırlama.
- `plan/reports/ADMIN_PANEL_EXPANSION_REPORT.md`: tapıntı→düzəliş, dəyişən fayllar, DB migration, test command/exit code/xam log yolları, real vs fixture/NOT_TESTED sərhədi və növbəti operator addımları. Tamamlanmayan hissəni “hamısı bitdi” kimi yazma.
- Canlı push/deploy, installer/service əməliyyatı, production package publish və fiziki lock/unlock etmə. Codex qəbulu üçün dayan.
