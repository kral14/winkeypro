# WebSocket Revision 1 — müstəqil audit

Tarix: 2026-11-01. Qərar: **CHANGES_REQUESTED**. Deploy edilməyib; fiziki LOCK/UNLOCK yoxlanmayıb.

## Təsdiqlənmiş irəliləyiş

- `scripts/codex_ws_batch_audit.py`: əvvəlki 3 regression testi PASS. Tək WS recipient, terminal retry dispatch etməməsi və mobil telemetry ACK müqaviləsi düzəlib. Xam nəticə: `plan/reports/websocket/codex_revision1_recheck.log`.
- `scripts/codex_mobile_ws_audit.cjs`: sağlam WebSocket ilə 1 command frame, 0 HTTP command POST.
- Bounded queue, mutex, pause yoxlaması və konfiqurasiya yenilənməsi əlavə olunub. Bunlar aşağıdakı davamlılıq problemlərini avtomatik bağlamır.

## Qalan tapıntılar

1. **R2-01 / P1 — Dispatch əvvəl, DB claim sonra.** `deploy/asgi_app.py:handle_commands` əvvəl `push_command_to_agent`, sonra pending→delivered UPDATE edir. Bu aralıqda HTTP poll/reconnect eyni pending əmri götürə bilər. UPDATE rowcount yoxlanması side-effect-dən əvvəl deyil. Bir bağlantının seçilməsi bütün transportlar arasında atomik sahiblik deyil. Deterministik yarış testi və ortaq durable claim/lease tələb olunur.
2. **R2-02 / P1 — Outbox itki pəncərələri.** `ws_transport.rs:atomic_write_outbox` rename uğursuz olduqda hədəfi silib yenidən rename edir. Windows-da bu atomik əvəzləmə deyil. Korlanmış/oxunmayan fayl bəzi yollarda boş siyahı kimi qəbul edilir. `save_pending_result` xətasına baxmayaraq nəticə şəbəkə kanalına ötürülür. `record_handled_command` icradan əvvəl yazılır, lakin queue RAM-dadır; qəza əmri nəticəsiz dedup edə bilər. `SUPERSEDED` nəticələri üçün aktiv bağlantıda ACK-a qədər çatdırılma da sübut edilməlidir. Exactly-once fiziki side-effect zəmanəti iddia edilməsin; qeyri-müəyyən crash vəziyyəti açıq modelləşdirilsin.
3. **R2-03 / P1 — Timeout faktiki connect-i əhatə etmir.** Ayrı TCP precheck-dən sonra `connect` yenidən DNS/TCP/TLS/upgrade edir. Precheck DNS-i də blocking-dir. Əsas əməliyyatlar eyni deadline ilə məhdudlaşdırılmalı, STOP/pause bu müddətdə də işləməlidir.
4. **R2-04 / P1 — Sərhəd yoxlamalarının sübutu çatmır.** ASGI Origin/rate siyasəti və runtime frame limiti yoxlanmalıdır. `deploy/vm/server.py` uvicorn çağırışında `ws_max_size` verilmir; tətbiq səviyyəsində receive-dən sonrakı limit transport yaddaş limitini əvəz etmir. Raw frame/error loglarında token əks olunmamalıdır.
5. **R2-05 / P2 — Gecikmə hələ ölçülüb, səbəb sübut edilməyib.** Revision1 load JSON: dispatch p95 **2719.72 ms**, E2E p95 **2874.62 ms** (100 agent, 100 telefon). Bunu Windows event loop ilə qəti izah edən faza ölçüsü yoxdur. DB/pool/lock wait, event-loop lag, queue/dispatch/ACK vaxtlarını ayırmaq və təcrid Linux Docker + PostgreSQL yük sınağı lazımdır.

## Codex-in kiçik qoruyucu düzəlişi

`COPY deploy/` və əvvəlki `.dockerignore` saxta `deploy/keys/DO_NOT_SHIP_CANARY.txt` faylını image-ə daxil etdi: **UNEXPECTED_KEYS_DIRECTORY_INCLUDED**. Həqiqi açar oxunmadı və bu sınaqda istifadə olunmadı. Bu, açarın public yayımlandığının sübutu deyil.

Codex Dockerfile-da yalnız 5 runtime Python modulunun explicit COPY-sini, ignore-da allowlist və keys/secrets/env/database deny qaydalarını tətbiq etdi. Təkrar saxta-canary image nəticəsi: **KEYS_EXCLUDED**. Düzəldilmiş real Dockerfile build + runtime import yoxlaması: **RUNTIME_IMPORTS_OK_KEYS_EXCLUDED**, exit 0. Əvvəlki image-lərin məzmun təhlükəsizliyi ayrıca yoxlanmadan paylaşılmasın; testlər real secret məzmununu çap etməsin.

Növbəti iş vahid batch olaraq `plan/GEMINI_WEBSOCKET_REVISION_2.md`-dədir. Cari hesabatdakı bütün bəndlər üçün “Qalan risk: Yoxdur” qərarı qəbul edilmir.
