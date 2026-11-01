# Revision 2 audit — CHANGES_REQUESTED

Tarix: 2026-11-02. Canlı deploy və fiziki Windows input testi edilməyib.

## Real lokal sübut

`scripts/codex_ws_revision2_audit.py` təcrid SQLite/ASGI/socket üzərində iki yeni regression aşkar etdi. İlkin log: `plan/reports/websocket/codex_revision2_audit.log` (2 FAIL).

- **P1 / R3-01:** `Origin: http://158.101.172.228:8080` ilə mobil WS 4003 ORIGIN_NOT_ALLOWED alır. `asgi_app.py` hardcoded localhost/private-IP/example.com siyahısı faktiki public VM-i qəbul etmir. Domen/VM dəyişəndə də təkrarlanacaq. Dəqiq konfiqurasiya edilən production/LAN origin müqaviləsi lazımdır; `10.attacker.tld` kimi prefix uyğunluğu IP doğrulaması deyil.
- **P1 / R3-02 — Codex düzəltdi:** `mark_command_delivered` terminal nəticə commit-dən sonra `claim_owner IS NULL` şərti ilə completed→delivered dəyişirdi. SQL yalnız `status='claimed' AND claim_owner=?` olduqda keçid edir. Təkrar log `codex_revision2_after_fix.log`: terminal testi PASS, Origin testi hələ FAIL. Bu SQL düzəlişini qoru.

## Koddan təsdiqlənən qalan risklər

- **P1 / R3-03:** `bounded_ws_connect` timeout olduqda JoinHandle drop edilir; Rust thread dayanmır. İçəridə limitsiz blocking `connect` davam edir. Təkrar cəhdlər sahibsiz thread/socket yığa bilər. “Resurslar azad edilir” hesabat iddiası sübutsuzdur. Səssiz upgrade/DNS/TLS və stop testləri yoxdur.
- **P1 / R3-04:** handled ID hələ `record_handled_command` ilə queue qəbulundan əvvəl yazılır, in-flight jurnal isə yalnız worker pop etdikdən sonra. Bu aralıqda crash nəticəsiz dedup yaradır. `record_in_flight` xətası udulub input icrasına davam edilir. Recovery `save_pending_result` uğursuz olsa da in-flight qeydi silir. Korlanmış JSON üçün `unwrap_or_default` qalır. SUPERSEDED yolunda da save xətasından sonra journal silinir/şəbəkəyə göndərilir. Bunlar fail-closed deyil. Mövcud in-flight testi sadə funksiya çağırışıdır, disposable crash/fault sübutu deyil.
- **P1 / R3-05:** Hub enqueue uğurunu socket çatdırılması sayır; server bundan sonra statusu delivered edir. Reconnect/poll seçimi yalnız pending/expired claimed götürür, delivered lease expiry-ni götürmür. Writer/disconnect prosesində növbədən itən əmrin bərpası yoxdur. Result protocol claim owner/attempt daşımır və stale claimant nəticəsi yoxlanmır. Əmr status maşını, recovery və ownership bir müqavilə olmalıdır; qeyri-müəyyən fiziki icranı kor təkrarlamaq olmaz.
- **P2 / R3-06:** `test_latency_phases.py` ASGI serveri Python thread-də host Windows-da işlədir; yalnız PostgreSQL Docker-dədir. Bu Linux gateway yük testi deyil. Revision1 SQLite ilə Revision2 PostgreSQL müqayisəsi eyni backend benchmark deyil; 6–9x rəqəmini yalnız WS düzəlişinə aid etmək olmaz. 457.62ms mock ölçüsüdür, fiziki Windows unlock ölçüsü deyil. Yeni rəqəmlər faydalıdır, hesabatın mühit və səbəb iddiaları düzəldilməlidir.

İrəliləyiş: atomik Windows replace, əvvəlcədən DB claim, queue məhdudiyyəti, transport ölçü/rate sərhədləri əlavə olunub. Bu irəliləyiş yuxarıdakı failure pəncərələrini bağlamır. Rədd qərarı bütün layihənin işləmədiyi mənasına gəlmir; bu batch-in hələ deploy üçün qəbul edilmədiyini bildirir.
