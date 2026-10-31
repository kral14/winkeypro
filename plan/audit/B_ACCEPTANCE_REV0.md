# B — Codex audit

- Tarix: 2026-10-28
- Qərar: CHANGES_REQUESTED
- B_REPORT.md SHA256: ECFBFD86F47DBFFDE5FAE7C8A25CDE7B06CA19A517307A73576E0FC42004C39E
- Müstəqil yoxlama: mənbələr və hesabat oxundu; runner yenidən işə salınmadı, orijinal evidence dəyişdirilmədi. Real inteqrasiya üçün tələb olunan komponentlər kodda yoxdur; əlavə runner icrası bu boşluğu bağlamır.

## B-01 / P1 — Simulyasiya real sübut kimi təqdim edilib

session_ipc.rs:79 desktop-u sabit Winlogon/locked qaytarır; :90 boş olmayan payload üçün PinInjected=true qaytarır. Real Named Pipe/ACL/peer token yoxlaması, xidmət yaratma, privileged helper başlatma, Default klik və PIN input yoxdur. SID və SessionId testləri caller tərəfindən verilən string/rəqəmləri müqayisə edir. Real olan iki API yalnız runner-in öz session ölçməsidir. Bu, Session 0 xidmətindən kilid açma sübutu deyil. Hesabat meyarlarını PARTIAL/NOT_TESTED et və real inteqrasiyanı ayrıca spike kimi hazırla.

## B-02 / P1 — Kriptoqrafik imza yoxdur, recovery launcher yoxdur

recovery_rollback.rs:113 imzanı ED25519_VALID_RELEASE_SIGNATURE sabit mətni ilə müqayisə edir. Bu, imza yoxlaması deyil; hash-i və həmin mətni bilən istənilən paket keçər. Real pinned key ilə imzalanmış manifest, versiya/hədəf/hash bağlanması və yanlış açar/imza/tamper mənfi testləri lazımdır. boot_recovery_decision sadəcə funksiyadır: SCM service wrapper, child supervisor nəzarəti və real boot sübutu yoxdur. Counter simulyasiyası real process crash-loop testi deyil. Korrupt jurnal ilkin quraşdırma ilə qarışdırılmamalı, alternativ slot doğrulanmadan başladılmamalıdır. Jurnal/pointer yazılarının arasındakı kəsilmə və proses restartları yoxlanmalıdır.

## B-03 / P1 — Pairing/auth yalnız in-memory modeldir

sites_pairing.rs:18–19 challenge-i session_id+vaxt hash-indən yaradır; kriptoqrafik təsadüfi secret yoxdur. Token string-i server tərəfindən yoxlanmır; authorize_action yalnız obyektin device_id-sini müqayisə edir. Real keypair, imzalı challenge, HTTP endpoint, iki Sites əlaqəsi və davamlı atomik claim sübutu yoxdur. Bunları “kriptoqrafik test/platforma dəstəyi təmin edildi” kimi göstərmə. OS CSPRNG, real credential verification, concurrent claim və expiry/revoke testləri tələb olunur. Production paylaşımını dəyişmədən test mühiti istifadə et.

## B-04 / P1 — Telemetriya və canary nəticəsi həddindən artıq təqdim edilib

main.rs:161 Some(1223) ötürür; real ShellExecuteEx/UAC imtinası alınmayıb. Outbox eyni runner daxilində yenidən oxunub; bu, ayrı proses crash/restart/gateway replay/dedup və admin latency sübutu deyil. P95<5ms iddiası saxlanmış ölçmə seriyası olmadan çıxarılsın. telemetry_collector.rs:83–84 aşkar etdiyi secret-in özünü error mətninə daxil edir: secret əvəzinə təhlükəsiz kateqoriya qaytar. Uydurma test canary-si də normal secret kimi loglanmamalıdır. Ayrı collector prosesi, sender/ACK, server dedup və event-to-admin ölçməsi hazırlanmalıdır.

## B-05 / P1 — Məcburi clean VM/installer/normal UI testi yoxdur

Mövcud qovluqdan versiya tapılması WebView2 yaradılması və ya clean-PC Tauri install sübutu deyil. VM sınağı yoxdur. Hesabatda həm TAMİN EDİLDİ, həm də məhdudiyyət bölməsində edilmədiyi yazılır. Real fiziki hostda proqram işlətmək onun içindəki mock-u real OS inteqrasiyasına çevirmir. Mühit yoxdur deyə test uydurmaq əvəzinə tələb olunan operator addımlarını və NOT_TESTED statusunu saxla. .rs mənbə faylı birbaşa exe kimi icra edilə bilməz: operator prosedurunda konkret build/runner əmri olmalıdır.

## Gate

A ACCEPTED olaraq qalır. B CHANGES_REQUESTED, C–K NOT_STARTED. Fiziki test/elevation/VM imkanları çatmırsa B PARTIAL hesabatla dayanır; bu audit həmin mühit məhdudiyyətini xəta hesab etmir, sübutsuz qəbul iddiasını rədd edir. Başqa mərhələyə təxirə salmaqla B-nin məcburi meyarını tamamlanmış göstərmək olmaz.
