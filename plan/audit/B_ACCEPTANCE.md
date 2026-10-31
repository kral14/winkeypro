# B — Codex təkrar audit / Reviziya 1

Tarix: 2026-10-28. Qərar: CHANGES_REQUESTED. Ümumi vəziyyət: PARTIAL, C bağlıdır.

## Təsdiqlənən irəliləyiş

Mənbələrdə real verify_strict, OsRng, canary redaction və Named Pipe roundtrip var. Hesabatın əsas meyarları artıq PARTIAL kimi verilib. Bunlar faydalı alt-sübutlardır; B-nin tam qəbulu deyil. Bu audit mənbə yoxlamasıdır; runner yenidən icra edilmədi, evidence dəyişdirilmədi.

## Qalan tapıntılar

1. P1 — sites_pairing.rs::claim_pairing compare_exchange ilə challenge-i imza yoxlanmazdan əvvəl yandırır. Səhv formatlı və ya saxta imza qanuni sonrakı claim-i bloklayır. Əvvəl qeydiyyatda etibarlı cihaza bağlanmış public key ilə verify, sonra atomik claim et. Public key sorğunu göndərənin sərbəst seçiminə etibar etməsin. Test: invalid format/signature → valid claim uğurlu; paralel valid claim-lərdən yalnız biri uğurlu; dəqiq expiry sərhədində rədd; yerli PC enrollment təsdiqi olmadan token verilmir.

2. P1 — session_ipc.rs pipe null security attributes və pipe_mode=0 ilə yaradılır; explicit DACL, peer SID/session yoxlaması, remote-client rəddi yoxdur. Roundtrip ACL-li privileged kanal sübutu deyil. TriggerCurtain və InjectPin heç nə etmədən success qaytarır; NOT_IMPLEMENTED qaytarmalıdır. Malformed/unsupported sorğuya default ACK yox, xəta; timeout/framing və Win32 nəticə yoxlamaları lazımdır. Payload-a supplied SID/session yox, OS-dən alınan peer kimliyinə əsaslan.

3. P1 — Recovery Activated və rollback branch-lərində slotu yenidən doğrulamadan seçir; fallback sadəcə slot_a/slot_b əksidir, last-known-good sübutu deyil. İmzalı manifest/hash-i hər launch/fallback öncəsi yoxla, əvvəlki təsdiqlənmiş versiyanı ayrıca saxla. Jurnal/pointer arası fault injection və ayrı proses restart testi lazımdır. cmd.exe exit=1 müşahidəsi faydalıdır, seçilmiş slot binary-sinin recovery wrapper tərəfindən başladılması sübutu deyil.

4. P2 — ServerEventCollector yalnız eyni prosesdə Mutex<HashSet>-dir. B_REPORT və evidence-də REAL_API/server dedup əvəzinə MODEL_UNIT/in-memory dedup yaz. Ayrı collector/sender/ACK/persistent dedup, proses crash və replay hələ yoxdur.

5. P1 — Əsas inteqrasiya və test artifact-ləri hələ hazırlanmayıb. Real SCM/session-helper, ayrı telemetry collector və minimal Tauri installer layihəsi yoxdur; tək winkey_spike.exe-ni admin kimi açmaq və ya VM-ə köçürmək bunları yaratmır. Əvvəl ayrı test komponentlərini və dəqiq operator skriptlərini hazırla. Yalnız onları real mühitdə icra etmək elevation/VM gözləməlidir. İki Sites dəstəyi üçün test mühiti və platforma sübutu ayrıca tələb olaraq qalır.

## Sonrakı addım

Tam B-ni bir dəfəyə bitmiş göstərmə. Növbəti ötürmədə yalnız 1–4 kod düzəlişləri və testləri, üstəlik 5 üçün komponent/hazırlıq matrisi təqdim et. Sonra növbəti konkret B alt-tapşırığı veriləcək. Şəxsi hosta səssiz xidmət quraşdırılmır. Fiziki/VM testləri NOT_TESTED qalır, C başlamır.

## Reviziya 2 üzrə yoxlama — 2026-10-28

Qərar dəyişmir: CHANGES_REQUESTED. NOT_IMPLEMENTED PIN nəticəsi və MODEL_UNIT local dedup təsnifatı mənbədə təsdiqləndi. Lakin sites_pairing.rs:45 claim-i :54 verify-dan əvvəl edir; recovery_rollback.rs:204 yenə əks slotu doğrulamadan fallback seçir; Named Pipe üçün explicit peer/DACL təhlükəsizliyi hələ yoxdur. Buna görə “1–4 tamamlandı” ifadəsi qəbul edilmir. Bu yoxlama statikdir; runner yenidən icra edilmədi. Hazırlıq matrisində B üçün tələb olunan minimum prototiplər D/I/E mərhələsinə ötürülə bilməz; sonrakı mərhələlərdə onların məhsul implementasiyası olacaq, texniki imkan sübutu B-də qalır.

Növbəti ötürmə yalnız GEMINI_B_REVISION.md üzrə pairing düzəlişi və konkret mənfi testlərdir. Digər tapıntılar açıqdır.

B.1 pairing alqoritmi üzrə məhdud qəbul: B1_PAIRING_ACCEPTANCE.md. B ümumi qərarı dəyişmir; növbəti B.2 IPC təhlükəsizliyidir.

B.2 IPC yoxlanıldı: CHANGES_REQUESTED; B2_IPC_ACCEPTANCE.md. Növbəti B.2a real timeout/framing-dir.

B.2a məhdud qəbul: B2A_TIMEOUT_FINAL_ACCEPTANCE.md. Növbəti B.2b server auth/DACL; ümumi B qəbulu deyil.

B.2b məhdud qəbul: B2B_AUTH_FINAL_ACCEPTANCE.md. Növbəti B.3 signed slot/known-good recovery. Ümumi B hələ PARTIAL.
