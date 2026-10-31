# Yekun batch audit: CHANGES_REQUESTED

Əsas GEMINI_FINAL_ALL_REMAINING.md qüvvədədir. Hamısını toplu tamamla; aralıq qəbul gözləmə. Final ZIP production üçün qəbul edilməyib.

## P0 — Yeni production gateway
- Codex `python scripts/codex_final_gateway_audit.py` ilə təcrid edilmiş handler+SQLite sınağında üç problemi təkrarladı: etibarsız public key ilə autentifikasiyasız qeydiyyat, heç yaradılmamış pairing kodu ilə mobil sessiya, autentifikasiyasız agent status dəyişməsi. Exit 1 burada gözlənilən təhlükəsizlik tapıntısıdır. Testi rəddi tələb edən regression testinə çevir və düzəlişdən əvvəl/sonra sübut saxla.
- /pair yalnız serverin yaratdığı, həmin cihaza bağlı, vaxtı bitməmiş, yerli PC təsdiqli sorğunu atomik claim edə bilər. Naməlum kod yaratma; cihaz ID-sini body-dən etibarlı sayma. Mövcud PENDING sorğu claim olunanda status həqiqətən dəyişməlidir.
- /agent/register INSERT OR REPLACE ilə mövcud cihazın açar/secretini əvəz edə bilir. Server nonce+device proof, one-use expiry, re-registration ownership yoxlaması bərpa edilsin.
- /agent/poll, /agent/result, /agent/telemetry üçün cihaz autentifikasiyası və object ownership məcburi olsun; saxta result/command theft/state overwrite mənfi testləri əlavə et.
- Hardcoded ADMIN_SECRET çıxarılsın; secret olmadan startup fail-closed, test secret ayrıca fixture. Admin sahib logininə bağlansın. Secret mətnini hesabatlara köçürmə.

## P1 — Tamamlanmamış məhsul inteqrasiyası
- Production /mobile hələ placeholder HTML-dir; əvvəlki işlək mobil axını real bu backend-ə bağla. Test gateway PASS yeni backend/frontend uyğunluğu deyil.
- service_supervisor.py docstring IPC health və boot recovery vəd edir, faktiki yalnız 1 saniyə poll edir, default mock və 60s standalone işlədir. Installer isə birbaşa service.exe --run-service qeydiyyat edir. Sabit recovery launcher-i actual SCM boot yoluna inteqrasiya et; imza/hash/target/LKG təsdiqi, actual IPC health və candidate qəzasından sonra LKG-nin avtomatik yenidən başladılmasını yoxla. Testin ayrıca ikinci start çağırması avtomatik bərpa sübutu deyil.
- update engine-də corrupted journal yoxlamasız slot_a seçir; candidate yaşaması health deyil və COMMIT zamanı prosesi terminate etmək real yeniləmə deyil. Əvvəlki audit qalıqlarını bağla, restart/checkpoint testləri əlavə et.
- diagnostics MAX_OUTBOX_BYTES elan olunub, tətbiq olunmur. JSON corruption-da queue=[] hadisələri itirir, paralel read-modify-write itki/race yaradır; yalnız error_code redaktə olunur; HTTP200 body ACK/event_id təsdiqlənmir. Durable concurrency, byte bound, schema allowlist/redaction və persistent dedup tətbiq et. Actual installer/service sender inteqrasiyasını göstər.
- Python fayllarını ZIP-ə əlavə etmək Python-suz istifadəçi quraşdırmasını təmin etmir. Bundle import/path/runtime və backend deployment müqaviləsini qur; Sites deploy artifact və maneələri açıq göstər.

Sonda yenilənmiş FINAL_BATCH_REPORT.md, xam sübutlar, yeni installer/ZIP hashları, IMPLEMENTED/PARTIAL/BLOCKED matrisi təqdim et. Fiziki unlock/WAN/VM NOT_TESTED sərhədləri qalsın; bütün qeyri-fiziki paketlərin PASS olması məhsulun hazır olması deyil. Tray istifadəçi təsdiqini və Codex düzəlişlərini qoru.
