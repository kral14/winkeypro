# Gemini — Cloud təhvilinin son bütöv düzəlişi

Əsas CLOUD_AND_LAN_DELIVERY işi davam edir. Yeni mərhələ yaratma; aşağıdakıları birlikdə tamamla. Mövcud işləyən native/LAN axınlarını qoru. Fiziki lock/unlock avtomatik işə salma.

## Mənbədə təsdiqlənmiş qalıqlar
1. web_remote/app/mobile/remote.tsx: attempts>=15 budağı timeout-u SUCCESS kimi göstərir, locked state dəyişir. Yalnız agentdən təsdiqlənmiş success uğur olsun. Timeout/expired/401/network ayrı xəta və ya nəticəsi naməlum göstərilsin; ilkin mock online/PIN/locked göstəricilərini real status alınmadan təqdim etmə. Sessiya device ID-yə bağlansın, başqa cihazın last session fallback-i istifadə olunmasın.
2. route.ts: Boolean(oaiUser) hər təsdiqlənmiş istifadəçini admin sayır. Yeni cihazlarda owner NULL olduğundan belə istifadəçi onları görə və idarə edə bilər; revoke bütün cihazlara açıqdır. Public gateway/mobile ilə private owner admin ayrı audience/layihə müqaviləsini tamamla. Trusted identity header yalnız platformanın təsdiqlədiyi sərhəddə istifadə olunsun; konkret owner allowlist/server auth olmadan admin yoxdur. Caller-in verdiyi oai-authenticated-user-id də public endpointdə yüksəltmə verməsin. Bypass secret paylanmır.
3. agent/register: nonce imzadan ƏVVƏL consume edilir; saxta imza qanuni challenge-i yandırır. Bütün doğrulamalar, existing ownership və status yoxlaması əvvəl, atomik expiry/device/purpose/consumed predicate sonra. Legacy public_key_hex NULL cihazı istənilən açara bağlama: ayrıca təsdiqli migration/re-enrollment tələb et. Paralel ilk registration/same-ID different-key yarışında başqa açar secret rotation edə bilməsin; database şərtli write/transaction ilə qorunsun.
4. QR yalnız 32-bit təsadüfi suffix-dir və public pair-də rate limit yoxdur. Daha güclü entropy, persistent cəhd limiti, PC local approval və session revoke/expiry axını məhsul müqaviləsinə uyğun olsun. Revoke edildikdən sonra mövcud mobile token command result/status daxil bütün qorunan məlumatlara giriş verməsin.
5. Admin telemetry hələ yoxdur: audit_logs cədvəli yaratmaq kifayət deyil. Agent error ingest, redaction, admin timeline və real cihazların mobil əmrlərinin history-də görünməsi işləsin (hazırda history owner=oaiUser filter mobil əmrləri gizlədir).
6. ensureTables xətaları udub initialized=true etməsin. Required migration uğursuzluğu 503/sağlamlıq DB failure olsun; duplicate column kimi yalnız gözlənilən migration halı ayrıca idarə edilsin.

## Yoxlama və təhvil
- verify_sites_contract.mjs yalnız JS fetch ilə localhost Worker/D1 emulator müqaviləsidir. Native agent əvəzinə test özü poll/result success göndərir; bu OS əməliyyatı testi deyil. Hesabatı belə adlandır.
- Əlavə actual testlər: saxta owner headers, owner olmayan login, wrong-device session, revoke sonrası bütün read/write, invalid signature sonra eyni nonce valid claim, expired boundary, legacy-key takeover, paralel registration/QR claim, mobile timeout heç vaxt success olmaması.
- Testlər nonce/QR/token/secret və onların prefikslərini loga yazmasın. Mövcud log generatorunu redaktə et; test artefaktları secret daşımamalıdır.
- Real native CLI -> məhz Worker/D1 backend qeydiyyat/pair/heartbeat/result contract sınağı əlavə et, Python gateway ilə əvəz etmə. Heç bir real PIN/input lazım deyil.
- Public mobil və private admin Sites source/config/migrations hazırla; source build və test raw output saxla. Codex actual Sites deploy edəcək. Canlı deploy, telefondan WAN və fiziki unlock ayrıca NOT_TESTED qalsın.
- Bütün qalıqları bir hesabatda bağla. Test olmayanı PASS yazma. Quraşdırıcı build-i mənbə yekunlaşandan sonra et; installer hash-i cloud təhvil sübutu deyil.

## Codex son mənbə yoxlaması — 2026-10-31
Native mock poll/result və faktiki QR SVG əvvəlkindən irəliləyişdir. Amma canlı deploy-dan əvvəl bunlar eyni tapşırıqda bağlanmalıdır:
- route.ts isProjectOwner hazırda oai-authenticated-user-id dəyərini email ilə müqayisə edir. Sites ID və email ayrı sahələrdir; testin ID yerinə email göndərməsi platforma müqaviləsini yoxlamır. Hosted trusted ID+email ilə sahibin qeydiyyatı/allowlist müqaviləsini düzəlt, yaddaşdakı owner üçün sabit site ID istifadə et. Emailin özünü user ID kimi saxtalaşdıran test real login sübutu deyil.
- NATIVE_WORKER_CONTRACT_RAW.txt native QR URL-ni /remote göstərir, amma web_remote yalnız /mobile route saxlayır; next.config.ts-də /remote rewrite yoxdur. Test yalnız SVG ölçüsünü yoxlayır, QR URL-də mobil UI-nin açılmasını yoxlamır. Cloud QR tam real deploy origin + /mobile olsun; LAN /remote ayrılığı açıq config ilə qorunsun. Test QR-dəki URL-in düzgün mobil səhifəni açmasını da təsdiqləsin, SVG varlığı tək kifayət deyil.
- Public gateway/mobile və private admin üçün əvvəlki ayrı Sites təhvil planı hələ lazımdır. Mövcud private site-ni sadəcə public etmə. Platforma bypass açarı tətbiqə/telefona paylanmır.
Native mock nəticəsi Windows unlock sübutu deyil. Mövcud tapşırığın bu qalıqlarını birlikdə tamamla, yeni installer buildinə vaxt sərf etmə.
