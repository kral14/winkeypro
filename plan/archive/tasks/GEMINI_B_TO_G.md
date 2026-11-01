# Gemini — B, C, D, E, F, G mərhələlərini bir ötürmədə tamamla

## Sahibin yeni icra qərarı

Sahib yalnız B alt-paketlərini deyil, B–G altı mərhələsini birlikdə sifariş edir. Hər mərhələdən sonra Codex auditini gözləmə: B-də qalanları tamamla, C→D→E→F→G implementasiyasını davam etdir, sonda bir toplu təhvil ver. Aralıq stage ACCEPTED uydurma; mərhələ icrası ilə auditor qəbulu ayrıdır. Codex sonda B–G-ni birlikdə audit edəcək.

Bu sənəd əvvəlki GEMINI_B_REVISION.md/GEMINI_B_BATCH.md/start fayllarının “yalnız B”, “C-yə keçmə”, “alt-tapşırıqdan sonra dayan” məhdudiyyətlərini və GEMINI_RULES.md/stage fayllarındakı aralıq audit gözləmə qaydasını BU B–G İCRASI ÜÇÜN əvəz edir. Təhlükəsizlik, test sübutu və istehsala buraxılış qaydaları qüvvədədir. H–K bu tapşırığa daxil deyil.

## Oxu və işə başla

plan/README.md, STATUS.json, DECISIONS.md, ARCHITECTURE.md, DIAGNOSTICS_SUPPORT.md, UPDATE_ROLLBACK.md, TEST_MATRIX.md və stages/ daxilində B–G fayllarını oxu. Qəbul edilmiş B.1, B.2a, B.2b alqoritmlərini və audit sərhədlərini qoru. GEMINI_B_BATCH.md-nin texniki siyahısından istifadə edə bilərsən, amma onun scope/dayanma qaydası bu sənədlə əvəz olunur.

Əvvəl qısa icra siyahısı və mühit yoxlaması et, sonra kod/build/test işinə davam et. Plan yazıb işi saxlamış sayılma. Mövcud işlək prototip və backupı qoruyaraq yeni məhsulu ayrıca qovluqda qur.

## B — Texniki riskləri bağla

Qalan signed slot/known-good recovery, real SCM service→düzgün session/helper, ayrı telemetry sender/reporter, WebView2 installer və test gateway sübutlarını hazırla. İmzalı manifest/hash hər launch/fallback öncəsi yoxlansın; candidate health confirmation-dan sonra known-good olsun. Checkpoint child kill/restart testləri, invalid signature, corrupted slot/journal, yanlış SID/session və secret redaction testləri apar. Kod yoxdursa maneəni yalnız elevation kimi təqdim etmə.

## C — Peşəkar desktop interfeysi

Tauri 2 + React/TypeScript ilə hazır istifadə edilən interfeys qur: onboarding, avtomatik/dəyişən PC adı, yalnız yerli saxlanan PIN, qeydiyyat, online status, QR, settings/support və diaqnostika ekranları. AZ mətn, klaviatura naviqasiyası, 100–200% DPI, loading/error/offline halları işləsin. PIN source/renderer log/telemetry/screenshot-a düşməsin. Uzaq sayt geniş native IPC səlahiyyəti ilə render edilməsin. Real mənbə və paketli build üzrə vizual yoxlama saxla. Mock vəziyyət real kimi göstərilməsin.

## D — Service, tray, startup və installer

Real Windows service/supervisor, sabit recovery launcher, session helper, dar ACL-li ayrı IPC kanalları və reconnect/singleton qur. X=tray, UI çıxışı ilə remote xidmətin dayanması fərqli əməl olsun. Boot-da service, login-də tray; repair/uninstall qalıqları təmizləsin. Mövcud Default klik→Winlogon fokus→bir dəfə credential→faktiki unlock etalonunu qoruyaraq inteqrasiya et. UAC ekranına PIN göndərmə, Hello açdıqda əlavə input yazma, yanlış PIN-i təkrar-təkrar sınama. Secure desktop ACL-lərini zəiflətmə.

Installer ilk kod icrasından stage eventləri, müstəqil crash reporter, bounded durable outbox, sender retry/ACK/replay və dedup qursun. UI crash və offline restart testləri apar. WebView2 təmin edən build edilmiş installer ver; clean VM yoxdursa yalnız real install testi NOT_TESTED qalsın, artifact hazır olsun. Test release unsigned-dırsa açıq göstər.

## E — Gateway və yalnız sahibə açıq admin

İki Sites sərhədinə uyğun public cihaz/mobile gateway və owner-only admin qur. Register/device proof, heartbeat, command queue/result, expiry/replay/revoke/rate limit, davamlı tenant isolation və audit log işləsin. Admin PC adı/status/versiya/incident timeline/support təlimatını görsün, PIN görməsin. Server-only admin əlaqəsi client/EXE/PWA-ya sızmasın. İki cihaz/istifadəçi üzrə IDOR/admin access testlərini real HTTP/backend səviyyəsində apar.

Mövcud production Sites audience/secret-lərinə toxunma. Yeni ayrıca test layihəsində deploy imkanı varsa test et; hesab/tool icazəsi yoxdursa deploy edilə bilən source/config və local HTTP inteqrasiya testlərini tamamla, canlı Sites dəstəyi/deploy-u NOT_VERIFIED saxla. Production-a buraxılmanı yerli hazırlıqla qarışdırma.

## F — EXE qeydiyyatı və QR pairing

İstifadəçi EXE-ni quraşdırır, adı avtomatik gəlir/dəyişir, PIN-i lokal daxil edir, qeydiyyatı tamamlayır və mobilini QR ilə qoşur. Manual service/admin key istəmə. Private device key cihazda yaransın, serverə çıxmasın. Qısaömürlü birdəfəlik QR, yerli PC enrollment/təsdiq, cihaz-məhdud revocable mobil session olsun. İmzalı pairing, səhv/reused/expired/copied QR, concurrent claim və revoke sınaqlarını işlət. Anonymous install_run_id düzgün device proof ilə bağlansın. QR-də PIN/admin/private key olmasın.

## G — Sadə mobil PWA

Telefon üçün sadə interfeys: Kilidlə / Kilidi aç, aydın nəticə/online status. Android və iPhone ana ekrana əlavə etmə təlimatı, manifest/icons, session resume/revoke/offline davranışı hazır olsun. Mobil istifadəçi ChatGPT admin hesabı istəmədən yalnız öz cihazını idarə etsin. PWA cache-də credential/komanda nəticəsi sızmasın. QR→mobil→əmr→real PC nəticəsi və ayrı şəbəkə sınaqlarını mümkün mühitdə tamamla; fiziki Android/iPhone yoxdursa bunu browser emulyasiyası ilə əvəz edib keçdi göstərmə.

## Avtonom iş və sərhədlər

- Alt-mərhələdən sonra dayanma. Maneə çıxsa təhlükəsiz müstəqil paketləri işləməyə davam et; lazım olan konkret operator addımını birləşdirilmiş siyahıya yaz.
- Şəxsi hostda səssiz service/startup quraşdırma, real hesab/PIN tələbi, production paylaşımı və stable publish üçün bu sənədi ümumi icazə sayma. Native icazə qaydalarına riayət et. İzolyasiya olunmuş test VM varsa onun daxilində test et. Operatordan real PIN-i yalnız öz lokal test ekranına daxil etməsi tələb oluna bilər; onu mesajla istəmə.
- Build və test üçün əlavə runtime/asılılıq və toolchain lazım olduqda mövcud imkanlarla hazırla. Mümkün olmayan mühit/testi uydurma.
- Model/unit, real API, real HTTP/process, VM və fiziki PC nəticələri ayrı göstərilsin. Qəbul olunmayan behavior-u success kimi qaytarma.
- Token/PIN/private signing key/raw memory dump source/log/prompt/artifact-a düşməsin. Test secret-ləri production-dan ayrı saxla. Test signing key-ni release signing authority kimi təqdim etmə.
- Köhnə evidence-ni əvəzləmə; reports/B–G və reports/B_G_BATCH/ daxilində yeni sübutlar saxla. Dəyişən alt-repo təlimatlarını oxu.

## Sonda toplu təhvil

plan/reports/B_G_BATCH_REPORT.md yarat:
- B/C/D/E/F/G üzrə IMPLEMENTED/PARTIAL/BLOCKED matrisi; ACCEPTED yalnız Codex qərarıdır.
- Source/build edilmiş EXE/installer/mobile/admin/gateway artifact yolları və reproduksiya əmrləri.
- Hər stage qəbul meyarı üzrə test əmri, exit code, redacted raw log, mühit və SHA256; UI vizual sübutları.
- Real install→register→QR→mobile lock/unlock→tray→restart axınının sübutu və ya çatışmayan hissəsi.
- Açıq P0/P1 və əsl maneələr; operatorun etməli olduğu qısa ardıcıl addımlar.
- Mövcud fərdi stage hesabatlarını aktual et, əvvəlki audit qərarlarını dəyişmə. STATUS-da implementasiya vəziyyətini dürüst saxla, audit qəbulu uydurma.

B–G işləri bitəndə və ya yalnız istifadəçi/mühitə bağlı maneələr qaldıqda READY_FOR_BATCH_AUDIT/PARTIAL təqdim et və dayan. H–K-yə keçmə.
