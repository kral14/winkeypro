# İmzalama və açar keçidi — Gemini üçün vahid qalan iş

## Codex qəbul qeydi — 2026-11-03

Codex test və hesabatdakı yanlış tam-E2E təsvirini düzəltdi; runtime koduna toxunmadı. test_signing_publication_contract.py hazırda Python verifier + test ZIP helper + repository-ni yoxlayır. Production create_update_package, NSIS, Rust staging və desktop selection çağırılmır. Aşağıdakı 4-cü bəndi bu real production yollarını işlədən disposable testlə tamamla; yalnız faylın mövcudluğunu yoxlamaq həmin mərhələnin icrası deyil. Açar bərpası/Setup miqrasiyası əsas açıq iş olaraq qalır. Etibar lövbərini səssiz dəyişmə. Yekun hesabatı yalnız faktiki sübutla yenilə.

Codex kiçik düzəlişləri etdi: release_pipeline ROOT_FILES artıq .gitattributes export edir; check_signing_key_consistency artıq WINKEY_RELEASE_PUBKEY_HEX ilə production trust anchor-u dəyişmir. tests/test_release_trust_boundary.py disposable signer və export regression-larını yoxlayır. Bu dəyişiklikləri qoru.

Qalan əsas məqsəd: eyni yeni release build/server/service/desktop tərəfindən qəbul edilsin və quraşdırılmış əvvəlki client-lərin etibar zənciri pozulmasın.

1. Runtime 56524c10... public key ilə yerli signer 4c7fa3c7... uyğunsuzluğunu həll et. Uyğun əvvəlki private key-in yalnız yerini/mövcudluğunu yerli yoxla, məzmunu loga/chat-a çıxarma və heç bir secret-i Git-ə əlavə etmə. Uyğun key yoxdursa bunu açıq BLOCKED kimi göstər; köhnə private key olmadan köhnə client-ə avtomatik etibarlı keçid vəd etmə. Owner üçün bir dəfə Setup ilə trust-anchor miqrasiyası variantını konkret hazırla; açarları səssiz dəyişmə, canlı install/deploy etmə.
2. İmzalanmış baytları dəyişmədən qoruyan publication müqaviləsi qur. build, Setup, ZIP, Git checkout, server və Rust verifier eyni manifest/signature baytları ilə işləsin. İndi Python yalnız CRLF-ni, Rust bütün CR-ləri silir; bunu vahid dəqiq qaydaya gətir. Üstün yol raw baytların imzasını yoxlamaq, yararsız köhnə checkout-u etibarlı original mənbədən bərpa etməkdir. Yeni .gitattributes export olunur. Verifier-ləri zəiflətmə.
3. Build metadata-only qovluqları və candidate/backup bərpasını qoruyaraq tam payload paketini ayrıca imza+size+hash+path yoxlamasından keçir. Production doğrulamasına env test key əlavə etmə. Test key yalnız açıq test injection/debug sərhədində olsun.
4. Bir real eyni imzalı fixture/artefaktla build verification → Setup inputs → ZIP → server ingest → native staging → desktop selection müqaviləsini test et. Köhnə client/açar uyğunluğu, yanlış signer, bayt dəyişməsi, çatışmayan payload və crash recovery mənfi halları daxil olsun. SCM fiziki testi aparılmayıbsa NOT_TESTED saxla.

Hamısını vahid hesabatda tamamla: dəyişən fayllar, test əmrləri/exit code/xam loglar, hazır olan hissə və key səbəbindən bloklanan konkret addım. Kod baxışı/test icazəlidir; Git push, canlı deploy, installer və real lock/unlock etmə. Mövcud işlək unlock axınını dəyişmə.
