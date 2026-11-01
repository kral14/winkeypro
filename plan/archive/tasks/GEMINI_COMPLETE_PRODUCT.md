# Gemini — WinKey-i bütöv işlək test məhsuluna tamamla (toplu tapşırıq)

## Sahibin son göstərişi

İşləri xırda reviziyalara bölüb hər dəfə dayanma. Aşağıdakı bütün qalıqları bir icra daxilində tamamla. Mövcud yaşıl dizayn və qəbul edilmiş təhlükəsizlik düzəlişlərini qoru. Maneə çıxsa digər müstəqil işləri davam etdir. Sonda işlək native tətbiq, telefon idarəsi, quraşdırıcı və bir toplu hesabat ver. Əvvəlki “yalnız bu alt-tapşırıqdan sonra dayan” qaydaları bu scope üçün əvəz olunur; özünü auditor kimi ACCEPTED elan etmə.

Oxu: plan/KNOWN_ISSUES.md, STATUS.json, ARCHITECTURE.md, DIAGNOSTICS_SUPPORT.md, UPDATE_ROLLBACK.md, reports/codex/CODEX_FIXES_HANDOFF.md və son source. Mövcud README/report iddialarına yox, faktiki kodun nə etdiyinə əsaslan.

## 1. İlk prioritet: singleton + işlək tray

Sahibin gördüyü problem: hər EXE açılışında yeni proses/tray ikonu yaranır; ikona basanda pəncərə görünmür; çıxış yoxdur.

- Tauri single-instance mexanizmi və ya düzgün user/session-scoped named mutex ilə ikinci instance qəbul edilməsin. Mövcud instance-ə Show/Restore mesajı verilib ikinci proses dərhal sonlansın. Singleton pəncərə/tray yaradılmasından əvvəl qüvvəyə minsin. Fərqli Windows user session-larını təsadüfən bloklama.
- Tray sol klik/double-click mövcud əsas pəncərəni show + unminimize + focus etsin. Sağ klik menyusu: “Proqramı aç”, “Uzaqdan idarəni dayandır/başlat” (real vəziyyətə bağlı), “Çıxış”. Hər action faktiki işləsin.
- X basıldıqda pəncərə gizlənsin, bir tray ikonu qalsın. “Çıxış” prosesi həqiqətən bitirsin; CloseRequested interception exit-i ləğv etməsin. Tray/proses handle-ları və singleton təmizlənsin. Desktop exit service-i avtomatik silməsin; service fonda qalırsa bunu çıxış davranışında açıq göstər.
- User login startup yalnız bir desktop instance yaratsın. İstifadəçinin əvvəlki test versiyası tray-da qala bilər: yalnız dəqiq verified WinKey desktop path/PID/creation identity ilə konfliktini göstər; digər tətbiqləri və şəxsi service-i kor-koranə öldürmə. Mümkün olduqda graceful exit, force cleanup yalnız aydın operator göstərişi ilə.
- Testlər: ardıcıl 10 launch→1 PID/1 tray; ikinci launch hidden pəncərəni bərpa edir; X→hide→tray restore; minimize→restore; right-click menu→exit→process gone; exit-dən sonra launch yenidən işləyir. Bunları real native EXE-də yoxla, yalnız browser modalı ilə deyil. Orijinal screenshot-da default icon görünür: WinKey tətbiq/tray icon identity-si də uyğun olsun.

## 2. Telefon ekranını real backend-ə bağla

Hazır gateway /remote HTML-i yalnız mətn göstərirdi. HTTP200 page title testi real mobil idarəetmə deyil.

- Mövcud mobil dizaynı real /remote və ya /mobile səhifəsinə bağla; QR eyni həqiqi URL-ni açsın. Kilidlə/Kilidi aç, cihaz adı, pending/approved/online/offline, loading və actual command result göstərilsin.
- QR→claim→PC-də pending approval→yerli authenticated təsdiq→device-scoped session→command→service result→mobil readback→revoke bütöv axın olsun. Telefonda admin/ChatGPT sahib hesabı və Windows PIN tələb edilməsin. PIN yalnız PC-də saxlanılır; server/phone schema credential sahələrini rədd etsin.
- Mobile session storage/expiry/revoke, QR-dən secret query təmizlənməsi, authorization/CSRF/cache sərhədləri və device isolation tətbiq edilsin. Saxta success spinner/state dəyişməsi real nəticə əvəzi deyil.
- Gateway origin konfiqurasiyası GUI-də olsun; LAN/HTTPS reachable adresi QR-a düşsün. Telefon üçün 127.0.0.1 istifadə olunmasın. Lokal HTTP yalnız explicit dev/test; production HTTPS və trusted origin tələb olunur.
- Test: browser actual click ilə register/QR/pair/approve/command/result; iki device/tenant, expired/replayed code, approval bypass, revoked token və offline error. Fiziki telefon yoxdursa browser emulyasiyasını physical PASS kimi göstərmə.

## 3. Desktop→service→helper real zənciri tamamla

- GUI name/register/pair/approve/PIN save/status/support düymələri production native komandalarına bağlı olsun. Demo ayrıca qalır; real adapter yoxdur deyə demo success qaytarılmasın.
- Codex helper PIPE_MIN_CREDENTIAL_ACCESS=0x0012008B düzəlişini qoru. E2E default real lock/input göndərmir; physical test explicit operator opt-in olmadan açılmır. scripts/codex_run_nonphysical_e2e.py və test_helper_pipe_access.py nəticələrini qoru.
- Device secret/PIN yalnız authenticated service IPC vasitəsilə service-owned DPAPI storage-a yazılsın; user/SYSTEM hesab sərhədi və normal-user→SYSTEM provisioning tam olsun. Client verified trusted SCM process binding; exact owner SID, minimum ACL/mask, deadline, checked revert və no-leak transport.
- LOCK və UNLOCK hədəf interaktiv session helper-də icra edilsin. WTS user SID/session və child SYSTEM token/session, exact desktop və qorunan helper path yoxlanılsın. Credential argv/env/log/plain disk/serverə çıxmasın.
- Default PIN-siz curtain click→Winlogon/fokus təsdiqi→bir input cəhdi→actual WTS unlocked confirmation. UAC/Hello/unknown focus/wrong session fail-closed. SendInput count və worker timeout/crash düzgün nəticə versin. Missing credential/permission failure funksional uğur sayılmasın.
- STOP/shutdown connected/silent peer olsa da bounded sonlansın. Status gerçək state-dən gəlsin, service özü ilə UI statusu qarışmasın.

## 4. Quraşdırma, başlanğıc, package və bərpa

- Tam installer/bootstrapper artifact hazırla: qorunan ProgramFiles payload/helper, ProgramData ACL/owner enrollment, service register/start/real health handshake, WebView2 təminatı, login startup, repair/uninstall. Öncəki test prosesləri ilə conflict-lər aydın error olsun.
- “Running” təkbaşına provisioning/IPC sağlamlığı deyil. Payload hash/imza metadata, minimum permissions, installer rollback/data preservation işləsin. İlk quraşdırma→ilk GUI→gateway config→PIN→QR ardıcıllığı manual config edit tələb etməsin.
- Recovery/auto-update əvvəlki plan üzrə gerçək məhsula bağlansın: signed pinned manifest, verified known-good slots, probation/health commit, failed candidate rollback, crash collector və data compatibility. Hələ hazır deyilsə implementasiya hissəsini tamamla; owner signing/release feed/deploy tələbini kod yoxluğundan ayır.
- Source/build/test Git CI hazırlığı; heç bir repo/publish/signing sertifikatı uydurma. Unsigned test build production release deyil. Startup və installer ssenarilərini test VM-də varsa işlə, şəxsi hosta səssiz quraşdırma etmə.

## 5. Admin, telemetry və testlərin dürüst nəticəsi

- Owner-only admin actual device/version/status/result/incident timeline göstərsin; mobil digər cihaza/admin endpointə daxil ola bilməsin. İki Sites layihəsi və private/public sərhədləri qorunsun. Mövcud production audience/secret-lər dəyişməsin; ayrı deploy/test config hazırla.
- Ayrı reporter, bounded durable outbox, offline replay/ACK/persistent dedup və installer stage/crash eventləri actual məhsula bağlansın. Localhost P95 internet SLA kimi verilməsin. Heç bir secret/dump yığılmasın.
- Test meyarlarını düz saxla: security rejection PASS funksional unlock PASS deyil. Default suite input-free; actual physical input yalnız ayrıca opt-in. Heç bir normal test şəxsi Windows ekranını kilidləməsin.
- Real native singleton/tray/menu click, packaged app UI, actual mobile command flow, normal-user service IPC, clean VM/repair/uninstall, reboot/startup və separate-network nəticələri source/test artifact-ləri ilə təqdim olunsun. Test olunmayıbsa NOT_TESTED, kod yoxdursa NOT_IMPLEMENTED; qondarma “100% hazır” yoxdur.

## Təhvil və avtonom davam

İcraya qısa checklistlə başla, sonra bütün mümkün kod/build/testləri tamamla. Xırda fix və build səhvlərini özün düzəlt. Fərqli mühit/privilege maneəsi olanda qalan paketləri işləməyə davam et. Şəxsi host service install/reboot, real ekran kilidləmə/PIN cəhdləri və production publish ayrıca konkret icazə olmadan edilmir. PIN-i mesajla istəmə.

Mövcud evidence-ni overwrite etmə. Yeni plan/reports/completion_batch/ qovluğu və plan/reports/COMPLETION_BATCH_REPORT.md:
- Hər bölmə IMPLEMENTED/PARTIAL/BLOCKED; göstərilən real source/build artifact yolları.
- Singleton/tray test videosu və ya real addım/screenshot+PID ölçümü; mobil UI actual klik smoke sübutu.
- Command/exit/redacted raw log/hash, unit/API/integration/VM/physical fərqi.
- Bir hazır yeni ZIP/installer və SHA256; içində işlək test manualı.
- İstifadəçi üçün bir səhifə: nəyə klikləsin, nə quraşdırsın, telefon necə qoşulsun, hansı mərhələ operator testidir, xəta olsa necə təhlükəsiz çıxıb logs götürsün.
- Açıq P0/P1 və həqiqi deploy/signing/physical maneələri. Codex qəbulları dəyişmir, status yalnız gerçək nəticəyə görə yenilənir.

Bütün paketlərin sonunda toplu nəticə təqdim et və dayan. Codex xırda düzəliş/testlərə paralel yardım edəcək; bu müddətdə onun yenicə etdiyi source dəyişikliklərini geri yazma, konflikt varsa bildir.
