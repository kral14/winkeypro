# Gemini — WinKey qalan implementasiyanı toplu tamamla

## Sahibin qərarı və icra rejimi

İlkin frontend görünüşü təqdim edilib. İndi demo arxasındakı real proqramı, qalan inteqrasiyaları və build/test hazırlığını tamamla. Hazır dizaynı qoru. Xırda alt-tapşırıqdan sonra dayanma; aşağıdakı paketləri birlikdə işlə. Maneə yarananda digər müstəqil işləri davam etdir. Codex sonda toplu audit edəcək; özünü ACCEPTED elan etmə.

Oxu: plan/STATUS.json, KNOWN_ISSUES.md, ARCHITECTURE.md, DECISIONS.md, DIAGNOSTICS_SUPPORT.md, UPDATE_ROLLBACK.md, TEST_MATRIX.md; B–K stage faylları, son B.1/B.2a/B.2b qəbulları və GEMINI_B_TO_G.md. Bu tapşırıq əvvəlki “frontend-dən sonra dayan” sərhədini əvəz edir. H–K üçün aşağıda göstərilən hazırlıq/test işləri də açılır; public/stable publish, real signing və pilot istifadəçilərə yayım ayrıca buraxılış qərarıdır.

## 1. Demo frontend-i real tətbiqə bağla (C–G qalıqları)

- Browser desktop maketindən real Tauri 2 + React Windows app qur. Build edilmiş EXE/installer təqdim et; frontend route-u native app sübutu sayma.
- Device status, PC adı, local credential save, register, QR, revoke, log/support düymələrini real typed adapterlə bağla. Demo adapter ayrı və aydın qalsın; production builddə demo/admin auth bypass olmasın.
- Native imkanlar minimal Tauri capabilities ilə daralsın. PIN native qorunan storage-a yazılsın, renderer log/localStorage/serverə düşməsin. Settings xətaları aydın olsun.
- Mobil/admin real backend adapteri işləsin; fake timeout→success arxasında real nəticə olmadan uğur göstərmə. Telefon lock/unlock komandası növbəyə düşsün, agent icra etsin, faktiki nəticə mobilə qayıtsın.

## 2. Windows service, helper, tray və startup (B/D)

- Real SCM service entrypoint/control-handler və ayrı sabit recovery launcher hazırla. UI bağlananda xidmət davam etsin. X=real tray, aç/çıx/idarəni dayandır davranışları ayrı olsun. Boot automatic service, user login tray, singleton/reconnect.
- LocalSystem Session0-dan doğru user sessiyasına etibarlı privileged helper başlat; actual SessionId və qeydiyyatlı Windows SID-ni təsdiqlə. Qorunan binary path və dar ayrı user/service, SYSTEM/helper IPC kanalları.
- Default curtain klik→Winlogon fokus→bir dəfə credential→faktiki unlocked təsdiqi real Win32 axını ilə işləsin. Enum dəyişdirib SuccessUnlocked qaytarmaq real icra deyil. Hello açıldıqda əlavə input, UAC-a PIN və yanlış PIN təkrarları bloklansın. Secure desktop ACL-lərini zəiflətmə.
- Mövcud pc_agent engine və işlək backupı qoruyaraq yeni tətbiqə təhlükəsiz inteqrasiya et və ya Rust portunun eyni davranışını sübut et.
- Installer repair/uninstall service/autostart qalıqlarını təmizləsin. Şəxsi hostda səssiz quraşdırma/reboot etmə; test artifact və operator proseduru hazırla.

## 3. Gateway, pairing və yalnız sahib admin (E/F/G)

- İki Sites layihəsi/private owner admin + public device/mobile gateway üçün deploy edilə bilən backend/config hazırla; cari platforma dəstəyini faktiki sənəd/tool ilə yoxla. Mövcud production audience/secret dəyişmir.
- Local device private key, public-key proof, register/heartbeat/command/result; mobil üçün qısaömürlü birdəfəlik QR, PC enrollment/təsdiqi, device-scoped expiry/revoke; owner-only admin və server-only admin API.
- Davamlı DB-də atomic claim, multi-process replay və concurrent request, iki cihaz/tenant IDOR, invalid signature/token, admin access/rate limit testləri real HTTP səviyyəsində işləsin. In-memory Rust modelini server sübutu kimi təqdim etmə.
- Production shared bypass/admin key EXE/QR/PWA/source-da olmasın. Lokal test üçün ayrı secret mühiti; operator hesab/key seçimi lazımdırsa konkret siyahı yaz və qalan işi davam etdir.
- PWA manifest/icons/install təlimatı, auth resume/revoke/offline; Android/iPhone real test yoxdursa browser renderi fiziki test kimi göstərmə.

## 4. Telemetriya və admin dəstək axını (D/E)

- Installer ilk kod icrasından stage/error eventləri, ayrı crash reporter prosesi, bounded durable outbox, HTTPS sender/retry/ACK və persistent server dedup.
- UI/agent crash, ayrı proses restart, offline replay, duplicate event, disk dolması və retention sınaqları. Yerli disk yazma vaxtı internet/admin latency deyil; həqiqi event→admin timeline P95 ölçmə seriyasını saxla.
- UAC denial və pre-execution SUSPECTED_STALL sərhədi; secret canary mətnləri loga düşməsin; raw memory dump yığma. Telemetry xətası əsas unlock-u dayandırmasın.
- Owner panelində installer stage, cihaz/version, redacted xəta və support instruction/known issue axını işləsin. Admin arbitrary shell icrası olmasın.

## 5. Recovery, yenilənmə və release pipeline hazırlığı (B/H/I)

- Pinned release key ilə signed bundle/manifest, target/version və bütün binary hash-ləri hər launch/fallback öncəsi yoxla. Known-good probation/health commit olsun, fallback “əks slot” deyil son təsdiqli versiya olsun. Traversal/absolute/reparse escape rədd edilsin.
- Sabit recovery wrapper boot-da candidate-dən əvvəl jurnalı yoxlayıb verified child supervisor başlatsın. Checkpoint process-kill/restart, tamper, signer mismatch, partial download/commit, candidate crash-loop, iki etibarsız slot və backward-compatible local data testləri.
- Git CI workflow, build/test/artifact/manifest və release approval hazırlığı. Git host/repo/sertifikat sahib tərəfindən verilməyibsə uydurma; local scripts və workflow source hazırla. Remote repo yaratma/push və public release ayrıca owner icazəsi olmadan edilmir.
- Avtomatik update yalnız trusted release feed/signature ilə işləsin; test feed və test signing key source/logdan kənar olsun. Wrong PIN/internet/gateway5xx rollback səbəbi deyil.
- Recovery-nin öz update-i ayrıca installer repair yoludur. Proqramın check/download/apply/rollback hadisələri admində izlənə bilsin. Unsigned installer-i signed production kimi təqdim etmə.

## 6. Test, uyğunluq və pilot hazırlığı (J/K)

- Windows11 x64 əsas hədəf; Win10/ARM əlavə dəstəyini test olmadan iddia etmə. Standard user, clean VM/WebView2, service startup, X=tray, sleep/wake, keyboard layouts, yanlış user/session, uninstall/reinstall və ayrı şəbəkə sınaqlarını mövcud mühitdə apar.
- Fiziki Windows, Android, iPhone, VM/elevation əlçatan deyilsə build edilmiş artifact + dəqiq operator addımı + gözlənilən nəticə hazır olsun; yalnız icra NOT_TESTED qalsın.
- Pilot installer/readme, QR/telefon təlimatı, troubleshooting, local logs/export redaction, known limitations və recovery proseduru hazırla. Pilot istifadəçilərə göndərmə/public publish etmə.
- UI regresiyası: mövcud görünüş, 360/390/430px mobil və 100–200% desktop DPI, real packaged app renderləri.

## 7. Launcher qalıqları

KNOWN_ISSUES.md-də PRE-002/PRE-004 açıq qeydləri bağla. Stop scriptində generic *npm*/*web_remote* substring-i ownership sübutu sayılmasın: exact resolved workspace/proses tree + stored PID creation timestamp tələb olunsun. Yad npm/node prosesi, PID reuse/stale metadata, cold start→health→duplicate→own stop testlərini ayrıca test portunda işlə. Mövcud istifadəçi serverini kor-koranə öldürmə.

## Ümumi qaydalar və təhvil

- Hazır source-a bax, çatışmayan kodu implementasiya et; yalnız hesabatı daha gözəl yazmaq işi bitirmir. Testləri real icra et, failing nəticəni gizlətmə.
- REAL_API/INTEGRATION/MODEL/CONTROLLED_INJECTION/VM/PHYSICAL fərqli etiketlənsin; backend fixture və mock status real uğur deyil.
- Şəxsi hostda real PIN mesajla istəmə; service/startup quraşdırma, reboot, production deploy/audience dəyişmə, signing alışları və public release native/owner icazəsi olmadan edilmir. İzolyasiya olunmuş test VM içində işləyə bilərsən. Bir icazə maneəsi bütün lokal kod/build/test işini saxlamasın.
- Yeni evidence-ni plan/reports/remaining/ daxilində saxla; əvvəlki sübutları overwrite etmə. Source/repo qaydalarını oxu, secret/private key/credential fayllarını hesabata çıxarma.
- STATUS.json/STATUS.md və KNOWN_ISSUES.md-də yalnız faktiki vəziyyəti yenilə; Codex acceptance-lərə toxunma. “Hamısı tamamlandı” yalnız bütün tələb olunan kod/artifact/test varsa deyilə bilər.

Sonda plan/reports/REMAINING_WORK_REPORT.md yaz: hər paket IMPLEMENTED/PARTIAL/BLOCKED; EXE/installer/source/local URL yolları; real test command/exit/redacted log/hash; açıq P0/P1-lər; operatorun konkret qısa addımları; deployment/signing üçün qalan sahib qərarları. Real işləyən user flow ilə demo hissələri cədvəldə ayır.

Bütün mümkün işləri tamamlayandan sonra bir toplu nəticə təqdim et və dayan. Codex bundan sonra qalan səhvləri toplayıb düzəliş batch-i verəcək; alt-paketdən sonra audit gözləyib dayanma.
