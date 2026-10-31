# Gemini — B mərhələsi, beş iş paketini fasiləsiz tamamla

İş qovluğu: D:\rust desk mobil kilid acma. Məhsul: WinKey Pro.
Codex auditor, sən implementersən. Sahib beş paketin bir ötürmədə işlənməsini istəyir. Xırda alt-tapşırıqdan sonra dayanma; bütün paketləri tamamla və yalnız sonda toplu hesabat ver. Bir paketdə mühit maneəsi varsa digər müstəqil işləri davam etdir.

## Əvvəl oxu

plan/STATUS.json, GEMINI_RULES.md, stages/B_TEXNIKI_SPIKE.md, ARCHITECTURE.md, UPDATE_ROLLBACK.md, DIAGNOSTICS_SUPPORT.md, audit/B_ACCEPTANCE.md və son B1/B2A/B2B qəbul faylları. Qəbul edilmiş pairing, IPC timeout/framing və user-channel auth-u qoru. Əvvəlki GEMINI_B_REVISION.md-dəki “yalnız B.3 və dayan” bu sahib tapşırığı ilə əvəz olunur.

Bu beş paket B texniki sübutunun toplu icrasıdır; C–G mərhələlərinin tam məhsul qəbulu deyil. Yeni kod ayrıca spike/prototype qovluğunda olsun. Hazır engine/backup və şəxsi Sites tətbiqi qorunsun.

## 1. Recovery və rollback

- Hər launch/fallback öncəsi pinned release public key ilə manifest imzası, versiya/target və binary hash-ləri doğrulansın.
- Fallback əks slot deyil, ayrıca təsdiqlənmiş last-known-good olsun. Candidate yalnız health probation uğurundan sonra known-good olur. Hər iki slot etibarsızdırsa binary başladılmır.
- Slot yolları nəzərdə tutulan versions qovluğundan çıxa bilməsin; traversal/absolute/reparse escape rədd edilsin.
- Sabit recovery launcher supervisor-u child kimi başladıb izləsin. Real minimal test supervisor binary-si ilə valid activation, health commit, crash-loop, saxta imza, tamper və fallback corruption testləri olsun.
- Jurnal/pointer checkpoint-lərində child kill və ayrıca proses restart/fault injection sübutu topla. Bunu elektrik kəsilməsi adlandırma. SCM boot testi mümkündürsə test VM-də icra et; yoxdursa artifact və operator proseduru hazır olsun.

## 2. Windows xidməti və session helper

- Real SCM ServiceMain/control-handler, recovery wrapper və minimal helper binary-lərini build et. Service Session 0-da, UI istifadəçi sessiyasında işləsin.
- Etibarlı privileged token və CreateProcessAsUserW/broker ilə düzgün hədəf sessiyada helper başlat. Faktiki SessionId və qeydiyyatlı user SID təsdiqlənmədən input göndərmə. Secure desktop ACL-lərini zəiflətmə.
- İşləyən etalon axınını saxla: kilidli Default pərdəyə PIN-siz klik → Winlogon təsdiqi → uyğun PIN fokusunda bir dəfə input → faktiki unlock təsdiqi. Hello açdıqda əlavə PIN/Enter göndərmə. UAC ekranına credential yazma.
- Ayrı user/service və SYSTEM/helper kanalları, protected binary/ACL, dar IPC, timeout və pre-transfer peer auth tətbiq et. X bağlananda tray-da qalma və boot/startup üçün minimum prototip qur; pro UI dizaynı sonrakı C mərhələsidir.
- Yanlış SID/session, kilidsiz desktop, timeout və təkrar əmr testləri olsun. Real PIN yalnız operator lokal daxil edir; prompt/source/log/telemetry-yə düşmür.

## 3. Telemetriya sender və müstəqil collector

- Bootstrapper ilk kod icrasından installer stage eventləri; ayrı reporter/collector prosesi; crash olsa belə qalan outbox göndərilməsi.
- Davamlı, ölçü/müddət limiti olan outbox; sender retry/backoff; ACK-dən sonra silmə; serverdə davamlı event_id dedup. İnternet/telemetry xətası əsas funksiyanı dayandırmasın.
- ShellExecuteEx elevation nəticəsi, UAC rəddi, installer failure və pre-execution SUSPECTED_STALL fərqini saxla.
- Ayrı proses crash/restart, offline replay, duplicate delivery, disk limit və secret canary testləri işlə. Sağlam şəbəkədə event-to-admin latency-ni timestamp-lərlə ölç; disk append vaxtını admin latency kimi göstərmə.
- PIN/token/private key/raw memory dump yığma. Admin üçün redacted timeline və xəta kodu→təlimat minimum axını hazırla.

## 4. Tauri installer və clean-PC hazırlığı

- Tauri 2+React minimal işlək UI, user-channel service status, installer/bootstrapper build artifact-ləri yarat. Tək WebView2 qovluq yoxlaması installer sübutu deyil.
- WebView2 detection/provisioning, istifadəçi/admin konteksti, installer rollback/uninstall və log mərhələləri olsun. Hazır runtime-ni istifadəçinin hostundan silmə.
- Clean VM mümkündürsə real install/launch/uninstall testini icra et. Yoxdursa bütün installer artifact-ləri və dəqiq operator əmrlərini hazırla, yalnız icra NOT_TESTED qalsın.
- Unsigned test build-i signed production release kimi təqdim etmə. Signing private key uydurma və source-a qoyma.

## 5. İzolyasiya edilmiş test gateway və qeydiyyat

- Private owner admin və device-scoped public/mobile gateway sərhədləri üçün minimum endpoint/backend və sadə Lock/Unlock mobil ekranı hazırla. Mövcud production Sites audience/secret-lərinə toxunma.
- Cihaz private key-ni lokal yaratsın, public key qeydiyyatı/imzalı challenge və qısaömürlü birdəfəlik QR pairing olsun. PC-də açılmış enrollment və yerli təsdiq olmadan mobil token verilməsin.
- Token credential-i faktiki serverdə yoxlansın: cihaz təcridi, expiry/revoke, rate limit, replay və concurrent claim davamlı/atomik şəkildə test edilsin. Shared admin/Sites bypass key EXE/JS/QR-a qoyulmasın.
- İki Sites layihəsinin cari platforma imkanlarını rəsmi sənəd/tool sübutu ilə yoxla. Access/deploy mümkün deyilsə local HTTP inteqrasiyası və deploy edilə bilən artifact hazırla; Sites platforma dəstəyi hələ NOT_VERIFIED qalsın. Lokal modeli Sites testi adlandırma.
- Admin owner icazəsi və server-only admin API ayrı olsun. Test açarları production-dan ayrı, git/source/log-dan kənar saxlanılsın.

## İş rejimi və icazələr

- Mühit/toolchain/VM/elevation imkanlarını əvvəl yoxla. Çatışmayan kodu yazmadan maneəni “admin lazımdır” kimi təqdim etmə.
- Hazırlama, lokal build və testləri avtonom davam etdir. Production publish, şəxsi hostda xidmət/startup quraşdırma, paylaşımı genişləndirmə və destructive əməliyyatları səssiz etmə. Test VM varsa yalnız onun daxilində test xidmətlərini quraşdır; native icazələrə riayət et. Operator addımı lazımdırsa konkret artifact/əmr/risklə bildir, digər paketləri işləməyə davam et.
- Mock/model, real API, real proses/HTTP inteqrasiyası, VM və fiziki PC ayrı etiketlənsin. “Keçdi” yalnız həqiqətən işləyən assert/test üçündür. Missing env və failed test gizlədilməsin.
- Mövcud sübutları əvəzləmə. Bu icra üçün plan/reports/B/batch/ qovluğu yarat. Hər paketdə mənbə, build artifact yolu, test command/exit, redacted raw log, SHA256 və qalan maneələr saxla.
- Repository/alt-qovluq qaydalarını oxu. Mövcud olmayan alət/model/deploy və ya sahibi təsdiqlənməmiş qərar uydurma.

## Sonda təqdim et və dayan

plan/reports/B_BATCH_REPORT.md yaz:
1. Beş paket üzrə DONE/PARTIAL/BLOCKED matrisi və konkret artifact keçidləri.
2. Hər qəbul meyarı üçün real sübut və ya NOT_TESTED səbəbi.
3. Tapılan/qalan P0/P1-lər; regressiya nəticələri.
4. Operatorun etməli olduğu qısa nömrələnmiş addımlar; build artifact hazır olmadan “test et” demə.
5. Repo/hash manifesti və növbəti audit üçün reproduksiya əmrləri.

B hesabatını və statusu dürüst yenilə, Codex acceptance fayllarını dəyişmə. Codex toplu audit etmədən B-ni ACCEPTED və C-ni başlamış göstərmə. Beş paketin sonunda READY_FOR_AUDIT və ya PARTIAL təqdim et; alt-paketdən sonra təkrar icazə gözləyib dayanma.
