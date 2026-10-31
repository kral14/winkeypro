# Worker trust və inteqrasiya — qalıq bloklar

Codex ZIP adlarını yoxladı: private key adı artıq yoxdur, pre-signed manifest/sig var. Bu alt-düzəliş qorunsun. Lakin aşağıdakı yeni arxitektura qalıqları real məhsul qəbulunu bloklayır; əsas toplu tapşırıq qüvvədədir.

## P0: SYSTEM worker üçün istifadəçi yazılan slot/helper
Installer versions/slot_a service+helper-i ProgramData daxilində saxlayır, sonra bütöv DataDir-ə enrolled OwnerSid üçün (OI)(CI)M verir. Worker SYSTEM kimi buradan işləyir və lock_engine::find_helper_exe current_exe.parent() daxilindəki helper-i tapır. Signed verification-dan sonra istifadəçi faylı dəyişdirə bilər; helper hər launch zamanı hash/signature ilə yenidən bağlanmır. Code/manifest/journal/slot pointers üçün SYSTEM/Admin-only qorunan ayrı tree qur; user-writable logs/settings ayrıca olsun. TOCTOU/reparse/rename və standard-user modification mənfi testləri əlavə et. Private key-in mənbədə saxlanması production deyil, release CI secret müqaviləsi ayrıca göstərilsin.

## P1: host/worker status və faktiki sağlamlıq
- SCM PAUSE/CONTINUE handler hostun PAUSED flag-ini dəyişir, poller isə ayrı child prosesindədir. Pause child-a authenticated IPC/control ötürülmədikdə SCM pause işləmir; real host+child test əlavə et. SCM STOP və bounded child/grandchild cleanup da yoxlanılsın.
- Host probation yalnız child.try_wait ilə 5 saniyə yaşamasına əsaslanır. IPC/poller thread ölsə və ya pipe yaradılmasa worker loop canlı qala bilər, host yenə commit edər. Child PID-bound actual health request/response və readiness/probation tələb olunur. HOST_LKG_SPAWN logu spawn-dan əvvəl yazılır: test markerə yox, child PID/executable/health təsdiqinə baxsın.
- Native test iki fərqli versiya build-i deyil, eyni binary+crash.marker işlədir. Bu faydalı REAL_PROCESS_FAULT_INJECTION-dır; release version compatibility/actual update download/activate sübutu deyil.

## Native service -> yeni production gateway
main.rs run_gateway_poller_loop actual request/result payload və auth müqaviləsi yeni deploy/gateway_production_server.py ilə inteqrasiya testində yoxlanılsın. Testdə HTTP client-in özünün success=True göndərməsi native icra sübutu deyil. Real worker nonphysical mock action alıb result qaytarsın, sonra mobil token result oxusun. Owner approval, revoke, pause və offline/reconnect bu eyni yol üzrə sınaqdan keçsin. Təhlükəsiz test heç vaxt lock/unlock/input etməsin.

Codex cargo test sandboxda 4 PASS/2 FAIL aldı, səbəb durable replace OS5; bunu environment-specific NOT_VERIFIED göstər, production ACL-ni zəiflətmə. ZIP key-name yoxlaması secret-byte scanning/CI secret storage qəbulunu əvəz etmir.

Bütün mümkün qalıqları birlikdə düzəlt; aktual source-entrypoint/test matrisi və yeni revision artefaktı ver. Fiziki Windows açılışı, clean VM SCM və WAN/Sites yoxdursa NOT_TESTED/PARTIAL qalsın. Yeni dar test sayını bütün məhsulun bitməsi kimi təqdim etmə.
