# B.2a — Codex audit

Qərar: CHANGES_REQUESTED. Tarix: 2026-10-28. Statik mənbə/test yoxlamasıdır; auditor runner-i yenidən icra etməyib.

Overlapped I/O, cancellation, bounded framing və real susan peer testləri əlavə edilib. Lakin üç boşluq qalır:

1. P1 — session_ipc.rs:874 FlushFileBuffers(h_server) sinxron və deadlinesizdir. Oxumayan client bu çağırışda serveri yenidən bloklaya bilər; FILE_FLAG_OVERLAPPED bunu asinxron etmir. Yazı nəticəsi :873 let _ ilə itirilir. Flush-u bu request/reply yolundan çıxar; qarşı tərəfin frame-i qəbul etməsi üçün bounded tətbiq ACK protokolu qur və ACK gələndən sonra disconnect et. Yazı xətasında uğur qaytarma. Test yalnız aşağı I/O primitive yox, məhz tam execute_secure_ipc_roundtrip yolunda cavabı oxumayan client ilə işləsin.

2. P1 — read/write/connect WaitForSingleObject-nin TIMEOUT-dan başqa xəta branch-lərində pending OVERLAPPED əməliyyatı cancel/drain edilmədən event bağlanır və stack/buffer buraxılır (məsələn :564–566, :645–647). Pending I/O hər çıxışda tamamlanmalıdır; eyni cleanup guard/helper istifadə et. API xəta yolunu idarə olunan fault injection ilə test et; CancelIoEx/GetOverlappedResult nəticələrini düzgün təsnif et. Cancel requested əməliyyat artıq bitibsə ERROR_NOT_FOUND ayrıca nəzərə alınsın.

3. P2 — read_framed_message header və body üçün timeout-u sıfırdan başlayır; write da eynidir. Bütün frame/request üçün bir Instant deadline ötür. Hazır testlər yalnız elapsed>=450ms yoxlayır, yuxarı hədd yoxlanmır; 35s watchdog 500ms müqaviləsini sübut etmir. Gecikdirilmiş header+body və tam roundtrip üçün aşağı/yuxarı müddət assert-ləri əlavə et (real Windows scheduling üçün ağlabatan toleransla).

B.2b server autentifikasiyası/DACL hələ açıqdır. B.1 qəbulu qüvvədədir; B PARTIAL, C bağlıdır.

## Reviziya 2 yoxlaması

FlushFileBuffers çıxarılıb, frame/read/write üçün vahid deadline və vaxt həddi assert-ləri əlavə edilib. Bu hissələr uyğundur. Tam qəbul hələ verilmir:

- drain_and_cancel_overlapped CancelIoEx üçün ERROR_NOT_FOUND-dan başqa xətanı boş branch-də itirir; GetOverlappedResult nəticəsi də yoxlanmır. Sadəcə helper-i çağırmaq təsdiqlənmiş cleanup deyil. Terminal completion nəticəsini təsnif və qaytar; pending yaddaşı tamamlanmadan buraxma. Testdə helper void olduğu halda sadəcə çağırışdan sonra true yazmaq cleanup sübutu deyil.
- ACK match Ok(_) olduğu üçün istənilən frame, hətta boş frame uğur sayılır. Yalnız dəqiq APP_ACK qəbul edilməlidir.
- Client raw h_client açıldıqdan sonrakı write/read/parse/ACK `?` çıxışlarında handle bağlanmır; server_thread də join edilmədən buraxılır. RAII handle və bütün error çıxışlarında thread/IO teardown tələb olunur. Təkrar timeout sınağında process handle count sabit qalmalıdır.

Növbəti tapşırıq GEMINI_B_REVISION.md-dədir. Yalnız bu qalıqlar bağlanmalıdır; əvvəlki işləyən timeout/framing testlərini yenidən yazmağa ehtiyac yoxdur.

## Reviziya 3 audit nəticəsi

Qərar: CHANGES_REQUESTED (statik yoxlama; auditor runner-i icra etmədi). Dəqiq APP_ACK və client RAII düzəlişi təsdiqləndi. İki yoxlanabilən qalıq var:

1. drain_and_cancel_overlapped ERROR_NOT_FOUND olduqda GetOverlappedResult nəticəsini yoxlamadan AlreadyCompleted qaytarır. Terminal nəticə prioritet olmalıdır; ERROR_NOT_FOUND özü tamamlanmanın sübutu deyil. Test üçün pending event-i bağlama: nüvənin istifadə etdiyi hEvent tamamlanmaya qədər açıq qalmalıdır. WAIT_FAILED-i wait adapterinin nəticəsinə injection ilə yarat, canlı event-i qoruyaraq cancel/drain et. Terminal xəta üçün yanlış uğur təsnifatı mənfi testi əlavə et.
2. Test 13-dəki 50 policy-rejected request client write/read/parse/ACK xəta çıxışlarını yoxlamır: bunlar normal serialize edilmiş error cavabı və APP_ACK ilə bitir. Client error çıxışlarına ayrıca fault injection lazımdır. Server ready timeout `?` hələ join yolundan əvvəldir; join nəticəsi də let _ ilə itirilir. Bütün exit-lər ümumi teardown-dan keçsin, server panic error kimi yayılsın. “Bounded join” yalnız recv_timeout+şərtsiz join deyil; qalan server əməliyyatlarının deadline daxilində bitdiyi ölçülsün.

ACK/RAII qəbulu geri alınmır; yalnız bu iki qalıq bağlanmalıdır. B.2b açıqdır.
