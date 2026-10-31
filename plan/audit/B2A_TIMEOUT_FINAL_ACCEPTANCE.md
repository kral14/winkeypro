# B.2a — yekun məhdud qəbul

Tarix: 2026-10-28. Qərar: ACCEPTED (yalnız Windows Named Pipe spike-nın timeout/framing/cleanup alt-tapşırığı).

Yoxlanılan mənbə SHA256 (session_ipc.rs): 948F464D4CB4B388E24986BC73DAD37A16AC1B98925545CF9A1205C1686E4A35.

Statik yoxlamada terminal status prioriteti, canlı event-i saxlayan wait adapteri, vahid deadline, APP_ACK müqayisəsi, client RAII və ümumi teardown/panic propagation təsdiqləndi. main.rs testləri və IPC_TIMEOUT_REVISION_4.md nəzərdən keçirildi. Auditor test runner-i yenidən icra etmədi; icra nəticələri Gemini-nin təqdim etdiyi sübutdur.

Qəbul sərhədi: FailWrite/FailReadTimeout/FailParse süni return injection-ları error-path cleanup testləridir, həqiqi OS write/read timeout/JSON parse failure sübutu deyil; real timeout primitivləri ayrıca əvvəlki sınaqlardadır. Hesabatda bu fərq saxlanmalıdır. std::thread::join özü timed join deyil; I/O deadline/cancellation altında müşahidə edilmiş sonlanma qəbul olunur, bütün kernel/driver nasazlıqlarına sərt sonlanma zəmanəti verilmir. SYSTEM xidmətində ayrıca watchdog/recovery meyarları qalır.

B.2b server etibarının transferdən əvvəl yoxlanması və dar DACL açıqdır. Real service/helper, fallback doğrulaması, collector/gateway, clean VM meyarları qalır. B ümumi CHANGES_REQUESTED/PARTIAL; C bağlıdır.
