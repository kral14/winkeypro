# D — Windows xidməti, tray və avtomatik başlanğıc

Status: NOT_STARTED — gate bağlıdır
Asılılıq: C. İcraçı: Gemini. Qəbul: Codex.

## Tapşırıqlar
- Supervisor/service, session helper, ACL-li IPC, singleton və reconnect qur.
- X=tray; UI-dən çıxmaq və idarəni dayandırmaq semantikasını ayır.
- Installer boot service/login tray/SCM recovery/repair/uninstall və credential miqrasiyası.
- Default→Winlogon etalonunu regressiyasız inteqrasiya et.

## Məcburi qəbul meyarları
- [ ] X-dən sonra real heartbeat/lock/unlock davam edir.
- [ ] Rebootda service automatic online olur; tray login sessiyasında açılır.
- [ ] Standard user, yanlış SID/session rəddi və clean-PC install sübutu var.
- [ ] Yanlış PIN təkrar olunmur; uninstall autostart/service qalıqları saxlamır.

## Hesabat/gate
plan/reports/D_REPORT.md — REPORT_TEMPLATE.md üzrə; sübutlar reports/D/ altında. Codex audit/D_ACCEPTANCE.md daxilində ACCEPTED yazmadan növbəti mərhələyə keçmə. Real Windows testi ilə mock/simulation ayrı göstərilir.


## Məcburi diaqnostika/support əlavəsi
- Bootstrapper ilk işləyən andan mərhələ start/finish/error, ayrıca crash reporter, davamlı bounded outbox qur.
- [ ] UI crash və service quraşdırılmadan installer failure itmir; restart/offline sonrası replay duplicate yaratmır.
Müqavilə: plan/DIAGNOSTICS_SUPPORT.md.
