# J — Uyğunluq, təhlükəsizlik və davamlılıq auditi

Status: NOT_STARTED — gate bağlıdır
Asılılıq: I. İcraçı: Gemini. Qəbul: Codex.

## Tapşırıqlar
- TEST_MATRIX üzrə qəbul edilmiş OS/telefon/şəbəkə matrisini tamamla.
- Installer/boot/tray/UI/QR/isolation/IPC/secrets/updater/rollback regression.
- Uzunmüddətli online/offline/reconnect və resurs ölçmələri.

## Məcburi qəbul meyarları
- [ ] P0/P1 açıq deyil; yoxlanmamış platforma dəstəklənən kimi göstərilmir.
- [ ] Redacted evidence və Codex müstəqil təkrar testi var.
- [ ] Dəstək sərhədləri və məlum məhdudiyyətlər yazılıb.

## Hesabat/gate
plan/reports/J_REPORT.md — REPORT_TEMPLATE.md üzrə; sübutlar reports/J/ altında. Codex audit/J_ACCEPTANCE.md daxilində ACCEPTED yazmadan növbəti mərhələyə keçmə. Real Windows testi ilə mock/simulation ayrı göstərilir.


## Məcburi diaqnostika/support əlavəsi
- Installer step failure, abrupt crash, offline/reboot replay, token/PIN canary scan və admin support dövrünü sına.
- [ ] Event-to-admin P95 hədəfi ölçülüb; əsaslandırılmayan səbəb UI-də suspected kimi göstərilir; live raw dump upload yoxdur.
Müqavilə: plan/DIAGNOSTICS_SUPPORT.md.
