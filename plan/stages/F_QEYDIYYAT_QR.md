# F — EXE qeydiyyatı və QR pairing

Status: NOT_STARTED — gate bağlıdır
Asılılıq: E. İcraçı: Gemini. Qəbul: Codex.

## Tapşırıqlar
- Avtomatik PC adı və istəyə görə dəyişiklik, yerli PIN, qeydiyyatı tamamla axını.
- Qısaömürlü QR challenge, telefonun yerli təsdiqi, revocable device-scoped mobile session.
- Credential/import xətalarını göstər; istifadəçidən manual service-key istəmə.

## Məcburi qəbul meyarları
- [ ] Clean PC-də Python/Node olmadan install→register→QR tamamlanır.
- [ ] Expired/reused/copied QR və yanlış device/user sınaqları var.
- [ ] QR-də PIN, admin key və uzunömürlü device private key yoxdur.

## Hesabat/gate
plan/reports/F_REPORT.md — REPORT_TEMPLATE.md üzrə; sübutlar reports/F/ altında. Codex audit/F_ACCEPTANCE.md daxilində ACCEPTED yazmadan növbəti mərhələyə keçmə. Real Windows testi ilə mock/simulation ayrı göstərilir.


## Məcburi diaqnostika/support əlavəsi
- Anonymous install_run_id-ni device key proof ilə qeydiyyata bağla; adı/şəxsi məlumatı identity sayma.
- [ ] PIN/QR/admin/device sirrləri telemetry-yə düşmür; disclosure və yerli diaqnostika vəziyyəti aydındır.
Müqavilə: plan/DIAGNOSTICS_SUPPORT.md.
