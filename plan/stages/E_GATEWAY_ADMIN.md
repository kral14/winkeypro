# E — Çoxistifadəçili gateway və şəxsi admin

Status: NOT_STARTED — gate bağlıdır
Asılılıq: D. İcraçı: Gemini. Qəbul: Codex.

## Tapşırıqlar
- Qəbul edilmiş Sites ayrımını qur; mövcud private admin audience-ni saxla.
- Device key/proof, register, heartbeat, queue/result, revoke, rate-limit, audit log.
- Admine qeydiyyat, PC adı, online və versiya göstər; PIN göstərmə/qəbul etmə.

## Məcburi qəbul meyarları
- [ ] İki ayrı istifadəçi ilə IDOR/tenant isolation və admin access testi keçir.
- [ ] İctimai EXE/PWA-da şəxsi Sites bypass tokeni yoxdur.
- [ ] Replay/expiry/invalid key rədd edilir, hər cihaz ayrıca revoke olunur.

## Hesabat/gate
plan/reports/E_REPORT.md — REPORT_TEMPLATE.md üzrə; sübutlar reports/E/ altında. Codex audit/E_ACCEPTANCE.md daxilində ACCEPTED yazmadan növbəti mərhələyə keçmə. Real Windows testi ilə mock/simulation ayrı göstərilir.


## Məcburi diaqnostika/support əlavəsi
- DIAGNOSTICS_SUPPORT.md üzrə restricted ingest, dedup, owner-only incident/timeline və versiyalı support instructions qur.
- [ ] Admin yalnız öz panelindən stage/error/version görür; cihaz digərinin loguna və admin API-yə daxil ola bilmir.
Müqavilə: plan/DIAGNOSTICS_SUPPORT.md.
