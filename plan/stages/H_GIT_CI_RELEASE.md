# H — Git, CI, imzalama və release pipeline

Status: NOT_STARTED — gate bağlıdır
Asılılıq: G. İcraçı: Gemini. Qəbul: Codex.

## Tapşırıqlar
- Sahibin seçdiyi Git deposunda branch/tag/release və reproducible build.
- CI testləri, artifact hash, updater signature, Authenticode, canary/beta/stable metadata.
- Private repo tokenini clientə vermədən artifact delivery; signing key yalnız secret store.

## Məcburi qəbul meyarları
- [ ] Clean CI-dan versiyalanmış installer/bundle və imzalar çıxır.
- [ ] Saxta/korlanmış artifact rədd edilir; uğursuz CI stable manifesti dəyişmir.
- [ ] Adi push→test/build, qəbul edilmiş release→stable ardıcıllığı sübut edilir.

## Hesabat/gate
plan/reports/H_REPORT.md — REPORT_TEMPLATE.md üzrə; sübutlar reports/H/ altında. Codex audit/H_ACCEPTANCE.md daxilində ACCEPTED yazmadan növbəti mərhələyə keçmə. Real Windows testi ilə mock/simulation ayrı göstərilir.


## Məcburi diaqnostika/support əlavəsi
- Build/release identity hər diaqnostika hadisəsində izlənir; binary/secrets artifact scan gate-i əlavə et.
- [ ] Support incident→fix release linki var; log export/signing private key artifactə düşmür.
Müqavilə: plan/DIAGNOSTICS_SUPPORT.md.
