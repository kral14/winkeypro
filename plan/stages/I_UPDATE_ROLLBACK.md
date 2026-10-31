# I — Avtomatik update və son işlək versiyaya dönüş

Status: NOT_STARTED — gate bağlıdır
Asılılıq: H. İcraçı: Gemini. Qəbul: Codex.

## Tapşırıqlar
- UPDATE_ROLLBACK müqaviləsi üzrə supervisor coordinator, A/B slot/journal/probation.
- Bundle uyğunluğu, PIN əməliyyatından sonra apply, pis versiya quarantine.
- Offline/server 5xx/yanlış PIN-i rollback triggerindən ayır; supervisor self-update recovery-ni sına.

## Məcburi qəbul meyarları
- [ ] Yarımçıq download, power loss, crash loop, disk/file lock və schema fault injection var.
- [ ] Candidate başlamırsa əvvəlki imzalı bundle avtomatik qalxır; pairing/credential qalır.
- [ ] Eyni pis versiya sonsuz quraşdırılmır; arbitrary downgrade mümkün deyil.

## Hesabat/gate
plan/reports/I_REPORT.md — REPORT_TEMPLATE.md üzrə; sübutlar reports/I/ altında. Codex audit/I_ACCEPTANCE.md daxilində ACCEPTED yazmadan növbəti mərhələyə keçmə. Real Windows testi ilə mock/simulation ayrı göstərilir.


## Məcburi diaqnostika/support əlavəsi
- Download/verify/activate/health/rollback stage-lərini eyni operation correlation ilə adminə ötür.
- [ ] Çökən candidate-in reporteri müstəqildir; telemetry outage yanlış rollback və ya sonsuz retry yaratmır.
Müqavilə: plan/DIAGNOSTICS_SUPPORT.md.
