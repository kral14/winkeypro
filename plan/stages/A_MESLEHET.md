# A — Məsləhət və arxitektura qərarları

Status: ACCEPTED — audit/A_ACCEPTANCE.md; 2026-10-28
Asılılıq: yoxdur. İcraçı: Gemini. Qəbul: Codex.

## Tapşırıqlar
- Tauri/Electron/Tkinter müqayisəsini, məhsul axınını və ADR-ləri nəzərdən keçir.
- Admin-private/consumer-mobile ayrımı, credential sərhədi və release risklərini dəqiqləşdir.
- OS matrisi, Gemini kanalı, Git/release sahibi və signing imkanları üzrə açıq qərarları təqdim et.

## Məcburi qəbul meyarları
- [ ] Əsaslandırılmış stack seçimi və B spike planı var.
- [ ] Admin yalnız sahibə, mobil idarə isə yalnız aid cihazın istifadəçisinə açıqdır müqaviləsi yazılıb.
- [ ] A hesabatı və Codex qərarı var; qəbuldan əvvəl tətbiq kodu dəyişməyib.

## Hesabat/gate
plan/reports/A_REPORT.md — REPORT_TEMPLATE.md üzrə; sübutlar reports/A/ altında. Codex audit/A_ACCEPTANCE.md daxilində ACCEPTED yazmadan növbəti mərhələyə keçmə. Real Windows testi ilə mock/simulation ayrı göstərilir.


## Yeni məcburi tələb
DIAGNOSTICS_SUPPORT.md-ni oxu; before-service installer telemetry, ayrı crash collector, offline outbox, admin timeline və support instruction→signed release dövrünü A qərarlarına daxil et. İnternet/OS-before-launch məhdudiyyətini gizlətmə.

