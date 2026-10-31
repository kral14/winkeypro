# B — Ən riskli imkanların texniki sübutu

Status: READY_FOR_IMPLEMENTATION — A qəbul edilib; icra hələ başlamayıb
Asılılıq: A. İcraçı: Gemini. Qəbul: Codex.

## Tapşırıqlar
- İzolyasiya edilmiş spike: Session 0 service → düzgün user sessiyası → Default klik → Winlogon helper.
- Tauri/WebView2 clean-PC install və normal user UI + ACL-li service IPC sübutu.
- İki Sites layihəsi, server-only admin əlaqəsi və cihaz-scoped auth üçün cari platforma dəstəyini yoxla. Production audience-ni səssiz dəyişmə.
- A/B bundle, atomic activation və independent recovery üçün minimum prototip təqdim et.

## Məcburi qəbul meyarları
- [ ] Ən az bir fiziki PC və clean VM üzrə reproduksiya/evidence var.
- [ ] Yanlış SID/session və Session 0-a input rədd edilir.
- [ ] Ümumi EXE-də shared admin/bypass key tələb olunmur.
- [ ] Uğursuz texniki fərziyyə alternativ və ADR düzəlişi ilə açıq göstərilir.

## Hesabat/gate
plan/reports/B_REPORT.md — REPORT_TEMPLATE.md üzrə; sübutlar reports/B/ altında. Codex audit/B_ACCEPTANCE.md daxilində ACCEPTED yazmadan növbəti mərhələyə keçmə. Real Windows testi ilə mock/simulation ayrı göstərilir.


## Məcburi diaqnostika/support əlavəsi
- Before-service installer error→collector→gateway→admin minimum spike; process crash və offline replay proof.
- [ ] Sağlam şəbəkədə event-to-admin latency ölç; başlanmadan OS tərəfindən bloklanma ilə installer fail-i ayır.
Müqavilə: plan/DIAGNOSTICS_SUPPORT.md.

## A auditindən məcburi qəbul əlavələri
plan/audit/A_ACCEPTANCE.md daxilindəki B dəqiqləşdirmələri bu mərhələnin qəbul meyarlarına daxildir.

