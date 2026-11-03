# WinKey Pro admin paneli və OTA telemetriyası

2026-11-04, Bakı vaxtı.

- Admin panelinə cihaz axtarışı, filtrlər, səhifələmə, cihaz detalları, hadisə zaman xətti və yenilənmə tarixçəsi əlavə edilib.
- Windows xidmətinin telemetriya növbəsi şəbəkə göndərişini arxa planda edir. Proseslərarası mutex alınmadıqda növbə oxunmur və dəyişdirilmir. Server eyni cihazın təkrar göndərdiyi hadisə ID-sini ikinci dəfə yazmadan təsdiqləyir.
- Son yoxlamada `cargo check` və `python -m pytest tests/test_admin_expansion.py -q` keçdi. Admin API nəticəsi 8/8. Gemini 33 Rust və 8 brauzer sınağının keçdiyini bildirdi. Həmin nəticələr son Codex düzəlişlərindən əvvələ aiddir.
- Lokal önizləmə son yoxlamada cavab vermədi. Yenilənmiş xidmət binarından real OTA hadisəsinin admin tarixçəsinə çatması açıq qəbul sınağıdır.
- Git-dəki mövcud imzalı Windows paketi 0.1.16 olaraq qalır. Yeni Windows telemetriya kodunun binara daxil olması üçün ayrıca imzalı build tələb olunur.

Növbəti qəbul addımı lokal paneli yoxlamaq və təcrid olunmuş Windows mühitində faktiki OTA keçidinin admin tarixçəsində `UPDATE_COMMIT_DONE` yaratdığını təsdiqləməkdir.
