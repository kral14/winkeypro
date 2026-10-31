# A — texnologiya və məhsul qərarları

Status: Tauri + React və ayrıca Windows xidməti məhsul sahibi tərəfindən 2026-10-28 tarixində qəbul edildi. A mərhələsinin Gemini hesabatı və müstəqil auditi hələ tamamlanmayıb.

## Tövsiyə
Tauri 2 + React/TypeScript desktop UI; ayrıca Rust Windows supervisor/xidmət və sessiya helper; mobil üçün sadə PWA.
Müasir GUI-ni etibarlı arxa plan işi ilə qarışdırma: tray və frontend framework Windows sessiya/input hüququnu özü həll etmir.

| Seçim | Uyğunluq | Əsas risk |
|---|---|---|
| Tauri 2 + React | Tövsiyə, müasir UI və Rust inteqrasiyası | WebView2 installer və clean-PC testi; ayrıca xidmət lazımdır |
| Electron + React | Uyğun alternativ, Chromium paketlə gəlir, tray/update ekosistemi | Daha iri paket/proseslər; xidmət və rollback yenə ayrıca qurulur |
| Tkinter + PyInstaller | Mövcud işləyən prototip və engine etalonu | Pro UI, installer və etibarlı update üçün əlavə infrastruktur |

Tauri tray/updater dəstəyi bütün məhsulun hazır olduğu demək deyil. B spike-u uğursuz olarsa konkret sübutla Electron və ya Windows-native alternativ yenidən qiymətləndirilir. Framework dəyişmə input probleminin avtomatik həlli deyil.

## Qərar reyestri
| ID | Təklif | Vəziyyət |
|---|---|---|
| ADR-001 | Tauri 2 + React UI | Sahib tərəfindən qəbul edildi — 2026-10-28 |
| ADR-002 | UI-dən müstəqil Windows xidməti | Sahib tərəfindən qəbul edildi — 2026-10-28 |
| ADR-003 | İlk hədəf Windows 11 x64; Win10 x64 ayrıca sertifikasiya | Sahib qərarı gözlənilir |
| ADR-004 | ARM64, Server, S-mode və BitLocker/preboot ilk release xaricində | Təklif |
| ADR-005 | Private admin Site + ayrıca public gateway/mobile Site | B texniki sübut tələb olunur |
| ADR-006 | PIN yalnız PC-də, server/admin/mobile-a açıq qaytarılmır | Məcburi |
| ADR-007 | Git push → CI; qəbul edilmiş imzalı release → stable update | Tövsiyə |
| ADR-008 | Vahid supervisor updater, A/B slot, müstəqil watchdog | B/I sübut tələb olunur |
| ADR-009 | Mövcud engine etalonu qorunur, səssiz rewrite yoxdur | Məcburi |
| ADR-010 | Gemini implementator, Codex auditor | İstifadəçi tələbi |

| ADR-011 | Installer ilk mərhələsindən structured telemetry, offline outbox və admin support dövrü | Sahibin məcburi tələbi — 2026-10-28 |

DIAGNOSTICS_SUPPORT.md hadisə, məlumat qorunması, göndərilmə və admin təlimat müqaviləsidir.

## Açıq məsələlər
Git hostu/depo və release sahibi müəyyən edilməlidir. Sites-in source deposu ümumi tətbiq release deposu deyil.
Windows Authenticode sertifikatı və updater signing açarı ayrı ehtiyaclardır; əldə edilmə/imzalama yolu seçilməyib.
Gemini əlaqə kanalı seçilməlidir: PATH-də gemini CLI və uyğun tool tapılmadı; heç bir Gemini icrası iddia edilmir.
Bütün PC-lərdə sıfır xəta vədi verilmir. Dəstəklənən OS/hardware matrisi və ölçülən qəbul meyarları əsasdır.

## Rəsmi mənbələr
- https://v2.tauri.app/learn/system-tray/
- https://v2.tauri.app/plugin/updater/
- https://v2.tauri.app/reference/webview-versions/
- https://www.electronjs.org/docs/latest/tutorial/updates
- https://learn.microsoft.com/en-us/windows/desktop/services/interactive-services

