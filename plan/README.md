# WinKey Pro — mərhələli iş planı

**Cari iş (2026-11-01): `GEMINI_WEBSOCKET_BATCH.md`.** Aşağıdakı A mərhələsi
qeydləri tarixidir. Cari quruluş üçün `docs/PROJECT_LAYOUT.md` oxuyun.

Tarix: 2026-10-28, Asia/Baku. Aktiv mərhələ: A — məsləhət. Yeni məhsulun implementasiyası başlanmayıb.
İcraçı: Gemini. Auditor və mərhələ qəbulçusu: Codex. Məhsul sahibi: istifadəçi.

## İstifadə
1. STATUS.md və STATUS.json: haradayıq, nə qalıb.
2. DECISIONS.md və ARCHITECTURE.md: qərarlar və sərhədlər.
3. GEMINI_START_HERE.md və GEMINI_RULES.md: icraçıya veriləcək tapşırıq.
4. stages/: A–K scope, test və qəbul şərtləri.
5. reports/: Gemini hesabatları; audit/: Codex qəbul qeydləri.
6. TEST_MATRIX.md və UPDATE_ROLLBACK.md: uyğunluq və etibarlılıq müqaviləsi.

## Tələb edilən məhsul
İstifadəçi imzalı EXE installerini yükləyir → PC adı avtomatik gəlir, istəsə dəyişir → Windows PIN/parolunu yerli yazır → qeydiyyatı tamamlayır → QR-ni telefonla oxudur → iki düyməli mobil PWA-dan Kilidlə/Kilidi aç edir.
X pəncərəni traya gizlədir. Xidmət Windows boot zamanı başlayır, tray istifadəçi login zamanı görünür. İmzalı release avtomatik alınır; kritik namizəd-versiya xətasında son işlək versiyaya qayıdılır.
Admin panelinə yalnız sahib daxil olur. Digər istifadəçilər yalnız öz cihazlarının mobil idarəsinə giriş alır. PIN adminə/serverə getmir.

## İş qaydası
Gemini yalnız bir aktiv mərhələ işləyir → sübutlu hesabat verir → Codex diffi/testləri müstəqil yoxlayır → ACCEPTED və ya CHANGES_REQUESTED yazır.
Qəbul qeydi olmadan növbəti mərhələ başlamır. Gemini özünü qəbul edə bilməz.
A məsləhəti qəbul edilmədən tətbiq kodu, Sites paylaşımı, sistem xidmətləri, signing açarları və release ayarları dəyişdirilmir.

## Mövcud baza
- Kilid engine: pc_agent, diag-20261027-6. İşləyən Default → Winlogon axını qorunmalıdır.
- GUI prototip: remote_agent, remote-20261028-3. Hazırda X prosesi bağlayır; boot service, tray, updater və rollback yoxdur.
- Sites: appgprj_6ae0e9db7e9c8191ba58d3348e1c86b0.
- Backup: backups/WinKey_ISLEYEN_diag-20261027-6_2026-10-27_22-04-43.zip.
- Prototip testlərinin keçməsi fiziki PC və kommersiya release qəbulu deyil.

## Hazırkı icra vəziyyəti
Gemini-yə faktiki tapşırıq göndərilməyib: bu sessiyada Gemini tool/CLI aşkar edilmədi. Hazır prompt paketi var. Başqa sessiyada Gemini-yə verilib hesabat bu qovluğa qaytarıla bilər.


## Qəbul edilmiş əlavə tələb — 2026-10-28
Tauri+React və ayrıca Windows xidməti sahib tərəfindən seçildi. İlk installer addımından telemetry, ayrı crash reporter, offline queue, admin problem timeline və support instruction/signed-release dövrü DIAGNOSTICS_SUPPORT.md-də məcburidir. Hazırda yalnız plan dəyişib; sistem implementasiya edilməyib.
