# Gemini icra müqaviləsi

2026-11-01: aktiv batch `plan/GEMINI_WEBSOCKET_BATCH.md`-dir. Sahib bu fayldakı
A–F paketlərini bir dəfəyə hazırlamağa icazə verib; köhnə stage qapıları bu işi
dayandırmır. Aşağıdakı məxfilik, real sübut və son Codex audit qaydaları qalır.
Əvvəlki batch təlimatları `plan/archive/tasks/` altındadır.

1. Əvvəl README, STATUS.json, DECISIONS, ARCHITECTURE və aktiv stage faylını oxu.
2. Yalnız aktiv/açılmış mərhələni icra et. A məsləhətdir: kod, installer/service, public paylaşım, secret və release dəyişmə.
3. Sonrakı mərhələnin asılılığını hesabatda qeyd et; qəbul olmadan scope-u genişləndirmə.
4. Plugin/framework varlığını işləyən məhsul xüsusiyyəti kimi təqdim etmə.
5. Testi həqiqətən işə sal; əmr, exit code, mühit və redacted sübut saxla. Mock, VM, fiziki PC ayrı göstərilir.
6. Mövcud engine/backupı qoru; yeni məhsulu ayrı qovluqlarda hazırla. Hazır Default→Winlogon etalonunu səssiz dəyişmə.
7. PIN, device/service/private signing key, recovery sirri, DPAPI faylı source/log/screenshot/release/prompt/hesabata daxil edilmir. Real test PIN-ini lokal operator daxil edir.
8. İctimai installerə Sites bypass tokeni daxil etmə. UI rendererə geniş shell/FS/IPC səlahiyyəti vermə.
9. Paylaşımı genişləndirmək, xidmət quraşdırmaq və stable release etmək yalnız həmin mərhələnin konkret planı/qəbulu və tətbiq olunan native icazələrlə mümkündür.
10. Mərhələ sonunda reports/<STAGE>_REPORT.md yaz. Evidence reports/<STAGE>/ altında olur. Yalnız READY_FOR_AUDIT və ya blokun səbəbini bildir.
11. Yalnız Codex audit/<STAGE>_ACCEPTANCE.md-də ACCEPTED yazandan sonra növbəti mərhələyə keç. P0/P1 açıq qala bilməz. Özünü qəbul etmə.
12. Tool/CLI səni Gemini-yə bağlamayıbsa faktiki icra/hesabat uydurma. Əlaqə yoxdursa sahibi promptu ayrıca Gemini sessiyasına ötürür və nəticəni geri gətirir.
13. Mövcud monorepo rootunda ümumi AGENTS qaydası yoxdursa belə dəyişdirdiyin alt-reponun AGENTS/GEMINI qaydalarını oxu. RustDesk mənbələri ayrıdır; ehtiyac yoxdursa dəyişmə.


## Sahib istisnası — B–G toplu icra
Sahib B,C,D,E,F,G-ni aralıq audit gözləmədən birlikdə implementasiya etməyə icazə verdi. Bu batch üçün stage-arası stop/gate qaydalarını plan/GEMINI_B_TO_G.md əvəz edir; qəbul və production/native icazə sərhədləri qüvvədə qalır.

## Sahibin növbəti toplu işi
GEMINI_REMAINING_WORK.md qalan real implementasiyanı, H–K üzrə lokal hazırlıq/test işlərini açır. Aralıq audit stop-u yoxdur. Production/public release, signing və şəxsi host sistem dəyişikliklərinin icazə sərhədləri saxlanılır.
