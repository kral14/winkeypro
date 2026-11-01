# Cari layihə quruluşu

| Yol | Məqsəd |
| --- | --- |
| `run.py` | Tauri dev rejimini compile/başlatmaq |
| `build.py` | Windows xidmət/helper/desktop və tək setup build-i |
| `apps/desktop_tauri/` | Aktiv Windows interfeysi |
| `apps/winkey_service/` | Aktiv native xidmət, IPC, recovery |
| `pc_agent/` | Aktiv helper, fokus və işlək unlock mühərriki |
| `deploy/` | VM gateway, mobil/admin UI, PostgreSQL, Docker ayarları |
| `installer/` | NSIS və helper PyInstaller spec-i |
| `tests/` | Cari testlər; `integration/`, `legacy/` ayrıca |
| `scripts/` | Yardımçı alətlər; köhnə frontend preview `preview/` altında |
| `experiments/spike/` | Əvvəlki texniki spike mənbələri |
| `legacy/` | Aktiv build-dən ayrı köhnə layihələr |
| `docs/` | İstifadə və quruluş təlimatları |
| `plan/` | Cari Gemini tapşırığı, audit və tarixi hesabatlar |
| `dist/WinKeySetup.exe` | Cari tək quraşdırıcı |
| `backups/` | İşlək etalon ZIP, əvvəlki işlək installerlər, mənbə ehtiyatları |
| `.dev-runtime/`, `build/` | Yerli iş məlumatları və bərpa oluna bilən yığım/test çıxışları |
| `.github-publish/` | Məxfi məlumatlardan təmiz GitHub checkout; avtomatik silməyin |

İmzalama açarları, yerli bazalar və DPAPI konfiqurasiyası GitHub-a daxil edilmir.
Quruluş dəyişikliyi runtime/service quraşdırmasını dəyişmir. Tarixi hesabatlar
köhnə yolları göstərirsə, bu cədvəli cari yol xəritəsi kimi qəbul edin.
