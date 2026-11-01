# WinKey Pro

Windows kompüterini telefonla idarə etmək üçün native Windows tətbiqi,
Windows xidməti və mobil veb gateway mənbə kodu.

## Linux VM-də Docker ilə server

Docker Engine, Compose plugin, Git və Python 3 quraşdırılmış VM-də:

```sh
git clone https://github.com/kral14/winkeypro.git
cd winkeypro
python3 deploy/vm/configure.py --domain winkey.example.com
docker compose up -d --build
docker compose ps
```

Domeni öz domeninizlə əvəz edin, DNS-i VM-ə yönəldin və 80/443 TCP portlarını açın.
Tam təlimat: [deploy/vm/README.md](deploy/vm/README.md).
Bu konteyner mövcud Python gateway və onun mobil/admin interfeysini işlədir;
`legacy/web_remote` daxilindəki Sites React dashboard ayrıca köhnə frontend mənbəyidir.

## Mənbə quruluşu

Gündəlik yalnız `run.py` və `build.py` istifadə olunur. Cari quraşdırıcı:
`dist/WinKeySetup.exe`. Tam yol xəritəsi: [docs/PROJECT_LAYOUT.md](docs/PROJECT_LAYOUT.md).
Cari Gemini işi: [plan/GEMINI_WEBSOCKET_BATCH.md](plan/GEMINI_WEBSOCKET_BATCH.md).

- `apps/desktop_tauri` — Windows Tauri interfeysi.
- `apps/winkey_service` — Windows native xidməti və helper komponentləri.
- `deploy` — gateway, Docker VM konfiqurasiyası və SQL.
- `pc_agent` — Python helper və əvvəlki işlək prototip komponentləri.
- `legacy/web_remote` — əvvəlki Sites/Vinext interfeysi; aktiv VM UI deyil.
- `installer`, `build.py` — Windows installer/build axını; helper spec-i installer altındadır.
- `tests`, `scripts`, `experiments/spike`, `plan`, `docs` — sınaqlar, alətlər və sənədlər.
- `legacy` — köhnə upstream/prototiplər; aktiv məhsuldan ayrıdır.

Windows build üçün Rust/MSVC, uyğun WebView2 və installer üçün NSIS lazımdır.
`build.py`-ın yerli `tools/nsis` və imzalama açarı tələbləri var; onlar repository-yə daxil deyil.
Production imzalama açarı, PIN və cihaz/admin giriş açarları ayrıca təhlükəsiz saxlanmalıdır.

## Yoxlama sərhədi

Docker image, nonroot/read-only konteyner, gateway qeydiyyat/cütləşmə və mock əmr
zənciri lokal yoxlanılıb. Canlı VM, WAN telefonu və fiziki Windows unlock ayrıca
sınaq tələb edir. Yerli bazalar, diaqnostik loqlar, backup-lar və release binarları
bu mənbə göndərişinə daxil deyil.
