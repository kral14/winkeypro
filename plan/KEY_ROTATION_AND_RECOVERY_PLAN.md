# WinKey Pro: Ed25519 Rəsmi İmzalama Açarı Bərpa və Təhlükəsiz Keçid Planı

**Tarix:** 2026-11-02  
**Mövzu:** Runtime Pinned Key (`56524c10...`) və Yerli Build Açarı (`4c7fa3c7...`) Uyğunsuzluğu  

---

## 1. Mövcud Vəziyyət və Diaqnoz

Sistemdə iki fərqli Ed25519 açar cütü aşkarlanmışdır:

| Açar Növü | 32-Bayt Public Key (Hex) | Yerləşdiyi Yerlər |
| :--- | :--- | :--- |
| **Runtime Pinned Key** (Rəsmi İstehsalat) | `56524c1040e3a8309e938332037d0a0167cc2da30761abcfb77c93a899ad61da` | - Windows Xidməti (`recovery_engine.rs`)<br>- Masaüstü UI (`slot_update.rs`)<br>- Yenilənmə Serveri (`deploy/update_repository.py`)<br>- Cari manifest (`deploy/pre_signed_slot_a/manifest.sig`) |
| **Yerli Build Açarı** (Diskdəki Fayl) | `4c7fa3c7a37b79b840e939741138f0748087ae0f06fa94e728557ec2a558fc54` | - `deploy/keys/prod_release_ed25519_key.bin` (private)<br>- `deploy/keys/prod_release_ed25519_pub.hex` (public) |

### Təhlükə / Problem
`build.py` imzalama mərhələsində diskdəki `deploy/keys/prod_release_ed25519_key.bin` faylından istifadə edir. Bu fayl `4c7fa3c7...` ictimai açarına uyğundur.  
Əgər bu açarla yeni paket imzalansa, quraşdırılmış tətbiqlər (xidmət və masaüstü) və yenilənmə serveri həmin imzanı **rədd edəcək (`E_INVALID_SIGNATURE`)**, çünki onların kodunda `56524c10...` açarı sabit qeyd olunub (pinned).

**Görülən tədbir (Fail-Closed):**  
`build.py` daxilinə `check_signing_key_consistency()` yoxlaması əlavə edildi. Açarlar uyğunlaşana qədər rəsmi build və imzalama icra olunmur, xəta ilə dayanır.

---

## 2. Həll Yolu A — Orijinal Açarı Bərpa Etmək (Tövsiyə Edilən)

Ən risksiz və quraşdırılmış tətbiqləri yenidən quraşdırmağa ehtiyac qoymayan yoldur.

1. **Axtarış mənbələri:**
   - CI/CD platforması (GitHub Actions Secrets: `RELEASE_SIGNING_KEY`, `PROD_ED25519_KEY` və s.).
   - Əvvəlki build maşını və ya təhlükəsiz oflayn açar saxlanılan flash-kart/kriptoqrafik anbar.
   - İstehsalat serverinin təhlükəsiz konfiqurasiya ehtiyat nüsxəsi.
2. **Bərpa addımları:**
   - 32-baytlıq xam gizli açar tapıldıqda `deploy/keys/prod_release_ed25519_key.bin` faylına yerləşdirilir.
   - `deploy/keys/prod_release_ed25519_pub.hex` faylına `56524c1040e3a8309e938332037d0a0167cc2da30761abcfb77c93a899ad61da` yazılır.
   - `python -c "import build; build.check_signing_key_consistency()"` icra edilir və uğurla təsdiqlənir.
   - Nəticədə mövcud bütün Windows maşınları avtomatik yenilənmə almağa davam edir.

---

## 3. Həll Yolu B — Təhlükəsiz Açar Keçidi Planı (Key Rotation)

Əgər `56524c10...` gizli açarı itirilibsə və bərpası qeyri-mümkündürsə, sistem yeni `4c7fa3c7...` açarına köçürülməlidir:

### Mərhələ 1: İkiqat Etibarlılıq Dövrü (Dual-Key Acceptance)
Runtime kodunda yalnız bir açar deyil, həm köhnə, həm yeni açar müvəqqəti qəbul edilir:
- `apps/winkey_service/src/recovery_engine.rs`: `ALLOWED_RELEASE_PUBKEYS` siyahısı həm `56524c10...`, həm də `4c7fa3c7...` qəbul edir.
- `apps/desktop_tauri/src-tauri/src/slot_update.rs`: hər iki açarı yoxlayır.
- `deploy/update_repository.py`: hər iki ictimai açarı qəbul edir.

### Mərhələ 2: Yenidən Quraşdırma / Setup Keçidi
Köhnə açarın gizli hissəsi olmadığı üçün köhnə quraşdırılmış tətbiqlər arxadan (avtomatik OTA) yeni açarla imzalanmış paketi qəbul edə bilməz.
- İstifadəçilərə yeni `WinKeySetup.exe` (yeni açarı tanıyan versiya) çatdırılır.
- Yeni quraşdırıcı işə düşdükdə mövcud quraşdırmanı yeniləyir və yeni açarı aktiv edir.

### Mərhələ 3: Köhnə Açarın Dövriyyədən Çıxarılması
Bütün maşınlar keçid etdikdən sonra:
- Kod bazasında köhnə `56524c10...` açarı silinir, yalnız `4c7fa3c7...` saxlanılır.
- `build.py` daxilindəki `RUNTIME_PINNED_PUBKEY_HEX` dəyəri `4c7fa3c7...` olaraq rəsmiləşdirilir.

