# Avtomatik Windows yenilənməsi

Server source deploy və Windows release fərqli artefaktlardır. Linux VM-dəki Python source deploy-u Windows exe yaratmır. Windows build skripti bunu bir əmrlə birləşdirir:

```powershell
python .\build.py --publish http://158.101.172.228:8080
```

Skript service/helper/desktop-u build edir, manifesti mövcud yerli Ed25519 açarı ilə imzalayır, setup və `dist/WinKeyUpdate-VERSION.zip` yaradır, sonra paketi sahib API-sinə göndərir. Server admin açarı ekranda göstərilmədən soruşulur; yaxud `WINKEY_ADMIN_SECRET` mühit dəyişənindən götürülür. Açar URL/command argumentinə və Git-ə yazılmır. Dəqiq versiya üçün `--version 0.1.2` əlavə edilə bilər; susmaya görə əvvəlki yerli manifestin patch versiyası artırılır. Eyni və aşağı versiya server/client tərəfindən rədd edilir.

## Bir dəfə tələb olunan keçid

1. Yeni server kodunu deploy edin.
2. Bu dəstəyi ehtiva edən yeni `dist/WinKeySetup.exe` paketini mövcud kompüterlərdə bir dəfə quraşdırın. Əvvəlki host binarı yeni WebSocket bildirişini başa düşmür; onun yalnız köhnə periodik yoxlamasına etibar etməyin.
3. Sonrakı release-ləri yuxarıdakı `--publish` əmri ilə yayınlayın. Sadəcə Git push etmək Windows paketini yayımlamır.

## Runtime axını

- `POST /admin/updates/publish`: yalnız admin Bearer açarı. ZIP, pinned Ed25519 imzası, versiya, fayl dəsti, path, ölçü və SHA-256 yoxlanır. Qüsurlu paket aktiv release-i dəyişmir.
- Hazır release `/updates/releases/<manifest-sha256>/` daxilində immutable saxlanır; `current` pointer atomik dəyişir.
- Server qoşulmuş agentlərə `update_available` WS frame göndərir. Offline agent auth zamanı son release-i alır. Serverdə pointer dəyişiklikləri də bir global watcher ilə bildirilir.
- Bildiriş yalnız yoxlamanı oyadır. SYSTEM host əvvəl konfiqurasiyasındakı serverdən manifesti alır, pinned imzanı və versiyanı binarları endirməzdən əvvəl yoxlayır. Fayllar release ID-yə bağlı immutable URL-lərdən gəlir.
- Host 10 saniyəlik debounce ilə bildirişə cavab verir; saatlıq fallback yoxlama qalır. Sağlamlıq sınağı bitməmiş yeni candidate başlamır. Cari input/queue receipt-ləri varsa yenilənmə təxirə salınır; keçiddən əvvəl worker PAUSE və təkrar idle yoxlaması edilir.
- İmzalı A/B slot aktivləşir; mövcud native probation/rollback qaydası qalır. Başlamış əməliyyat yarıda kill edilmir. Yeni masaüstü yalnız COMMITTED slot imza/hash yoxlamasından sonra seçilir; açıq Tauri 15 saniyəlik yoxlama ilə restart edir. PIN və pairing yaddaşı dəyişmir.
- Sabit recovery/host bootstrap installer ilə yenilənir; runtime paketi slot service/helper/runtime/desktop-u yeniləyir. Bootstrap-ın özü avtomatik dəyişdirilmir.

## VM yaddaşı

`/updates` qovluğunu qalıcı volume ilə saxlayın. Compose-da `updates_data:/updates` artıq əlavə edilib. Başqa Docker deploy panelində də `/updates` üçün qalıcı named volume bağlanmalıdır; yeni anonymous volume ilə konteyneri hər dəfə yaratmaq yayımlanmış release-ləri qorumur. PostgreSQL cihaz/session məlumatlarını saxlayır; Windows release binarları bu DB-yə yazılmır. Private signing key yalnız build kompüterində qalır.

Lokal synthetic-package/WS/native-mock və signature/rollback testləri aparılıb. Real kompüterdə SYSTEM hostun slot keçidi və Tauri restartı bu işdə canlı sınaqdan keçirilməyib; installer avtomatik açılmayıb.
