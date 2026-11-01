# Bir əmrlə build və buraxılış

```powershell
python .\build.py
```

Standart axın: service/helper/Tauri build → mövcud yerli açarla imza → setup və update ZIP → mənbə ilə imzalı paketin eyni Git commit-də main-ə push edilməsi → paneldə aktiv Git auto-deploy → VM startup-da paketin yoxlanıb import edilməsi → proqramlara WebSocket yenilənmə bildirişi.

Yalnız `deploy/windows_release/WinKeyUpdate.zip` binar paket kimi Git-ə daxil edilir. Private signing key, .env, PIN/config, bazalar, loglar, target/node_modules və backup-lar göndərilmir. Köhnə mənbə fayllarının silinməsi də snapshot-a tətbiq edilir. Force push yoxdur; GitHub-da alınmamış kod varsa build dayanır.

Server ayrıca admin açarı və əl ilə fayl daşıma tələb etmir: imzalı paket Docker image-də `/app/windows_update.zip` olur. VM-də daha yeni buraxılış varsa köhnə image onu downgrade etmir. Offline agent qoşulanda son release-i alır. Git push-un bitməsi VM deploy-un bitməsi demək deyil; panelin deploy nəticəsini də yoxlayın.

## Seçimlər

- `python build.py --check`: tələbləri yoxlayır; build/push/deploy etmir.
- `python build.py --local-only`: yalnız yerli setup və update ZIP yaradır.
- `python build.py --version 0.1.2`: dəqiq versiya. Susmaya görə son yerli manifestin patch hissəsi artırılır.
- `--publish SERVER`: əvvəlki birbaşa admin API yolu saxlanılıb; standart Git→VM axını üçün lazım deyil.

## Bir dəfə tələb olunan keçid

Köhnə Windows proqramına bu avto-update dəstəyini əlavə etmək üçün yeni setup bir dəfə quraşdırılır. Sonrakı buraxılışlar avtomatik qəbul edilir. Sabit recovery/host bootstrap özü runtime yenilənmir; onun dəyişiklikləri installer ilə edilir.

Host işləyən input əməliyyatını yarıda kəsmir: receipt-lərin bitməsini gözləyir, keçiddən əvvəl PAUSE və təkrar idle yoxlaması edir. A/B probation/rollback qalır. Desktop yalnız COMMITTED slotun imza/hash yoxlamasından sonra seçilir; açıq Tauri restart edir. PIN və pairing saxlanır.

## VM yaddaşı

Compose-da `updates_data:/updates` qalıcı volume-u var. Dockerfile-only paneldə də bu mount əvvəlki release-lərin saxlanması üçün tövsiyə olunur. Yeni boş volume yaransa, Git commit-dəki son imzalı paket startup-da yenidən import edilir; köhnə release faylları isə volume olmadan qorunmur. PostgreSQL cihaz və telefon sessiyalarını saxlayır, Windows binarları DB-yə yazılmır.

Lokal bare Git-də real commit/push və real Docker startup testləri keçirilib. Canlı GitHub release push-u bu yoxlamalarda icra edilməyib. Real SYSTEM hot-switch və real GUI restartı ayrıca canlı sınaq tələb edir; setup avtomatik açılmır.
