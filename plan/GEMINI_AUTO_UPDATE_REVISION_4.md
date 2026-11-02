# Codex: son konkret qəbul qalıqları

Setup MANIFEST_DIR, protokol daşması və handover timeout düzəlişləri kodda mövcuddur. Node UI testi Codex tərəfindən yenidən işləndi: PASS. Tam SCM/OTA bu baxışda icra edilməyib.

## P1 — release publication crash recovery hələ yoxdur

Codex disposable qovluqda production commit_staged_release çağırıb ilk shutil.move-dan sonra child prosesi os._exit(77) ilə dayandırdı. Faktiki nəticə: target-də yalnız manifest.json, manifest.sig YOX; .backup qalır. Main/startup onu bərpa etmir, növbəti commit isə backup-ı başlanğıcda silir. Faylları unlink + ayrı-ayrı move etmək atomik commit deyil.

Düzəlt: davamlı transaction/recovery qaydası qur. Başlanğıcda və hər read/version selection/push-only/publication-dan əvvəl yarımçıq commit bərpa edilsin; yeganə düzgün backup heç vaxt yeni snapshot naminə silinməsin. Yeni və köhnə manifest/imza birlikdə kriptoqrafik yoxlanılsın. Disposable child-process crash testini hər publication keçidində tətbiq et, sonra təzə proseslə recovery çağır və tam köhnə və ya tam yeni release olduğunu sübut et. Test production release fayllarına toxunmasın; bütün yollar temporary root-a yönləndirilsin. Exception-only test kifayət deyil.

## Slot cleanup üzrə qalan açıq sərhəd

clean_lingering_slot_processes hələ birbaşa TerminateProcess edir, canonical protected-slot/reparse yoxlaması yoxdur; yalnız string prefix və basename yoxlanır. İndiki hesabatda graceful çıxış və qorunan kök doğrulaması tamamlanmış sayılmasın. Bunları tamamla və ya avtomatik kill-i çıxarıb kilidli slot üçün təhlükəsiz defer qaytar; yeniləmə mövcud desktop/worker-i zorla bağlamasın. Aktiv/LKG qorunmasını saxla. Test üçün production allowlist-i genişləndirmə.

Yekun hesabatda həqiqətən bağlanan maddələri, konkret yeni log yollarını və NOT_TESTED SCM sınağını göstər. Build/push/deploy/install və canlı xidmətlərə toxunma. İşlək unlock axınını dəyişmə. Bütün qalıqları bir paketdə tamamla.
