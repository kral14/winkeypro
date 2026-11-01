# Qəbul blokları — signing key və native worker

## P0: release private key sızması
create_final_batch_zip.py release_ed25519_key.bin-i ZIP-ə əlavə edirdi. Codex yalnız həmin packaging entry-ni çıxardı; saxla. Mövcud ZIP-də private key var: paylama. Açarın baytlarını log/reply-a çıxarma. Bu açarı TEST/COMPROMISED kimi qeyd et; production üçün etibarlı deyil. Yayıldığı məlum deyil, amma artefakt sahibinə artıq açıqdır. Yeni signing trust/key rotation planı hazırla, private key source/release paketinə qoyulmasın; imzalama build/release mərhələsində owner-controlled secret ilə olmalıdır. Mövcud açarı silib sübutu məhv etmə.

Installer runtime python+private key ilə manifest imzalayır; end-user signing qətiyyən düzgün deyil. Build zamanı tam signed manifest/payload hazırla, installer onu native pinned verifier ilə yoxlayıb exact bytes kopyalasın. Python/private key olmayan extracted clean install sınağı. İmza yaranmadan hazırda PASS yazılır; missing signature fail-closed olsun. UTF-8 BOM/manifest serialization müqaviləsi də native verifier-ə uyğun yoxlanılsın.

## P0/P1: worker actual executable yolu
main.rs service_main slot binarını --worker ilə spawn edir, lakin main-də --worker üçün icra branch-i yoxdur; yalnız --standalone/--run-service var. Child usage yazıb çıxa bilər. Host sonra hardcoded slot_a spawn edir və öz IPC/poller-ini də başladır. Bu rollback deyil.
- Düzgün ayrıca worker entrypoint, absolute protected data/config path, host-only lifecycle/SCM STOP propagation, bir IPC/poller sahibi olsun.
- LKG hardcoded slot_a deyil, validated journal last_known_good_slot-dan seçilsin.
- Host child health/probation/crash monitor əsasında commit etsin, öz RUNNING flag-inə görə yox.
- Actual iki fərqli native child build/versiya markerləri ilə candidate -> LKG keçidini sübut et; Python supervisor testini native launcher sübutu adlandırma. --worker regression testini nonphysical safe rejimdə qur.

## Açıq digər qalıqlar
- _drain_and_cancel 200ms wait-dən sonra GetOverlappedResult(False) nəticəsini yoxlamır. ERROR_IO_INCOMPLETE hələ pending-dir; lifetime bitirmə. Kernel completion terminal olmadan buffer/OVERLAPPED/event azad edilməsin.
- storage.rs production build-də WINKEY_TEST_ENV varlığı OS5 ACL xətasını Ok edir. Test injection cfg(test) ilə məhdud olsun, production env bypass olmasın.
- Fresh install testi installer-i çağırmır, Python vasitəsilə slot/manifesti özü yaradır və repo private key istifadə edir. Bu installer baseline sübutu deyil. Actual extracted installer prepare/preflight real code yolunu çağıran safe test hazırla.

Əsas bütün-qalıqlar tapşırığı qüvvədədir. Bu blokları toplu düzəlt, əvvəlki testləri saxla. Yeni ZIP-də private key yoxluğunu avtomatik test et; əvvəlki ZIP-i quarantine/test-only kimi qeyd et və yeni immutable revision artefaktı ver. Özəl açarı heç bir hesabatda çap etmə. Clean VM/SCM/fiziki unlock sübutu yoxdursa NOT_TESTED qalsın.
