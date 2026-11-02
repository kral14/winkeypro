# Codex review — CHANGES_REQUESTED

Əvvəlki düzəlişləri qoru. Canlı xidmət/install/push/deploy etmədən aşağıdakı konkret qalıqları birlikdə bağla.

## P1 — Setup köhnə manifesti paketləyir (yeni regression)
build.py main yeni manifesti STAGING_PRE_SIGNED_DIR-də yaradır, commit_staged_release isə step_build_installer-dən SONRA çağırılır. installer/WinKeySetup.nsi:144-145 hələ deploy/pre_signed_slot_a/manifest.* oxuyur. Beləliklə Setup yeni binarlar + köhnə imza/hash ilə çıxır. NSIS-ə manifest mənbəyini açıq parametr ver, staging manifestini paketlə. Köhnə default yalnız uyğun birbaşa NSIS istifadəsi üçün qalsın. Installer inputlarının və update ZIP-in eyni manifest/imza/file hash-ləri ilə uyğunluğunu real build etmədən də disposable packaging kontrakt testi ilə yoxla.

## P1 — Release commit və fault injection
commit_staged_release sadəcə faylları ardıcıl copy2 edir; manifest və sig arasında qəza uyğunsuz release buraxa bilər. Təhlükəsiz publication/recovery mexanizmi qur. Hazır test_build_rollback_integrity.py production build orchestration-u çağırmır: test özünün yazdığı try/except-də özü xəta atıb özü təmizləyir. Main/orchestration-u mock build addımları ilə həqiqətən çağır, compile/sign/installer/package/commit-in hər mərhələsində xəta inject et. Köhnə release və metadata/lock bərpasını, yarımçıq commit-dən bərpanı yoxla. SystemExit yolları da rollback-dən yayınmasın.

## P2 — Handover nəticəsi
wait_for_process_exit artıq Result qaytarır, amma Err olduqda main yalnız warning yazıb işə davam edir. Timeout/AccessDenied üçün əvvəlki prosesə nə olacağı və retry/exit davranışı açıq olsun; uğurlu keçid kimi davam etmə. Singleton/tray-in itmədiyini disposable testlə göstər.

## P2 — Protokol daşması
Həm main.rs, həm recovery_engine.rs min_host_protocol_version u64 dəyərini `as u32` ilə kəsir. 4294967297 → 1 olur və uyğunsuz paket qəbul edilə bilər. checked conversion və ya u64 müqayisə et; overflow/yanlış tip/normal uyğunsuz protokol testləri əlavə et.

## P2 — Slot cleanup tələbi hələ tam deyil
clean_lingering_slot_processes dərhal TerminateProcess edir; qorunan kök/reparse doğrulaması, graceful handoff və dəqiq executable yolu yoxdur. Production allowlist-də test_disposable_desktop.exe saxlanılıb. Yalnız real dəqiq slot executable-larını qəbul et; test hook-ları debug/test kontekstində qalsın. Root/active/LKG yoxlaması və uğursuz termination üçün fail-closed nəticə qaytar. Yeni staging LKG blokunu qoru.

Codex bu baxışda Node UI testini yenidən işlətdi: PASS. Qalan native/SCM testləri bu baxışda icra edilməyib. Hesabatda “hamısı tamamlandı” əvəzinə konkret sübutları göstər. Mövcud işlək unlock axınını dəyişmə. Qalıqları tamamlayıb yeni xam loglarla hesabat ver.
