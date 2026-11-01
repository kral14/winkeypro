# Gemini — yalnız B.3 imzalı slot və last-known-good recovery

B.2b qəbul edildi: plan/audit/B2B_AUTH_FINAL_ACCEPTANCE.md. İndi recovery_rollback.rs üzrə əvvəlki açıq tapıntını bağla. Xidmət quraşdırma və reboot tələb olunmur, production dəyişmir.

1. Fallback “əks slot” olmasın: ayrıca son sağlamlığı təsdiqlənmiş versiya/slot və ona bağlanmış signed manifest saxla. Candidate aktivləşməsi onu dərhal known-good etməsin; ayrıca health confirmation tranzaksiyası olsun.
2. Hər seçilmiş launch/fallback öncəsi pinned public key imzası və bütün icra olunan faylların hash-i yoxlanılsın. Activated/Idle/Rollback yolları yoxlamanı keçməsin. Etibarlı fallback yoxdursa fail-closed, heç bir binary başlatma. Slot yolu canonical olaraq workspace test versions qovluğunda qalsın; path traversal/absolute path/reparse escape rədd edilsin. Manifest versiya/slot/target/hash bağlanması tələb olunur.
3. Jurnal/pointer yazıları arasındakı hər checkpoint-də ayrı child prosesi məcburi dayandır, ayrıca recovery prosesi ilə yenidən oxu. Korrupt/missing journal ilə first-install fərqi, əvvəlki imzalı known-good-un seçilməsi və iki slot da korrupt olduqda rədd sınaqları olsun. Simulyasiya edilmiş checkpoint kill real elektrik kəsilməsi deyil.
4. Minimum test supervisor child binary-si yarat (real PIN yoxdur). Recovery məhz doğrulanmış slot binary-sini başlatsın; cmd.exe exit 1 real slot launch sübutu sayılmasın. Valid activation, valid health commit, candidate crash-loop fallback, fallback tamper, untrusted signer, altered manifest, interrupted commit və no-valid-slot mənfi testləri işləsin.

RECOVERY_REVISION.md və ayrıca raw log/test command/exit/hash təqdim et. Mövcud evidence-ni əvəzləmə. SCM boot/service, fiziki PC/clean VM, telemetry/gateway hələ açıqdır. Yalnız B.3-dən sonra dayan. B PARTIAL, C bağlıdır.
