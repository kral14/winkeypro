# Qəbul: irəliləyiş və qalan real bloklar

Yeni native worker -> production gateway nonphysical mock action testi actual worker poll/result yolunu işlədir: əvvəlki HTTP-client-only sınağından irəliləyişdir. Protected tree və host control kodu əlavə olunub. Amma aşağıdakı qalıqlar bağlanmayıb; əsas toplu tapşırıq qüvvədədir.

## 1. Native host IPC yenidən bloklanandır (P1)
main.rs send_control_command_to_worker və probe_worker_health FILE_FLAG_OVERLAPPED olmadan CreateFileW açır; sinxron ReadFile/WriteFile/FlushFileBuffers vaxt həddi olmadan çağırılır. STOP handler belə sonsuz bloklana bilər. Python supervisor timeout testi native hostu yoxlamır.
- Native bounded overlapped I/O, single deadline, terminal cancel/drain, exact framing/partial I/O, bounded cleanup istifadə et; B spike-dəki qaydaları yeni yola daşı.
- probe_worker_health GetNamedPipeServerProcessId uğursuz olanda rədd etmir; fail-closed et. resp.contains("RUNNING") yerinə strict typed status/request correlation olsun.
- send_control_command_to_worker server PID-ni yoxlamır. Actual child PID/token/path trust binding əmrdən əvvəl təsdiqlə; rogue pipe-a sıfır payload testi əlavə et.
- SCM handler uzun pipe I/O etməsin, control loop-a bounded queue ilə tapşırsın. PAUSE/RESUME yalnız worker ACK və actual state-dən sonra təsdiqlə; uğursuz send-i log edib SERVICE_PAUSED yazmaq kifayət deyil.
- Native host+child nonreply/rogue-PID/STOP/PAUSE/RESUME sınaqları. test_host_worker_health_and_pause.py birbaşa worker pipe-a yazır: actual SCM-host forwarding deyil.

## 2. ACL test və upgrade repair (P0/P1)
test_system_slot_acl_security.py yalnız DryRun markerini yoxlayır, faktiki standard-user deny testi deyil. Symlink testinin unsigned manifest səbəbindən rədd olması symlink guard sübutu deyil.
- icacls /grant:r yalnız sadalanan SID-lərin grantlarını əvəz edir; əvvəlki OwnerSid explicit Modify ACE-ni avtomatik silmir. Upgrade/repair köhnə root/versions/slot explicit grantlarını təmizləməli, yalnız allowlist ACL/owner tətbiq etməli və bütün exit kodlarını yoxlamalıdır. Precreated/reparse ancestor və directory replacement hallarını bağla.
- Actual standard-user token ilə root/versions/journal rename/write/replace rəddi; logs/settings icazəsi ayrıca. VM/səlahiyyət yoxdursa NOT_TESTED göstər, DryRun-u security acceptance sayma.

## 3. Helper verification fail-open
validate_helper_binary manifest yoxdursa, parse xətası varsa, files list/helper entry/hash yoxdursa True verir; manifest imzasını yoxlamır. ProgramFiles üstün helper seçimində məhz manifest olmaya bilər. Expected signed bundle+required helper entry/hash/size məcburi olsun; manifest parse/missing entry/missing sig mənfi testləri actual helper seçmə/launch yolunu yoxlasın. Reparse parent ancestor və TOCTOU qoruması actual protected tree ilə təmin edilsin.

## 4. Qalan məhsul qəbulu
Native gateway test config.json-u Python özü yazır, registration/pairing də HTTP client ilədir. Desktop onboarding -> trusted service provision -> local phone approval -> real worker poll/result/revoke yolu hələ ayrıca sübut tələb edir. Public HTTPS/Sites, owner-only admin, actual update delivery və diagnostics integration üzrə əvvəlki açıq tələbləri IMPLEMENTED/PARTIAL/BLOCKED matrisi ilə bağla. Fiziki unlock/clean VM/WAN NOT_TESTED sərhədlərini saxla.

Yeni evidence revision qovluğunda toplu düzəliş və testlər ver; mövcud 26 suite PASS yalnız onların faktiki əhatəsidir. Şəxsi hostda səssiz SCM install/lock/reboot yoxdur. Codex əvvəlki helper/nonphysical qorunmaları saxlanılsın.
