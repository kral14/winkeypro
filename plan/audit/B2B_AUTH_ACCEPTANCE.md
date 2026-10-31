# B.2b — Codex audit

Tarix: 2026-10-28. Qərar: CHANGES_REQUESTED — bir təhlükəsizlik qalığı.

Statik yoxlamada dar user DACL, pre-transfer PID/retained-process/token/path yoxlamaları və client SECURITY_IDENTIFICATION təsdiqləndi. Hesabat/0-payload testləri nəzərdən keçirildi. Auditor runner-i yenidən icra etmədi; SYSTEM/protected install və başqa hesab testləri hələ NOT_TESTED-dir.

## P1 — RevertToSelf xətası ilə davam etmək olmaz

session_ipc.rs:1303 OpenThreadToken error yolunda RevertToSelf nəticəsini let _ ilə itirir. :1331 əsas yolda RevertToSelf uğursuz olduqda adi Err qaytarır; caller server cavabını yazıb prosesdə işləməyə davam edir. Bu, sorğunun rəddidir, impersonation kontekstinin təhlükəsiz təmizlənməsi deyil. Microsoft API sənədi bu halda prosesi dayandırmağı tələb edir.

Mənbə: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself

Bütün successful impersonation çıxışları checked revert-dən keçməlidir. Həqiqi revert failure adi response/panic-unwind deyil, nəzarətli fatal process termination olmalıdır; in-process runner-i öldürməmək üçün bunu disposable child-process testi ilə sübut et. Şəxsi host xidməti/production prosesinə toxunma. Injection həqiqi revert-i icra edib fatal path-i simulyasiya edə bilər, amma child-da dedicated exit code və sonrakı callback/response icra olunmadığı yoxlanmalıdır. OpenThreadToken failure→revert failure yolu ayrıca test edilsin.

Bu bir qalıq bağlandıqdan sonra B.2b məhdud user-channel qəbulu nəzərdən keçiriləcək. B PARTIAL, C bağlıdır; B.1/B.2a qəbulları qüvvədədir.
