# Yekun audit reviziya 2 — toplu davam

Əvvəlki üç dar audit testi artıq NOT_REPRODUCED verdi; bu irəliləyişdir. Lakin bütün P0/P1 bağlanmayıb. Əsas toplu tapşırıq qüvvədədir.

## Yeni təsdiqlənmiş P0
`python scripts/codex_gateway_ownership_audit.py` (yalnız müvəqqəti SQLite/handler, ekran/network yoxdur) exit 1:
- REGISTRATION_WITHOUT_PROOF: düzgün formalı public key təqdim edib nonce/imzasız qeydiyyat mümkündür. `if nonce and proof_sig` məcburi proof deyil. Hər ikisi məcburi; challenge purpose/device binding/expiry/one-use atomik olmalıdır.
- PUBLIC_KEY_ONLY_SECRET_ROTATION: həmin public key ilə imzasız təkrar register yeni device_secret verir. Public key açıq məlumatdır, sahiblik sübutu deyil. Re-enrollment üçün mövcud sahibin kripto proof-u və dəqiq rotation/revocation müqaviləsi tələb olunur; INSERT OR REPLACE ownership bypass aradan qaldırılsın.
- REJECTED_PAIR_GRANTS_SESSION: DB-də REJECTED olan kod sessiya verir. Yalnız PENDING və doğru expiry/PC approval qəbul edilməli; conditional UPDATE rowcount==1 olmadan sessiya yaratmaq olmaz. CLAIMED/REJECTED/EXPIRED bütün statuslar və paralel claim mənfi testlərlə yoxlanılsın.
- Mobil Revoke yalnız localStorage.clear edir. Server sessiyasını revoke et və köhnə tokenin rəddini sına. Cihaz ACTIVE/revoked statusu command/status/pair yollarında məcburi olsun. PC-də pairing təsdiqi hələ actual axına bağlanmalıdır.

## Açıq P1 — yanlış tamamlama iddiaları
- Installer yenə birbaşa winkey_service.exe --run-service qeydiyyat edir, supervisor actual boot entrypoint deyil.
- Supervisor check_pipe_health STATUS göndərmir: sadəcə CreateFileW açıb bağlayır. ctypes handle restype/argtypes yoxdur, server PID/token/path/session təsdiqi yoxdur. Eyni adlı yad pipe sağlamlıq kimi qəbul edilə bilər. Namizəd və bərpa LKG üçün authenticated bounded request/response health və probation tələb olunur; 60s standalone real boot xidməti deyil.
- Update `_is_slot_valid` sadəcə qovluq boş deyil yoxlayır. Bu imza/hash/salamtlıq təsdiqi deyil. Corrupted journal-da təsadüfi fayllı slot seçilməməlidir; signed manifest+payload hashes+target+entrypoint ilə fail-closed recovery tələb olunur.
- Gateway mobil yalnız queued cavabı göstərir, actual command result poll etmir; offline status stale qala bilir. Fiziki nəticə gəlmədən uğur göstərmə.
- Əvvəlki batch-in deploy/Python-suz installer/telemetriyanın real məhsula inteqrasiyası və Sites/WAN qalıqlarını maddə-maddə source/test sübutu ilə bağla və ya PARTIAL/BLOCKED göstər.

Test harness-ləri zəiflətmə. Təcrid testlərini təhlükəsiz rejection assertions ilə genişləndir; sübutları yeni revision qovluğunda saxla. Tray/etalon/helper və nonphysical-default qorunsun. Bütün mümkün qalıqları bir toplu icrada tamamla; sonda dürüst FINAL_BATCH_REPORT təqdim et.
