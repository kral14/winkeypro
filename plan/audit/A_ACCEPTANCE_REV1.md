# A — Codex təkrar audit (Reviziya 1)

- Tarix: 2026-10-28
- Qərar: CHANGES_REQUESTED
- Hesabat SHA256: 9D3D14FB06BCFFB6BD7D5CD5380EFF2E033F78270494FE4310AFFDCBAF260911
- A-03, A-04, A-05: A məsləhət səviyyəsində bağlandı. A-01/A-02 üzrə aşağıdakı iki konkretləşdirmə qalıb.

## A-01 / P1 — Session 0-dan prosesin düzgün sessiyada yaradılması

Bölmə 2, fərziyyə 1 sənədləşdirilmiş API məhdudiyyətini açıq fərziyyə kimi saxlayır. CreateProcessWithTokenW tokenin sessiyasına keçirmir, çağıranın sessiyasında proses yaradır. Mövcud etalon artıq istifadəçi sessiyasında işlədiyindən onun eyni API çağırışı Session 0 xidmətindən birbaşa port edilə bilməz.

Planı konkretləşdir: xidmət seçilmiş sessiyanın etibarlı privileged primary tokeni ilə CreateProcessAsUserW istifadə edir; ya da əvvəl düzgün sessiyada etibarlı broker yaradır, CreateProcessWithTokenW yalnız orada işləyir. Bunların real işləyişi B-də yoxlanacaq. Prosesin faktiki SessionId-si ölçülmədən input və PIN ötürülməsin. Standart istifadəçiyə Winlogon desktop DACL hüququ vermək alternativini çıxar; mövcud secure desktop ACL-lərini zəiflətmə. Qorunan binary yolu və ACL-li dar IPC müqaviləsi göstərilsin.

Mənbə: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw (Terminal Services qeydi).

## A-02 / P1 — Recovery crash-dən əlavə boot-da da işləməlidir

SCM on-failure hər boot-da və ya bütün xidmət start xətalarında recovery-nin işləyəcəyinə zəmanət deyil. Sabit recovery komponenti boot-da candidate supervisor-dan əvvəl jurnalı yoxlamalı, etibarlı slot seçməli və sonra onu başlatmalıdır. Başlatma mexanizmini və sahibini konkret seç. Jurnal/current pointer/candidate xaricində qorunan recovery fayllarının yeri, xidmət hesabı/ACL-i və diskə davamlı yazı qaydası göstərilsin. İmzalı bundle və hash yoxlaması aktivləşdirmədən əvvəl məcburi olsun. Recovery-nin öz yenilənməsi bu spike-dan kənar, ayrıca installer bərpa yolu kimi saxlanıla bilər.

## Qəbul sərhədi

Yeni fiziki test A üçün tələb olunmur; yalnız düzgün B planı tələb olunur. Hesabatın digər düzəlişlərini təkrarlama. B NOT_STARTED qalır. Kodun dəyişmədiyini yoxlamaq üçün əvvəlki tam baseline olmadığı məhdudiyyəti qalır; icraçının iddiası müstəqil hash sübutu deyil.
