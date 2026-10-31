# A — Codex audit qərarı

- Tarix/auditor: 2026-10-28 / Codex
- Hesabat: plan/reports/A_REPORT.md
- Hesabat SHA256: 06157C18DF5290E64164388FB9AC141F36FC07C670198377555C40A2B8BF5EDA
- Qərar: CHANGES_REQUESTED

## Müstəqil yoxlama

Hesabat plan tələbləri və mövcud pc_agent/secure_input_worker.py ilə tutuşduruldu. Bu A məsləhət auditidir; yeni build, fiziki PC testi və ya B spike icra edilmədi. Əvvəlki tam kod hash bazası olmadığından “heç bir kod dəyişməyib” iddiası müstəqil təsdiqlənmir. Təkcə fayl adları hash manifest deyil.

## Tapıntılar

1. **A-01 / P1 — Secure desktop səlahiyyət modeli natamamdır (bölmə 2).** WTSQueryUserToken istifadəçi tokeni qaytarır; LocalSystem çağıran prosesin səlahiyyəti avtomatik həmin tokenlə yaradılan prosesə keçmir. DuplicateTokenEx də özbaşına səlahiyyət yüksəltmir. SID ilə cihaz sahibinin yoxlanması ilə Winlogon-a giriş səlahiyyətini ayırın. Mövcud helper eyni sessiyadakı winlogon tokenindən istifadə edir. B üçün Default pərdə klikindən sonra ayrıca səlahiyyətli Winlogon helperinin necə başladılacağını, sessiya/SID yoxlamalarını, qorunan binary/IPC sərhədini və sübut tələb edən fərziyyələri yazın. PIN yalnız təsdiqlənmiş kilid ekranına bir dəfə daxil edilməlidir; Hello avtomatik açıldıqdan sonra şərtsiz Enter göndərilməməlidir.

2. **A-02 / P1 — Supervisor öz yenilənməsini necə bərpa edir? (bölmə 4).** Supervisor yeganə koordinator olduğu halda onun öz crash/yarımçıq yenilənməsi üçün müstəqil bərpa sahibi göstərilmir. Sabit bootstrapper/recovery komponentinin jurnal, supervisor versiyası və əvvəlki slotu necə bərpa etdiyini planlaşdırın. Elektrik kəsilməsi nöqtələrini və B-də yoxlanacaq ssenariləri qeyd edin. “Tauri updater yalnız UI pəncərəsini yeniləyir” dəqiq deyil: paket/installer yenilənməsi ilə bütün xidmətlərin və məlumatların koordinasiyalı rollback təminatı ayrı məsələlərdir.

3. **A-03 / P2 — UAC rəddi yanlış təsnif edilib (bölmə 5).** Artıq işləyən yüksəldilməmiş bootstrapper elevation sorğusunun rəddini qeydə alıb göndərə və ya outbox-a yaza bilər. Heç bir kod işə başlamazdan əvvəl OS bloklaması və elektrik kəsilməsi ilə bunu ayırın. SUSPECTED_STALL təsdiqlənmiş səbəb kimi göstərilməsin.

4. **A-04 / P2 — Qeydiyyat/pairing müqaviləsi dəqiqləşsin (bölmə 3).** Private key cihazda yaranır və cihazdan çıxmır; server public key qeydiyyatı və challenge qəbul edir. QR-in oxunması ilə sahiblik avtomatik təsdiqlənmir: yerli PC təsdiqi və ya açıq şəkildə istifadəçinin başladığı məhdud enrollment pəncərəsi, müddət, birdəfəlik istifadə və ləğvetmə qaydası yazılsın.

5. **A-05 / P2 — Sübut və fərziyyələr qarışıb (bölmə 1, 6, 7).** Mövcud şəbəkə prototipi HTTP polling-dir; WebSocket həyata keçirilmiş sübut kimi yazılmasın. Installer/RAM rəqəmləri ölçülməyib: çıxarın və ya yoxlanmamış təxmin kimi etiketləyin. OS build və test nəticələrini yalnız saxlanmış çıxışla əsaslandırın; yoxdursa “yoxlanmayıb” yazın. API iddialarına konkret rəsmi URL əlavə edin. Git/release deposu, imzalama sahibi və dəstəklənən Windows matrisi üzrə açıq qərarlar ayrıca göstərilsin.

## İstinadlar

- [WTSQueryUserToken — istifadəçinin primary tokeni](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
- [CreateProcessAsUserW — verilən tokenin təhlükəsizlik konteksti, sessiya və desktop giriş tələbləri](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- Yerli sübut: pc_agent/secure_input_worker.py, xüsusən tokenin alınması və CreateProcessWithTokenW çağırışı.

## Növbəti gate

Gemini yalnız A hesabatını düzəldib READY_FOR_AUDIT təqdim edir. A-01 və A-02 bağlanmadan A qəbul edilmir. B–K NOT_STARTED qalır. Arxitektura planının düzəldilməsi işlək implementasiyanın sübutu sayılmır.
