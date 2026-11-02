# Auto-update: Codex review və vahid düzəliş tapşırığı

## Audit qərarı

AUTO_UPDATE_AUDIT.md faydalıdır, lakin bütöv real yenilənmənin uğurlu olduğunu sübut etmir. Bu Codex baxışında kod oxunub; testlər yenidən işə salınmayıb.

Təsdiqlənən kod tapıntıları: desktop singleton/restart toqquşma riski; build metadata versiyalarının sinxron olmaması; auth-da versiyanın olmaması; legacy Python və sintetik native staging testlərinin canlı SCM yenilənməsini sübut etməməsi.

Auditdə düzəldilməli iddialar:
- Worker artıq `update_available` versiyasını active_version ilə müqayisə edir. Eyni versiyanın hər reconnect-də diskə yazıldığı iddiası yanlışdır; server bildirişi təkrarlayır, worker isə normal halda süzür.
- Server UpdateRepository-də cihazlara məxsus karantin yoxlaması yoxdur. Server downgrade-i, cihaz isə öz karantinini yoxlayır.
- Slotdan ayrı məlumat saxlamaq məlumatların bütün qəza hallarında “100% qorunduğunu” sübut etmir.
- A/B iki slotdan ibarətdir: əvvəlki desktop hələ qeyri-aktiv slotdan işləyə bilər. İkinci ardıcıl update-də həmin slotun faylları kilidli qala bilər; “file-lock baş vermir” zəmanəti yoxdur.
- Tauri restart yarışını təkrar edilən proses testi ilə təsdiqlə; fərziyyəni müşahidə edilmiş hadisə kimi yazma.
- PASS iddialarına icra əmri, exit code və yeni xam log əlavə et. Mövcud hesabatda bunlar yoxdur.

## Vahid icra paketi

1. Desktop restart handoff: köhnə prosesin həqiqi çıxışını gözləyən məhdud, yoxlanılan mexanizm qur. Sadəcə sabit sleep etmə. Normal ikinci açılış mövcud pəncərəni bərpa etməlidir; mutex alınmaması/null handle fail-closed idarə edilməlidir. İki ardıcıl A→B→A update-də köhnə desktop slot kilidlərini də yoxla.
2. Compile-dan əvvəl service/desktop Cargo və Tauri metadata versiyalarını release versiyasına uyğunlaşdır; lock fayllarını uyğun saxla. Uğursuz build-in son uğurlu release göstəricisini pozmadığını yoxla.
3. Agent auth-a faktiki işləyən worker versiyasını əlavə et. Server yeni versiya varsa bildirsin; versiyasız köhnə client-lər bildiriş almağa davam etsin. Worker-in müstəqil versiya/imza yoxlamalarını saxla. Broadcast və reconnect yollarını birlikdə test et.
4. Desktop arqumentlərini yalnız tanınmış GUI/relaunch bayraqları üçün ötür. Bütün arqumentlərə kor yönləndirmə etmə: diaqnostika/CLI əmrləri ilkin executable-da düzgün işləməlidir, dev istisnası saxlanmalıdır.
5. Real production Rust download/staging yolu üçün lokal HTTP inteqrasiya testi əlavə et. İmzalı paketlə hash/signature, yarımçıq download, təkrar bildiriş, köhnə versiya, karantin, restart və rollback yoxlamaları qur. Test key yalnız ayrıca test kontekstində olsun; production pinned key zəiflədilməsin, private key paketə/loga düşməsin.
6. Stabil host/recovery installer ilə yenilənir: bunu səssizcə dəyişmə. Manifestdə host-protokol uyğunluğu tələbinə ehtiyac olub-olmadığını araşdır; uyğun olmayan worker köhnə host-da aktivləşməsin, UI dəqiq “Setup tələb olunur” desin. Mövcud stabil recovery sərhədini saxla.
7. UI/server telemetriyasına release id, əvvəlki/yeni versiya və download/stage/activate/probation/commit/rollback mərhələlərinin müddətini, konkret xəta kodunu əlavə et. PIN/token daxil etmə. “Yükləndi” ilə “yenilənmə təsdiqləndi” ayrı göstərilsin.

İşlək kilid açma axınını, PIN/DPAPI yaddaşını və telefon cütləşməsini qoru. Canlı xidmətləri dayandırma, real lock/unlock, install, push və deploy etmə. Təhlükəsiz avtomatlaşdırılmış testləri disposable qovluqlarda icra et. GUI/SCM fiziki testləri ayrıca NOT_TESTED kimi göstər.

Yekunda plan/reports/AUTO_UPDATE_REVISION_REPORT.md: dəyişən fayllar, tapıntı→düzəliş xəritəsi, test əmrləri/exit code/log yolları, qalan risklər və operator üçün qısa real sınaq addımları. Bütün paketi tamamla, Codex yoxlaması üçün dayan.
