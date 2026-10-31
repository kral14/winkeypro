# A — Codex yekun audit qərarı

- Tarix: 2026-10-28
- Qərar: ACCEPTED
- Hesabat: plan/reports/A_REPORT.md (son reviziya)
- SHA256: F67E0398C938D2C79F76368DB5F3CD47D2CDEA40A2126AE448B2391335600C90

## Qəbulun əhatəsi

Yalnız məsləhət/arxitektura mərhələsi qəbul edilir. A-01–A-05 plan səviyyəsində bağlandı: token/sessiya ayrımı, iki mərhələli input, boot recovery sahibi, UAC telemetriyası, yerli açar/pairing və sübut sərhədləri göstərilib. Mövcud helper kodu ilə müqayisə edildi. Yeni build və real Windows testi bu auditdə icra edilməyib. Əvvəlki tam hash baseline olmadığından “başqa kod dəyişməyib” iddiası müstəqil təsdiqlənmir.

## B üçün məcburi dəqiqləşdirmələr

Hesabatdakı aşağıdakı mütləq ifadələr işlək məhsul təminatı kimi qəbul edilmir:

- Qovluq handle-ında FlushFileBuffers və atomik əvəzləmə Windows-da avtomatik universal power-loss zəmanəti deyil. Dəstəklənən API/flag/filesystem davranışını rəsmi sənədlə yoxla; hər yazı/flush/replace nəticəsini yoxla; köhnə jurnal/pointer zədələnəndə də imzalı known-good seçimi və fault-injection testi tələb olunur.
- Binary qovluq ACL-i təkbaşına bütün DLL hijacking hallarını “tam” aradan qaldırmır. DLL axtarış yolu, iş qovluğu, executable yolu, pipe peer/proses identifikasiyası və remote pipe rəddi B-də yoxlanmalıdır. Standart user renderer birbaşa privileged INJECT_PIN kanalına qoşula bilməz.
- LocalSystem tokeni ilə CreateProcessAsUserW və ya düzgün sessiyadakı broker faktiki SessionId ölçümü ilə sübut edilməlidir. Windows secure desktop ACL-ləri zəiflədilmir. UAC secure desktop-da PIN yazılmamalıdır; yalnız uyğun kilid/auth ekranı təsdiq ediləndə input mümkündür.
- Recovery launcher SCM protokolunu özü icra edən sabit xidmət kimi child supervisor-u izləməli, boot və crash zamanı jurnalı bərpa etməlidir. İmza yoxlaması pinned etibarlı release açarı/naşirə bağlanır; sadəcə istənilən etibarlı Authenticode sertifikatı kifayət etmir.
- Git hostu, signing sahibi və Windows dəstək matrisi hələ owner qərarıdır. Private Sites admin girişini dəyişdirmək bu qəbulla avtomatik icazə verilmiş sayılmır.

Bu qeydlər B-nin qəbul meyarlarıdır, A üçün yeni implementasiya tələbi deyil. B nəticəsi uğursuz olarsa ADR və plan sübuta əsasən yenilənir.

## Növbəti gate

A ACCEPTED. B READY_FOR_IMPLEMENTATION, hələ başlanmayıb. C–K NOT_STARTED. B hesabatı və ayrıca Codex qəbulu olmadan C-yə keçilmir. Əvvəlki qərarlar A_ACCEPTANCE_REV0.md və A_ACCEPTANCE_REV1.md-də saxlanılıb.
