# WebSocket runtime qeydləri

Gateway eyni origin-dən açılan mobil səhifəni qəbul edir. Ayrı public frontend/reverse proxy üçün `WINKEY_ALLOWED_ORIGINS` mühit dəyişəninə tam origin-ləri vergüllə yazın, məsələn `https://remote.example.org,https://panel.example.org`. Sxem və port uyğun olmalıdır; path/token yazılmır. Native agent Origin başlığı göndərmədən device autentifikasiyasından keçir. Cari VM `http://158.101.172.228:8080` qəbul edilir.

Gateway, telefon və service dəyişiklikləri birlikdə yayımlanmalıdır. Təkcə lokal service-ni compile etmək VM konteynerini yeniləmir. Build/setup normal signing prosesindən keçməlidir; quraşdırılmış exe-ni əl ilə əvəz etməyin.

Command bir dispatch attempt-i alır. Nəticə 60 saniyə gəlməsə `INDETERMINATE_DELIVERY_TIMEOUT` həm mobilə, həm admin incident jurnalına düşür. Bu uğurlu və ya uğursuz fiziki icranın sübutu deyil; avtomatik fiziki replay edilmir. İstifadəçi yeni niyyət üçün yeni əmr verə bilər. Native queue-da 55 saniyə köhnəlmiş receipt inputa başlamır.

Native outbox/in-flight korlananda `TRANSPORT_BLOCKED`/`E_JOURNAL_*` loqları yaranır. Sübut faylları silinməməlidir. Disk icazəsi/yer problemi düzəldilib jurnalın bərpası araşdırılmalıdır; proqram boş fayl yaradıb uğur göstərmir.

Mock və lokal yük sınaqları fiziki Windows unlock və WAN gecikməsi sübutu deyil. Yerli yoxlamaların nəticələri `plan/reports/CODEX_WEBSOCKET_REVISION_3.md`-dədir.
