# WinKey Pro — arxitektura təklifi

## Admin və istifadəçi səthləri
Admin Site private qalır: yalnız sahib hesabı cihaz adlarını, online vəziyyəti, versiyaları, qeydiyyatı və revoke/release statusunu görür. Sahibin admin hesabı nesib20@gmail.com-dur. Faktiki layihə sahibi fərqli hesabdır; sahiblik özbaşına ötürülmür.
Public gateway/mobile ayrıca Site kimi təklif olunur. Public URL anonim kilid açma icazəsi demək deyil: hər API əməliyyatı fərdi cihaz identity-si və cihazla məhdud mobil session ilə serverdə yoxlanır.
Hazır private Sites giriş qapısı bütün origin-i qoruyur. Eyni hazır private origin-də kənar istifadəçiyə ChatGPT-siz mobil giriş vəd etmək olmaz. B-də cari platforma imkanları təsdiqlənməlidir.
İki Sites layihəsi avtomatik eyni D1 bazasını paylaşmır. Gateway öz DB-sinə sahib olur; private admin backend xüsusi məhdud server credential-i ilə gateway admin API-sinə çıxır. Bütün idarəetmə serverləri Sites-də qalır.

QADAĞAN: hazır OAI-Sites-Authorization bypass açarını ümumi EXE/QR/JavaScript daxilində paylamaq. Hazır owner-private prototipin bağlantısı kütləvi məhsulun auth arxitekturası deyil.
Consumer API heç vaxt admin səlahiyyəti vermir. Display name cihaz identity-si deyil; təsadüfi device_id və fərdi key/proof tələb olunur.

## Qeydiyyat və mobil
1. İmzalı installer bir dəfə admin icazəsi ilə servis/supervisor, UI və helper quraşdırır.
2. PC adı avtomatik doldurulur; istifadəçi dəyişə bilər. PIN/parol yerli brokerə verilir, serverə göndərilmir.
3. Agent fərdi identity ilə qeydiyyat olur; abuse/rate-limit və key proof var. Qeydiyyat endpointi shared service key paylama yolu deyil.
4. PC qısaömürlü, bir dəfə işlənən QR pairing challenge açır. Telefon oxudur; PC-də telefonun təsdiqi və ya açıq, qısa enrollment pəncərəsi tələb olunur. Dəqiq UX B/F-də qəbul edilir.
5. Telefon revocable, device-scoped session alır. PIN, uzunömürlü device key və admin key QR-də yoxdur. Sirr ilk mübadilədən sonra URL-dən silinir; cache/referrer qorunur.
6. Mobil PWA yalnız Kilidlə/Kilidi aç və status göstərir. Android/iPhone ana ekrana əlavə etmə təlimatı ilk istifadədə çıxır.
7. İstifadəçi başqa device_id yazmaqla digər PC-ni, yaxud admin panelini idarə edə bilmir.

## Windows prosesləri
- WinKeySupervisor: Windows service, bootda automatic/delayed-auto start, SCM recovery; minimal, stabil komponent və vahid update coordinator.
- Agent worker: versiyalanmış slotda şəbəkə/queue/health komponenti. UI bağlansa belə heartbeat və command davam edir.
- Session helper: yalnız qeydiyyatlı Windows SID və icazəli aktiv sessiyada. Görünən Default pərdəsinə klik → Winlogon keçidi təsdiqi → PIN fokus təsdiqi → bir dəfə yazma.
- Tauri UI/tray: normal user hüququ, yalnız lokal React məzmunu. X=hide-to-tray, singleton, ikinci launch mövcud pəncərəni göstərir.
- Lokal IPC: ACL-li named pipe, caller SID yoxlanır; arbitrary shell, executable yolu, PID/token seçimi qəbul edilmir.

Xidmət Session 0-da özü ekrana klik etmir. Mövcud CreateProcessWithTokenW caller-session davranışını xidmətə kor-koranə köçürmək olmaz. Düzgün sessiya tokeni ilə CreateProcessAsUserW yolu B-də fiziki PC üzərində sübut edilməlidir.
Tray menyusu: Aç, bağlantı/status, update vəziyyəti, dəstək loqu, uzaqdan idarəni dayandır. UI-dən çıxmaq və idarəetməni dayandırmaq fərqli və aydın əməliyyatlardır.

## Credential sərhədi
Xidmət hesabına bağlı DPAPI + məhdud NTFS ACL, istifadəçi SID ilə indeks. Rendererə saxlanan PIN açıq qaytarılmır.
User-scope prototip DPAPI faylı LocalSystem xidməti tərəfindən avtomatik açıla bilməz. Miqrasiya user-side lokal brokerdə decrypt → təsdiqli IPC → service-side yenidən qoruma yolu ilə olur.
EXE yanında şəxsi credential saxlama prototip workaround-udur; ümumi installerə daxil edilmir. Sirrlər log/crash dump/telemetry/server DB/release artifactlərə düşmür.

## Startup və engine
Service Windows bootda başlayır, tray yalnız desktop login zamanı görünür. Şəbəkə yoxdursa backoff; gələndə özü qoşulur.
Sessiya kilidini açmaq və tam rebootdan sonrakı ilk Windows sign-in ayrı ssenarilərdir. İlk giriş ayrıca sertifikasiya olunur; BitLocker/preboot avtomatik bypass edilmir.
Hazır Python helper ilkin sidecar/uyğunluq etalonu ola bilər, istifadəçi Python quraşdırmamalıdır. Native Rust port yalnız sübutlu müqayisə və auditlə qəbul edilir.

