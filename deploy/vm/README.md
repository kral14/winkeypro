# WinKey — şəxsi Linux VM-də Docker

## Xarici PostgreSQL bazası

Deploy panelində gizli environment kimi `DATABASE_URL` əlavə edin. Dəyər panelinizin
verdiyi PostgreSQL bağlantı ünvanı olmalıdır; TLS parametrini saxlayın.
Bağlantı ünvanını GitHub-a, Dockerfile-a və build argument-lərə yazmayın.
Image yenidən build/deploy edilməlidir. Başlanğıc loqunda `database=PostgreSQL`
görünməlidir. Cədvəllər avtomatik yaradılır; istifadəçi schema CREATE icazəsinə
malik olmalıdır. Bağlantı uğursuz olsa server SQLite-a səssiz keçmir, dayanır.
`DATABASE_URL` yoxdursa əvvəlki `/data/winkey.db` SQLite rejimi işləyir.

PostgreSQL aktivləşəndə mövcud SQLite qeydiyyatları avtomatik köçürülmür.
Köhnə bazanı qoruyun; boş yeni bazada PC qeydiyyatı və telefon QR cütləşməsi
yenidən tələb olunur. Windows PIN-i kompüterdə qalır və bazaya göndərilmir.
Redeploy zamanı eyni DATABASE_URL saxlanmalıdır; xarici baza ayrıca qalır.

Telefon cütləşməsi avtomatik vaxt bitməsi olmadan saxlanır (`expires_at=0`).
Telefonun Bağlantını Kəs düyməsi və admin cihaz ləğvi tokeni serverdə silir.
Yenilənmə zamanı hələ qüvvədə olan köhnə 24 saatlıq sessiyalar daimi edilir;
artıq vaxtı bitmiş tokenlər avtomatik bərpa edilmir. Brauzer yaddaşı silinərsə
və ya başqa brauzer/telefon işlədilərsə yeni QR tələb olunur.

Mobil diaqnostika `/mobile/telemetry` üzərindən həmin telefonun sessiyası ilə
admin xronologiyasına göndərilir. Basış, göndəriş/server/ümumi müddət, timeout,
şəbəkə və ekranın status/xəta kodları əlaqə ID-si ilə görünür. Məxfi dəyərlər,
raw URL, stack və sərbəst ekran mətni göndərilmir. Offline qeydlərin son 200-ü
telefonda saxlanır; bağlantı və sessiya işləyəndə ACK ilə təkrar göndərilir.
Telemetriya əmr göndərilməsinə üstün gəlmir. Telefon və admin səhifəsini deploy-dan
sonra yeniləyin. Şəbəkəsiz və ya ləğv edilmiş sessiya ilə canlı göndəriş mümkün deyil.

## Dockerfile seçən deploy panelləri

Build növü `Dockerfile`, Dockerfile yolu `Dockerfile`, build context `.` olsun.
Entrypoint və Command override xanalarını BOŞ saxlayın; image-in öz CMD-si var.
Paneldə `PORT=8080` və secret kimi `WINKEY_ADMIN_SECRET` (ən azı 32 təsadüfi simvol) təyin edin.
Açar yaratmaq üçün öz terminalınızda `python3 -c 'import secrets; print(secrets.token_hex(32))'` işlədin.
Panelin container/internal portu da 8080 olmalıdır. Health URL `/healthz` (HTTP 200).
Daimi volume-u `/data` yoluna bağlayın, UID 10001 üçün yazma icazəsi verin.
Host bind directory istifadə edilirsə onu əvvəl UID/GID 10001:10001 sahibi edin.
Image-dəki VOLUME təkbaşına redeploy zamanı eyni bazanın bağlanmasına zəmanət deyil;
paneldə sabit named volume və ya host path mütləq seçilməlidir.
Panelin reverse proxy-si/domain ayarı HTTPS verməlidir; tək Dockerfile Caddy-ni işə salmır.
Admin URL `/admin`; burada yuxarıda saxladığınız WINKEY_ADMIN_SECRET ilə daxil olun.

Bu paket mövcud Python gateway-in mobil və admin səhifələrini yerləşdirir.
Sites/Cloudflare hesabı tələb etmir. Sites-dəki React dashboard bu konteynerə daxil deyil.
Windows helper/service VM-də deyil, idarə olunan Windows kompüterində işləyir.

## İlk quraşdırma

VM-də Docker Engine + Compose plugin, Python 3, Git olmalıdır.
Domenin A yazısını VM-in ictimai IP-sinə yönəldin; AAAA varsa düzgün IPv6-yə yönəlməlidir.
VM/provider firewall-da 80 və 443 TCP açıq olmalıdır. 8788 portunu açmayın.
Başqa proqram 80/443 istifadə edirsə, əvvəl mövcud reverse proxy ilə uyğunlaşdırın.

Repository-ni çəkdikdən sonra onun kökündə:

```sh
python3 deploy/vm/configure.py --domain winkey.example.com
docker compose up -d --build
docker compose ps
docker compose logs --tail=80 gateway caddy
```

`winkey.example.com` yerinə öz domeninizi yazın. Caddy HTTPS sertifikatını özü alır.
Admin: `https://winkey.example.com/admin`.
Admin açarını yalnız öz terminalınızda oxuyun və həmin panelin giriş xanasına yazın:

```sh
cat deploy/vm/secrets/admin_key
```

Bu açarı GitHub-a, söhbətə və ya ekran görüntüsünə daxil etməyin.
Windows WinKey proqramında İnternet rejimi və server ünvanı kimi
`https://winkey.example.com` seçin (sonuna `/api`, `/admin`, `/mobile` əlavə etməyin).
Yeni QR yaradıb telefondan oxudun. Kilid açmaq üçün Windows-da SYSTEM xidməti və yerli PIN sazlanmalıdır.

## Yeniləmə və məlumatların saxlanması

```sh
git pull --ff-only
docker compose up -d --build
```

Cihazlar, sessiyalar və loqlar `gateway_data` volume-da, HTTPS sertifikatları ayrı volume-da saxlanır.
Adi `docker compose down` məlumatları silmir. `down -v` məlumatları silir, işlətməyin.
Admin açarı configure.py təkrar işlədildikdə dəyişmir; onun ehtiyatını ayrıca qoruyun.
İmzalı Windows yenilənmə faylları image-ə daxil edilmir; avtomatik update repository bu paketdə aktiv deyil.

Məlumat bazasının ehtiyatını yazılar dayandırılmış halda alın:

```sh
docker compose stop gateway
docker compose cp gateway:/data/winkey.db ./winkey-backup.db
docker compose start gateway
```

Ehtiyat faylında cihaz/session məlumatları var; onu GitHub-a göndərməyin.
Bu hazırlıq canlı WAN/telefon və fiziki Windows unlock testi əvəzi deyil.
