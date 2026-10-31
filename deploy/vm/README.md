# WinKey — şəxsi Linux VM-də Docker

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
