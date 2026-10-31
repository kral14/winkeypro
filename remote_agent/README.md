# WinKey Windows köməkçisi

`dist/WinKeyRemote/WinKeyRemote.exe` faylını açın. `_internal` qovluğu EXE ilə yanaşı qalmalıdır.

1. Administrator sorğusunu təsdiqləyin.
2. Windows-da istifadə etdiyiniz PIN/parolu kompüterdə saxlayın.
3. “Saxla və qoşul” basın.
4. Köməkçinin göstərdiyi qoşulma kodunu şəxsi veb paneldə “Kompüter əlavə et” pəncərəsinə yazın.
5. Telefon ayrı şəbəkədə olsa da veb paneldən idarə edin.

Köməkçi açıq və kompüter internetə bağlı olmalıdır. Pəncərəni bağlamaq bağlantını dayandırır. Bu versiya Windows açılan anda avtomatik işə salınmır.

Ayarlar `%LOCALAPPDATA%/WinKeyRemote/agent.dpapi` faylında həmin Windows hesabının DPAPI qoruması ilə saxlanır. PIN relay serverinə göndərilmir. Xidmət açarı ayrıca icazə ilə yaradılır; yayım arxivinə daxil deyil. Başqa kompüter üçün ayrıca xidmət ayarı və qoşulma kodu lazımdır.

Loqlar `%LOCALAPPDATA%/WinKeyRemote/` qovluğundadır. Əmrlər 20 saniyə sonra köhnəlir və eyni əmr təkrar icra olunmur.

Build:
`python -m PyInstaller --noconfirm remote_agent/WinKeyRemote.spec --distpath remote_agent/dist --workpath remote_agent/build`
