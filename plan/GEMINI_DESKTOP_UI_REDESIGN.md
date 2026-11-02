# WinKey Pro desktop — səliqəli və adaptiv interfeys

İstifadəçi tələbi: mövcud desktop interfeys dağınıqdır. Əvvəlcə peşəkar, səliqəli görünüş hazırla. Səhifələr pəncərə ölçüsünə uyğunlaşmalı, səhifə scrollbar-ı olmamalıdır. Tablar yuxarı navbar-a çevrilməli, navbar-da istifadəçi giriş/profil ikonu olmalıdır.

## İcra

1. Faktiki apps/desktop_tauri/ui interfeysini yenilə. Köhnə web preview ilə kifayətlənmə. Əvvəl mövcud HTML/CSS/JS, native command əlaqələrini və minimum window ölçüsünü oxu. Başlanğıc görünüş, bütün bölmələr, onboarding, PIN, QR pairing, status, update və dəstək ekranları eyni dizayn sistemində olsun.
2. Yuxarıda sabit, yığcam navbar: WinKey markası, mövcud bölmələrə keçidlər, aktiv bölmənin aydın göstəricisi, sağda istifadəçi ikonu. İkon daxil olmayanda real giriş/qeydiyyat axınını, daxil olanda istifadəçi məlumatı və çıxış menyusunu açsın. Mövcud account backend-i ilə bağla; saxta login uğuru yaratma. Hər ikonun tooltip və əlçatan adı olsun. Tray/bağlama davranışını qoru.
3. Pəncərə daxilində grid/flex ilə `100dvh`, `min-height:0`, elastik sütun və sətirlərlə layout qur. Böyük boşluqları, təkrarlanan izahları və həddən böyük kartları yığışdır. QR və düymələr əlçatan, mətn oxunaqlı qalsın. Fixed pixel hündürlükləri və bütün ekranı transform:scale ilə kiçiltmə istifadə etmə.
4. Səhifədə və əsas ekran kartlarında scrollbar yaratma. Məzmuna yer çatmırsa alt bölmə, addımlı axın, səhifələmə, açılıb-bağlanan detal və ya ayrıca mətn viewer-i istifadə et. Loqları səhifələyərək göstər, tam log export/kopyalama saxlanılsın. `overflow:hidden` ilə məzmunu/düymələri əlçatmaz etmək qəbul edilmir. Uzun xəta mesajları və istifadəçi adları layout-u pozmasın; tam məzmun detal açılışında əlçatan olsun.
5. Dəstəklənən minimum pəncərə ölçüsünü real dizayna uyğun əsaslandır və native Tauri minWidth/minHeight ilə tətbiq et. Fiziki olaraq istənilən kiçik ölçüyə və istənilən mətn böyütməsinə limitsiz məzmun sığdırmaq vədi vermə. Minimum sahəyə çatmayan ekran/DPI üçün kompakt alternativ axın qur; elementləri gizlətmə. Windows scaling 100%, 125%, 150%, 200% zamanı faktiki CSS viewport-u nəzərə al.
6. Təmiz vizual iyerarxiya: vahid şrift, ölçü/spacing, uyğun kontrast, məhdud accent rəngi, aydın əsas düymə və sakit ikinci düymələr. Azərbaycan mətnləri düzgün encoding ilə göstərilsin. Navbar dar sahədə yığcam ikon+tooltip və ya overflow menyuya adaptasiya etsin; üfüqi scroll yaranmasın.

## Sərhədlər

- İşlək lock/unlock, DPAPI, QR, pairing, account, update, tray və single-instance məntiqini qoru. Native command adları/parametrləri səbəbsiz dəyişməsin.
- PIN, token, QR sirləri önizləmə/loga düşməsin. Vizual test üçün sintetik təhlükəsiz məlumat istifadə et; demo görünüşü real uğur kimi göstərmə.
- Əvvəlki GEMINI_INSTALLER_TEXT_FIX.md tapşırığı da qüvvədədir; hər ikisini bir hesabat paketində tamamlamaq olar. Codex build düzəlişlərini qoru. Yeni framework/backend miqrasiyası etmə.

## Qəbul testləri və təhvil

- Desktop-da bütün navbar keçidləri, giriş ikonu, PIN visibility/save status, QR yaratma və ləğv, update yoxlama, tray düyməsi işləsin; yalnız HTTP 200 kifayət deyil. Fiziki lock/unlock icra etmə.
- Minimum dəstəklənən ölçü, default pəncərə və 1366x768/1920x1080 ekran ssenariləri üzrə viewport yoxlaması apar. DPI ilə kiçilən istifadə sahəsini də test et. Hər bölmədə uzun ad/xəta, loading/offline/account vəziyyətlərini göstər.
- `documentElement/body scrollWidth > clientWidth` və `scrollHeight > clientHeight` yoxlamaları, əsas kartlarda overflow və düymələrin viewport xaricində qalmasını ölç. Hidden overflow olmasa belə layout-un sığdığını sübut et. Navbar/keyboard fokus sırası işləsin.
- Screenshot hazırlama və təqdim etmə. Hazır interfeysi lokal önizləmə serverində aç, serveri işlək saxla və brauzerdə birbaşa açılan dəqiq kliklənən link ver. Mövcud dev server varsa onu istifadə et, əlaqəsiz prosesləri dayandırma. Linkin cavab verdiyini və bütün bölmələrin açıldığını yoxla. Browser preview-də native əməliyyatların məhdudiyyətlərini aydın göstər; saxta real uğur yaratma. Eyni UI asset-ləri Tauri-də də istifadə olunsun. Canlı install, xidmət dayandırma, push/deploy etmə.
- plan/reports/DESKTOP_UI_REDESIGN_REPORT.md: ölçü/DPI matrisi, test nəticələri, dəyişən fayllar və NOT_TESTED hallar. Yekun cavabın əvvəlində hazır səhifənin işlək önizləmə linkini ver. Codex qəbulu üçün dayan.
