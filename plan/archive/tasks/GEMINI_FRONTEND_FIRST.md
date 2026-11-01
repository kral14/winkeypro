# Gemini — əvvəl işlək frontend önizləməsi: 5 iş paketi

## Sahibin son prioriteti

Sahib əvvəl tətbiqi ayağa qaldırıb frontend görünüşünü görmək istəyir. Tam audit və bütün backend/security boşluqlarının bağlanması bu önizləməni gecikdirməsin. Bu tapşırıq əvvəlki B–G batch-in icra sırasını dəyişir: əvvəl aşağıdakı beş preview paketini hazırla, ilk işlək görünüşü göstər, sonra qalan implementasiya davam edə bilər. Bunlar yeni məhsul mərhələsi H–K deyil, frontend üçün PREVIEW-1–5 iş paketləridir. Production/stable release və qəbul iddiası yoxdur.

## PREVIEW-1 — Cari frontend-i işə sal

Mövcud yeni məhsul source-unu və başlanğıc əmrlərini tap. Hazır frontend varsa onu istifadə et; bütün layihəni sıfırdan yenidən yazma. Asılılıqları qur, dev server-i işə sal, açılan lokal URL və dəqiq start əmri hazırla. Mövcud run/build xətası varsa yalnız preview-ni açmaq üçün lazım olanı düzəlt. Backend yoxdursa açıq DEMO rejimi ilə işləyən adapter istifadə et; interfeys qapalı backend-i gözləyib boş qalmasın.

## PREVIEW-2 — Desktop görünüşü

Tauri/React frontend-də peşəkar, ardıcıl WinKey dizaynı hazırla: ilk açılış/onboarding, avtomatik dəyişdirilə bilən PC adı, lokal credential sahəsi, qeydiyyat, əlaqə statusu, QR qoşma ekranı, settings/support. AZ mətnlər, aydın düymələr, səliqəli boşluqlar, kiçik ekran uyğunluğu və loading/error/offline halları olsun. Real PIN istəmə: demo sahəsinə yalnız dummy fixture daxil edilir, screenshot-da masked olur.

## PREVIEW-3 — Sadə mobil ekran

Telefon görünüşü: Kilidlə, Kilidi aç, cihaz adı və əlaqə/nəticə statusu. Android/iPhone ana ekrana əlavə etmə təlimatı və QR qoşulma görünüşü hazırla. Responsive preview lokal URL ilə açılsın. Demo QR yalnız lokal preview/simulyasiya üçündür, real idarəetmə tokeni daşımır.

## PREVIEW-4 — Admin görünüşü və kliklənən axınlar

Owner admin üçün PC siyahısı, online/offline, versiya, qeydiyyat və redacted xəta timeline ekranını hazırla. Desktop→QR→mobil və admin→cihaz detalları kliklə nümayiş etdirilsin. Backend endpoint hazırdırsa uyğun bağla; deyilsə typed demo data adapteri istifadə et. DEMO statuslarını real online, real qeydiyyat və real unlock kimi təqdim etmə. Demo lock/unlock yalnız UI state-ni dəyişir, native input göndərmir.

## PREVIEW-5 — Önizləmə təhvili və xəta siyahısı

- Dev server-i işlək saxla; port, lokal URL, start/stop və build əmrlərini yaz. Mümkündürsə desktop shell-i normal user kimi aç; alınmırsa browser frontend-i göstər, bunu EXE işləyir kimi təqdim etmə.
- Desktop, mobil və admin ekranlarının real render screenshot-larını saxla. Uydurma screenshot/mockup icra sübutu deyil.
- Typecheck/build və əsas click/navigation smoke yoxlaması apar. Hər düymənin demo/real/işləməyən statusunu göstər.
- plan/KNOWN_ISSUES.md yarat və ya yenilə: ID, ekran/komponent, reproduce, təsir, prioritet, real/demo vəziyyəti, sonra düzəliş üçün qeyd. Mövcud audit tapıntılarını silmə; hər əvvəlki fayla keçid ver. Hələ düzəldilməyən tapıntı bağlandı sayılmasın.
- plan/reports/FRONTEND_PREVIEW_REPORT.md-də açılan URL, screenshot yolları, build nəticəsi, işləyən axınlar və qalan maneələri qısa yaz.

## İş rejimi

Səhv görəndə qeyd et və önizləmə işinə davam et. Yalnız açılışı bloklayan xətanı və ya preview özü həssas məlumatı ifşa edirsə həmin problemi dərhal düzəlt. Tam rollback/SCM/crypto/VM auditinə dalıb frontend-i gecikdirmə. Mövcud engine/backup/production Sites paylaşımını dəyişmə, şəxsi hostda service/startup quraşdırma. Demo internetə açıq publish edilmir və production credential istifadə etmir.

İlk görünüş hazır olan kimi istifadəçiyə URL və necə açılacağını təqdim et. Beş preview paketinin sonunda FRONTEND_PREVIEW_REPORT.md və KNOWN_ISSUES.md ilə dayan. Sonrakı düzəlişlər istifadəçinin görünüş rəyindən və Codex-in toplanmış auditindən sonra ayrıca batch olacaq. Köhnə stage qəbulları dəyişmir; bu önizləmə məhsulun hazır/təhlükəsizlik auditindən keçmiş olduğu demək deyil.
