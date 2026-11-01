# Gemini — önizləmənin son görünüş və launcher düzəlişi

Yeni screenshot-a baxışda mobil layout pozulub: DEMO banner solda sütun kimi qalır və ekranı sağa sıxır. plan/KNOWN_ISSUES.md son UI-005/PRE-002/PRE-003 qeydlərini oxu.

1. Mobil demo banner yuxarıda, əsas control aşağıda tam responsive olsun. 360/390/430px screenshot və üfüqi overflow yoxlaması saxla. Desktop/admin görünüşünü qoru.
2. stop_preview.ps1-də $pId istifadə etmə (read-only $PID ilə toqquşur). Portdakı istənilən node/cmd-ni öldürmə. Yalnız öz başlatdığı workspace prosesini PID+creation-time+command/path və process tree üzrə doğrulayaraq stop et; ownership sübutu yoxdursa xəbər ver və stop etmə.
3. Start script explicit web_remote cwd istifadə et, /desktop endpoint sağlamlığını və server workspace kimliyini yoxla; sağlamlıq alınmırsa browser açmaq əvəzinə log yolu və xəta ver. Mövcud başqa workspace/port prosesinə toxunma. Start-Process hidden qalsın.
4. Başlat→HTTP200→ikinci start duplicate yaratmır→öz prosesini stop sınağını ayrıca test port/proses ilə et; unrelated proses saxlanılsın. Powershell parse/runtime xətalarını yoxla. Şəxsi mövcud serveri icazəsiz öldürmə.

FRONTEND_PREVIEW_REVISION_3.md və ayrıca screenshot/test log təqdim et. Backend/security auditinə keçmə, production dəyişmə. Görünüşü göstərmək prioritetdir.
