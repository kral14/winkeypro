# Cari giriş nöqtəsi

Aktiv tapşırıq: `plan/GEMINI_WEBSOCKET_BATCH.md`. Onu tam oxu və icra et.
Bu faylın aşağısı köhnə A mərhələsinin tarixi qeydidir, cari scope deyil.

---
# Tarixi ilk ötürmə — yalnız A məsləhət mərhələsi

Layihə: WinKey Pro. İş qovluğu: D:\rust desk mobil kilid acma.
Sən icraçı Gemini-sən. Codex müstəqil auditor və qəbulçudur. Hazırda implementasiya başlanmır.

Oxu: plan/README.md, STATUS.json, DECISIONS.md, ARCHITECTURE.md, UPDATE_ROLLBACK.md, GEMINI_RULES.md və stages/A_MESLEHET.md.

Tapşırıq:
1. Tauri 2 + React + ayrıca Windows supervisor/service təklifini Electron/Tkinter ilə məhsul tələbləri əsasında qiymətləndir. UI seçimini Session 0 etibarlılığı ilə qarışdırma.
2. Mövcud Default→Winlogon axınını qorumaq, düzgün Windows SID/session-da helper başlatmaq üçün B spike planı ver.
3. Private admin və kənar istifadəçilər üçün cihazla məhdud mobil axının iki Sites layihəsində qurulmasını cari imkanlarla yoxla. Shared bypass key-i EXE-yə paylamağı təklif etmə.
4. İmzalı multi-component release və independent last-known-good recovery dizaynındakı boşluqları göstər. İnternet/PIN xətası rollback səbəbi deyil.
5. Mövcud sübut, rəsmi sənəd, fərziyyə və fiziki test tələb edən riskləri ayrı göstər.
6. REPORT_TEMPLATE.md üzrə yalnız plan/reports/A_REPORT.md yaz. Plan dəyişikliklərini təklif kimi ver. Kod/paylaşım/xidmət/secret/release dəyişmə.
7. READY_FOR_AUDIT təqdim et; Codex qəbulundan əvvəl B-yə keçmə.

Gemini-yə faktiki dispatch bu fayl yaradılmaqla baş vermir. İcra ayrıca təsdiqlənməli və reportda sessiya/model göstərilməlidir.


Yeni sahib qərarı: Tauri+React və ayrıca Windows xidməti qəbul edilib. DIAGNOSTICS_SUPPORT.md-ni mütləq oxu: installerin ilk mərhələsindən real-time best-effort eventlər, ayrı crash collector, offline outbox, admin timeline və support knowledge-base tələbdir. A hesabatında bunu və qeyri-mümkün before-process/elektrik/internetsiz vəziyyət sərhədlərini qiymətləndir. Kod yazmağa keçmə.
