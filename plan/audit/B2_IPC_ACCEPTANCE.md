# B.2 — Codex audit

Tarix: 2026-10-28. Qərar: CHANGES_REQUESTED. Statik mənbə və test yoxlaması aparıldı; runner yenidən icra edilmədi.

İrəliləyiş: explicit security descriptor, FIRST_PIPE_INSTANCE, REJECT_REMOTE_CLIENTS, OS client SID ölçməsi, NOT_IMPLEMENTED və malformed rejection mənbədə var. Tam alt-qəbul üçün aşağıdakılar açıqdır:

1. P1 — Real timeout yoxdur. execute_secure_ipc_roundtrip timeout-u yalnız server-ready kanalında istifadə edir. ConnectNamedPipe/ReadFile/WriteFile və thread join bloklanır. main.rs:188–193 “silent” client dərhal handle-ı bağlayır: bu EOF/disconnect sınağıdır, qoşulu və susan peer timeout-u deyil. 3000 default pipe timeout-u sinxron ReadFile üçün deadline yaratmır.
2. P1 — Client server identity-ni yalnız oxuyub qaytarır, payload göndərməzdən əvvəl etibarlı gözlənilən PID/token ilə yoxlamır. Testin sonradan session==console assert-i server autentifikasiyası deyil. Client SECURITY_IMPERSONATION verir: gələcək həssas kanal üçün server etibarı məlumat/əməl ötürülməzdən qabaq yoxlanmalıdır.
3. P1 — Byte pipe-da tək ReadFile tam frame deyil. Fragmentasiya, yarımçıq/trailing frame və böyük payload üçün etibarlı framing yoxdur. Oversize test də təqdim olunmayıb. WriteFile və identity API nəticələrinin bir qismi yoxlanmır; RevertToSelf uğursuzluğu nəzərə alınmır.
4. P2 — DACL bütün Interactive Users qrupuna açıqdır; bu konkret istifadəçi+SYSTEM minimum siyahısı deyil. Siyasət tətbiq səviyyəsində əlavə rədd etsə də bunu “yalnız icazəli user ACL-i” kimi təqdim etmə. Privileged SYSTEM/helper kanalı hələ layihə təsviridir, implementasiya sübutu deyil. User-policy-də session0 rəddi gələcək SYSTEM/helper kanalına kor-koranə daşınmamalıdır.

Növbəti ötürmə yalnız 1 və 3: real deadline/cancellation və framing, aşağıdakı GEMINI_B_REVISION.md üzrə. Sonra 2/4 ayrıca bağlanacaq. B.1 pairing qəbulu qüvvədədir. B PARTIAL; C bağlıdır.
