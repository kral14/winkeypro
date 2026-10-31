# B.2b — yekun məhdud qəbul

Tarix: 2026-10-28. Qərar: ACCEPTED (yalnız user-channel təhlükəsizlik spike-ı).

Statik kod yoxlamasında checked_revert_to_self_or_fatal həm OpenThreadToken error, həm əsas teardown yolunda çağırılır; real revert uğursuzluğu dedicated exit 202 ilə nəticələnir. IPC_AUTH_REVISION_2.md və 06_ipc_auth_rev2_raw_output.txt-də disposable child normal/fatal exit və marker yoxluğu nəticələri təqdim edilib. Auditor runner-i təkrar icra etməyib; execution nəticələri Gemini-yə aiddir.

Dar DACL, pre-transfer server binding və revert fatal path üzrə bu alt-tapşırıq bağlanır. Production SCM/SYSTEM helper binding, qorunan install ACL-ləri, başqa real Windows istifadəçi/remote testləri NOT_TESTED qalır. B.2a timeout/framing və B.1 pairing qəbulları qüvvədədir.

B ümumi PARTIAL/CHANGES_REQUESTED qalır. Növbəti alt-tapşırıq B.3: hər launch/fallback üçün imzalı slot doğrulaması və last-known-good recovery modeli; real boot/service sübutu ayrıca açıqdır. C bağlıdır.
