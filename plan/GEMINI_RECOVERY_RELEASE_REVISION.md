# Yekun qəbul: qalıq boot/recovery/release blokları

Codex əvvəlki iki gateway harness-i yenidən işlətdi: hər ikisi exit 0, altı əvvəlki reproduksiya artıq yoxdur. Bu məhdud alt-nəticəni qəbul edirik; bütöv məhsul qəbulu deyil.

## Təkrarlanan konkret qüsurlar
`python scripts/codex_recovery_boundary_audit.py` exit 1 (MODEL_FAULT_INJECTION, real Win32/ekran/SCM çağırışı yoxdur):
- FAILED_PID_AND_WRITE_ACCEPTED_AS_HEALTHY: PID sorğusu və WriteFile uğursuz olsa da check_pipe_health True qaytarır. Xəta branch-indəki şərtsiz True silinsin. PID alınmaması fail-closed, response strict schema/action/state, partial I/O handling və overlapped deadline/cancel/drain olsun. Sinxron ReadFile loop-un vaxt həddini poza bilər. Cavabda 'status'/'success' substring olması sağlamlıq deyil. Handle tam bir dəfə bağlansın; LKG də eyni health/probation yoxlamasından keçsin.
- UNSIGNED_INVALID_SLOT_ACCEPTED: imzasız, PE olmayan winkey_service.exe faylı _is_slot_valid tərəfindən qəbul olunur. Manifestsiz fallback çıxarılsın və ya ilkin etibarlı paket üçün ayrıca kriptoqrafik installer trust sübutu yaradılsın. Manifest target/entrypoint/path/reparse/version hash binding və aktivasiya öncəsi yenidən yoxlama tələb olunur.

## Yeni installer geriləməsi — bloklayıcı
- BootMode Auto Python tapanda adi python.exe service_supervisor.py --service prosesini SCM binPath edir. Skript StartServiceCtrlDispatcher/RegisterServiceCtrlHandler/SetServiceStatus həyata keçirmir: argparse --service adi prosesi Windows xidməti etmir. Actual native SCM recovery host (və ya düzgün paketlənmiş service implementation) yaz; idarə olunan Python-suz runtime təmin et. Şəxsi hostda install etmə; VM integration test və ya NOT_TESTED qeyd et.
- Quraşdırılan supervisor `from pc_agent.update_rollback_engine` import edir, amma installer iki faylı flat InstallDir-ə kopyalayır; pc_agent paketi yoxdur. ZIP də flat-dır, installer mənbə kimi ../pc_agent axtarır. Çıxarılmış ZIP clean working-dir testini əlavə et; source tree-dən işləmək sübut deyil.
- Installer initial signed slots/journal/real pinned key qurmur; supervisor default public key 00...dır. Boot üçün validated slot və pinned production/test key müqaviləsi tam qurulsun. Məhsul xidməti 60 saniyə timeout standalone kimi bitməməlidir.

Əsas bütün-qalıqlar tapşırığı qüvvədədir. Pairing local PC approval (owner_approved DEFAULT 1 deyil, actual phone claim təsdiqi), deploy/Sites, Python-suz end-user setup, actual diagnostics sender və real update pipeline maddələrini source/test sübutu ilə IMPLEMENTED/PARTIAL/BLOCKED göstər. 15/15 mövcud dar test bu qalıqları bağlamır.

Kod düzəlişləri və yeni negative tests hamısı toplu verilsin; testləri yalnız mətnə uyğunlaşdırmaq üçün zəiflətmə. Əvvəlki logları saxla, yeni revision evidence qovluğu yarat. Son ZIP extracted clean layout smoke/installer dry-run + VM SCM/start-stop/reboot test kateqoriyalarını ayır. Fiziki unlock yalnız operator opt-in; nonphysical default qalsın.
