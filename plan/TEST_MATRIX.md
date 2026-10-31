# Məhsulun test matrisi

Dəstək hədəfi A/B-də dəqiq OS buildləri ilə qəbul edilir. Bütün PC-lərdə sıfır xəta vədi yoxdur.

| Mühit | Məcburi sübut |
|---|---|
| Windows 11 x64 clean VM, Python/Node/Rust olmadan | Installer/WebView2/register/tray/repair/uninstall |
| Windows 11 x64 fiziki PC | Default pərdə, Winlogon/PIN, monitor sleep, reboot, şəbəkə keçidi |
| Windows 10 x64 | Yalnız dəstək hədəfi qəbul edilərsə ayrıca eyni matris |
| Admin və standard user | İlkin install elevation; gündəlik UI normal user |
| 100/125/150/200% DPI, kiçik ekran, AZ/EN klaviatura | UI kəsilməməsi, fokus/simvol uyğunluğu |
| Bir neçə sessiya/RDP | Yanlış user/session əmrləri rədd edilir |
| Android Chrome və iPhone Safari | QR, expiry/replay, ana ekran, session revoke |
| Ayrı Wi-Fi/NAT/mobil data, offline→online | Port açmadan əlaqə, reconnect və dürüst offline status |

## Funksional
- X-dən sonra heartbeat/command davam edir; ikinci launch duplicate worker yaratmır.
- Rebootda service başlayır; login zamanı tray görünür. İlk Windows sign-in ayrıca test/nəticədir.
- PIN yalnız bir dəfə yazılır. Yanlış PIN retry loop yaratmır.
- Görünən Default pərdəsinə klik → Winlogon/fokus təsdiqi → PIN. Inactive desktop input-u success sayılmır.
- İki ayrı sınaq istifadəçisi A/B: device ID/token dəyişikliyi digər cihaz və admin API-yə giriş vermir.
- Revoke-dan sonra telefon əmri rədd edilir; expired/replayed command icra edilmir.
- Sirrlər log, screenshot, crash dump, source və serverə düşmür.

## Fault injection
Saxta signature/hash, interrupted download, disk dolması, power loss, antivirus/file lock, IPC uyğunsuzluğu, startup crash, worker hang, credential-read regresiyası və server outage ayrı yoxlanır.
Offline/PIN xətası versiya rollback triggeri olmur.

## Sübut
Mock məntiqi, VM təmiz quraşdırmanı, fiziki PC Windows input davranışını sübut edir.
İlkin beta meyarı təklifi: 3 fərqli clean VM/PC quruluşunda install/reboot, ən az 1 fiziki PC-də 20 ardıcıl lock/unlock cycle, 10 update/crash/rollback fault ssenarisi. A-da rəqəmlər sahib/auditorla yekunlaşdırılır; bu, zəmanət deyil.


## Məcburi telemetry/support testləri
DIAGNOSTICS_SUPPORT.md son qəbul checklist-i bütün matrisə tətbiq olunur: installer stage failure, GUI/worker crash, offline→reboot→replay, dedup, canary secret scan, server 5xx, disk full, append-only ingest isolation, admin instruction→resolution və latency ölçümü.
