# İmzalı yenilənmə və rollback müqaviləsi

Status: dizayn, hələ implementasiya yoxdur.

## Release
Git push → CI test/build → hash/signature/Windows code signing → canary/beta → audit və release qəbulu → stable manifest → agent download/check/apply.
Adi push test/build yaradır. Hər commit avtomatik bütün PC-lərə quraşdırılmır; yalnız qəbul edilmiş release stable olur.
Git hostu/depo hələ seçilməyib. Private repo istifadə olunarsa clientə PAT verilmir; imzalı, oxuna bilən release artifactləri və ya uyğun ayrıca download endpointi lazımdır. Sites admin release kampaniyasını göstərə bilər; binary storage H-də seçilir.

## İmza
Yalnız HTTPS. Signature/hash yoxlanmadan icra yoxdur. Private signing key yalnız CI secret və ya ayrıca signer-dədir.
Updater signature və Authenticode sertifikatı ayrı məqsəddir. Ad-hoc kripto yazılmır; yoxlanmış kitabxana və sabit kanonik manifest müqaviləsi seçilir.
Arxiv path traversal/zip bomb, disk dolması, yarımçıq download və file lock yoxlanır.
UI/worker/helper/IPC versiyaları bütöv bundle kimi uyğunlaşdırılır.
Vahid coordinator supervisor-dur. Tauri UI-nin ayrıca in-place updater-i eyni vaxtda müstəqil işləyə bilməz. Tauri plugin təkbaşına multi-component rollback həlli sayılmır.

## A/B aktivasiya
Sabit supervisor versions/<version>/ slotlarını idarə edir; user data/credentials ayrıca qalır.
Inactive slotda download və verify → pending journal → təhlükəsiz nöqtədə worker stop → current-slot göstəricisinin atomik dəyişməsi → candidate start → health/probation → last-known-good yenilənməsi.
Son işlək slot candidate qəbulundan əvvəl silinmir. Update PIN yazılması əsnasında tətbiq olunmur. Əmrlər replay edilmir.
Supervisor özünü yeniləyəcəksə ayrıca minimal bootstrapper/installer recovery yolu tələb olunur. Tək prosesin özünü restart etməsi etibarlı rollback deyil.

## Trigger təklifləri
- Candidate 30 saniyədə sağlam IPC vermir.
- 5 dəqiqədə 3 crash/startup crash loop.
- Integrity, component/IPC uyğunluğu və credential-read proqram regresiyası.
- 120 saniyəlik probation daxilində kritik lokal health xətası.
Hədlər I-də ölçülüb yekunlaşdırılır.

Rollback triggeri DEYİL: internet kəsilməsi, Sites 5xx, yanlış PIN, mobil səhifənin bağlanması. Bunlar retry/backoff və aydın statusla idarə olunur. Hər PIN xətasına rollback/retry hesab bloklanmasına yol aça bilər.

## Recovery
Pis candidate quarantine edilir; eyni versiya sonsuz quraşdırılmır. Rollback yalnız əvvəlcədən imzası yoxlanmış lokal last-known-good bundle-a olur; arbitrary köhnə versiyaya downgrade yoxdur.
DB/config əvvəlki versiya ilə uyğun qalmalıdır. Destructive migration rollback ssenarisi olmadan stable-a çıxmır.
Elektrik kəsiləndə journal vasitəsilə staging/pending/healthy bərpa olunur; yarımçıq slot aktiv edilmir.
UI update və rollback nəticəsini dürüst göstərir.

