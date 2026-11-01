# Sites təhvili auditi — publish hələ qəbul deyil

LAN auth state əlavə edilməsi irəliləyişdir. Amma web_remote actual source aşağıdakı qüsurlara görə publish-ready deyil. Əsas CLOUD_AND_LAN tapşırığı üzrə hamısını bir toplu düzəlt, xırda alt mərhələdə dayanma.

## P0 — Cloud cihaz identity takeover
app/api/[...path]/route.ts agent/register A branch:
`deviceId.length > 0 && (body.public_key_hex || body.proof_signature_hex)` yalnız sahənin varlığını yoxlayır. crypto Ed25519 import/verify, nonce binding/expiry/atomic consume yoxdur. Mövcud device ID üçün secret_hash autentifikasiyasız UPDATE edilir. İstənilən caller həmin ID-ni təqdim edib özünə secret ala bilər.
- Required validated Ed25519 public key və actual signature verify; native mesaj müqaviləsi `WINKEY_REGISTER:{nonce}:{device_id}` ilə eyni olsun. Challenge D1 durable, target/purpose binding, atomic consume; in-memory Map Worker isolates üçün qəbul deyil.
- Existing key/secret ownership sübutu olmadan secret rotation/update qəti rədd. Pre-hashed unauth direct register fallback çıxarılsın. DB-də bound public key/revoked/status və lazım olan migrations olsun.
- Mənfi testlər: missing/malformed/wrong-key signature, unknown/expired/reused/wrong-device nonce, same public key without proof, existing device secret takeover, concurrent registration/claim; hər birində persistent state dəyişməsin.

## Public mobile vs private admin
- Cloud /api/pair hazırda ChatGPT user header ilə owner bağlayır. Məhsul tələbi: istehlakçı telefon sahibin ChatGPT hesabına girmir. Public mobile device-scoped bearer session + PC approval olmalıdır, owner admin ayrı private audience.
- `x-user-id` fallback caller-controlled header-dən owner identity götürməsin. Trusted Sites identity server kontraktı ilə admin auth ayrılsın. Public worker/API admin identity header-i browserdən qəbul etməsin.
- Mövcud private site audience-ni ictimailəşdirib admini açmaq həll deyil; public gateway/mobile ayrı Site + private admin server-side authenticated integration kimi hazırla. Bypass key native/mobile/source/loga daxil edilmir.

## Native/backend müqaviləsini eyniləşdir
- Native desktop POST /agent/* və /devices/pair-request, worker POST /agent/poll/result çağırır; Sites routes yalnız /api/*-dir. API base ilə mobile base ayrı config olsun; origin-ə /api əlavə edib QR-ni /api/mobile yaratma.
- Native helper register/pair/result shapes, expiry units və mobile session proof serverlə actual integration testdən keçsin. localhost Python source eyni testin əvəzi deyil.
- Dashboard artıq demo devices/success fallback saxlamamalıdır; actual confirmed command result polling və full tenant-safe telemetry/admin DB schema hazır olsun. DB boşdursa boş siyahı göstər.

## Təhvil/publish
Source checked build+migrations və actual Worker integration evidence təqdim et. Codex Sites connector ilə publish edəcək; platforma sirri tələb etmə. Deploy nəticəsi olmadan 'canlı cloud işləyir' demə. Private admin/public mobile ayrı layihə tələbini supported Sites workflow üzrə hazırla. LAN setup isə actual phone test olunmayıbsa yalnız TEST/NOT_TESTED etiketilə qalsın.
