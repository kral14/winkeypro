# <STAGE> — Gemini hesabatı

- İcraçı/model/sessiya:
- Tarix:
- Başlanğıc və bitiş commit; Git yoxdursa dəyişən faylların hash manifesti:
- Status: READY_FOR_AUDIT / BLOCKED (Codex qəbulu deyil)
- Scope:

## Fayllar
| Fayl | Dəyişiklik | Məqsəd |
|---|---|---|

## Qəbul meyarları
| Stage meyarı | Nəticə | Sübut |
|---|---|---|

## Testlər
| Tam əmr / əl addımı | OS build/arxitektura | Mock/VM/fiziki | Exit code/nəticə | Evidence |
|---|---|---|---|---|

## Yanlış ssenarilər və təhlükəsizlik
Auth/IDOR/replay/expiry/IPC/secret redaction və mərhələyə aid fault injection.

## Regression
Əvvəl işləyən nə yenidən yoxlandı, nə yoxlanmadı?

## Artifactlər
Versiya, installer/bundle SHA256, signature statusu. Private key/credential əlavə etmə.

## Məhdudiyyət və risklər
Açıq xətalar, yoxlanmamış mühit və xarici asılılıq. İnternet xətasını proqram regresiyası ilə qarışdırma.

## Auditor üçün reproduksiya
Eyni nəticəni almaq üçün konkret minimum addımlar.

## Qəbul istəyi
Yalnız cari stage üzrə qəbul istə; növbəti mərhələ başlanmayıb.


## Diaqnostika/support sübutu
Stage/error event nümunələri (redacted), collector/outbox vəziyyəti, delivery/dedup/latency ölçməsi, admin timeline sübutu, PIN/token canary scan. Uyğun deyilsə səbəb göstər.
