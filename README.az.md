<div align="center">

# DƏLİL

**Kriptoqrafik yolla yoxlanıla bilən audit infrastrukturu**

İstifadəçilərinizin, auditorlarınızın və məhkəmənin müstəqil yoxlaya biləcəyi
audit hadisələri qeydə alın. Hər dəyişiklik, silinmə, əlavə və ya sıranın
pozulması aşkar edilir və dəqiq yeri göstərilir.

[![CI](https://github.com/serxan22/delil/actions/workflows/ci.yml/badge.svg)](https://github.com/serxan22/delil/actions/workflows/ci.yml)
[![Security](https://github.com/serxan22/delil/actions/workflows/security.yml/badge.svg)](https://github.com/serxan22/delil/actions/workflows/security.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

[English](README.md) · **Azərbaycanca**

</div>

---

Əksər audit jurnalları verilənlər bazasındakı adi sətirlərdir və kifayət qədər
girişi olan hər kəs onları səssizcə dəyişə bilər. DƏLİL bu cür dəyişikliyi
**aşkar edilə bilən** edir. Hər hadisə kanonik formaya salınır (RFC 8785),
heşlənir (SHA-256), öz axınındakı əvvəlki hadisəyə bağlanır və imzalanır
(Ed25519). Yoxlama bunların hamısını yenidən hesablayır və hansı qeydin necə
dəyişdirildiyini dəqiq göstərir. Yoxlama auditorun öz kompüterində, serverə
etibar etmədən də aparıla bilər.

```
$ delil verify --stream payments --trusted-keys trusted-keys.json     # çıxış qısaldılıb

Hash chain:         VALID
Payload hashes:     INVALID
Digital signatures: VALID
Tampering detected: YES

First invalid event:
  Sequence:  17
  Failure:   payload hash mismatch
```

## İmkanlar

- **Müdaxiləni aşkar edən axınlar.** Hər axın üçün Ed25519 imzalı heş
  zənciri, imzalı yoxlama nöqtələri (checkpoint), açarların rotasiyası və
  ləğvi. Dəyişdirilmiş məzmun, aktor və ya vaxt, silinmiş, əlavə edilmiş,
  yerləri dəyişdirilmiş hadisələr, saxta imzalar, zəncirin sonunun kəsilməsi
  və (şahid nöqtələri ilə) bazanın köhnə vəziyyətə qaytarılması aşkar edilir.
- **Müstəqil yoxlama.** `delil` CLI xam zənciri endirir və onu sabitlənmiş
  açıq açarlarla yerli olaraq yoxlayır. Ələ keçirilmiş server uğurlu nəticəni
  saxtalaşdıra bilməz.
- **Oflayn sübut paketləri.** Seçici açıqlama ilə imzalı ZIP ixracı:
  qalanlarını göstərmədən konkret hadisələrin bütöv zəncirdə olduğunu sübut
  edin. `delil verify-export` üçün nə server, nə də verilənlər bazası lazımdır.
- **İstehsalat üçün hazır.** Yalnız əlavə etməyə icazə verən triggerlər və
  minimal hüquqlu iş rolu ilə PostgreSQL, təhlükəsiz paralel yazma, atomar
  paketlər, idempotent təkrar cəhdlər, çoxkirayəçilik, səlahiyyəti
  məhdudlaşdırılmış API açarları, sürət limitləri, heşləmədən əvvəl gizli
  məlumatların silinməsi (redaction) və Prometheus metrikləri.
- **Tam alətlər dəsti.** REST API ([OpenAPI](api/openapi.yaml)), TypeScript
  SDK, CLI, Next.js idarəetmə paneli, Docker obrazları və işlək
  [nümunələr](examples).
- **Açıq və yoxlanıla bilən.** Sənədləşdirilmiş konstruksiya, müstəqil Node.js
  realizasiyası ilə təkrarlanan dərc edilmiş [test vektorları](docs/test-vectors.json),
  yalnız standart kriptoqrafik primitivlər.

<p align="center">
  <img src="docs/assets/overview.png" alt="İdarəetmə paneli" width="49%">
  <img src="docs/assets/verification-failed.png" alt="Dəyişdirilmiş hadisəni göstərən uğursuz yoxlama" width="49%">
</p>

## Sürətli başlanğıc

Compose ilə Docker lazımdır.

```bash
git clone https://github.com/serxan22/delil && cd delil
cp .env.example .env
make dev                 # PostgreSQL, :8080-də API, :3000-də idarəetmə paneli
make credentials         # admin girişi və API açarı (bir dəfə göstərilir)
```

http://localhost:3000 ünvanını açın və daxil olun. Demo təşkilatda dörd
axında bir aylıq nümunə fəaliyyəti var.

### Hadisəni qeydə alın

```bash
export DELIL_API_KEY=dlk_…        # make credentials əmrindən

curl -s http://localhost:8080/v1/events \
  -H "Authorization: Bearer $DELIL_API_KEY" -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: approve-contract-813' \
  -d '{
    "stream": "contracts",
    "actor": {"type": "user", "id": "user_128", "displayName": "Sarkhan Mahabbatli"},
    "action": "contract.approved",
    "resource": {"type": "contract", "id": "contract_813"},
    "before": {"status": "pending"},
    "after": {"status": "approved"}
  }'
```

Cavab imzalı qəbzdir: sıra nömrəsi, `eventHash`, `previousHash`,
`payloadHash`, imza və imzalayan açarın identifikatoru. TypeScript SDK ilə:

```ts
import { Delil } from "@delil/sdk";

const delil = new Delil({ baseUrl: "http://localhost:8080", apiKey: process.env.DELIL_API_KEY });
const receipt = await delil.events.record({
  stream: "contracts",
  actor: { type: "user", id: "user_128" },
  action: "contract.approved",
  resource: { type: "contract", id: "contract_813" },
  before: { status: "pending" },
  after: { status: "approved" },
});
```

### Yoxlayın, sonra pozun

```bash
go build -o bin/delil ./cmd/delil         # və ya buraxılışdakı hazır faylı yükləyin
export DELIL_URL=http://localhost:8080

bin/delil keys export > trusted-keys.json # açıq açarları sabitləyin (bu faylı etibarlı yerdə saxlayın)
bin/delil verify --trusted-keys trusted-keys.json

make tamper-demo   # geri ödəniş məbləğini birbaşa PostgreSQL-də dəyişir və yenidən yoxlayır
```

Demo, superistifadəçinin edə biləcəyi kimi, bazanın öz qoruma mexanizmlərini
yan keçir. Yoxlama gözlənilən və tapılan heşləri göstərərək məhz həmin sıra
nömrəsində uğursuz olur. `make reset` təmiz bazanı bərpa edir.

### Sübut paketini ixrac edin

```bash
bin/delil export --stream contracts --resource-type contract --resource-id contract_813 -o contract-813.zip
bin/delil verify-export contract-813.zip --trusted-keys trusted-keys.json   # oflayn
```

## Necə işləyir

```
payloadHash = SHA-256("delil:v1:payload" ‖ 0x00 ‖ JCS(məzmun))
eventHash   = SHA-256("delil:v1:event"   ‖ 0x00 ‖ JCS(başlıq))
signature   = Ed25519(sk, "delil:v1:event-signature" ‖ 0x00 ‖ eventHash)

 ┌────────────┐     ┌────────────┐     ┌────────────┐
 │ hadisə #1  │◄────│ hadisə #2  │◄────│ hadisə #3  │◄── axının başı ◄── imzalı yoxlama nöqtələri ──► şahidlər
 │ prev = 0…0 │     │ prev = h1  │     │ prev = h2  │
 └────────────┘     └────────────┘     └────────────┘
```

Başlıq kirayəçini, layihəni, axını, sıra nömrəsini, hadisə identifikatorunu,
qeydə alınma vaxtını, `previousHash`, `payloadHash`, açar identifikatorunu və
sxem versiyasını ehtiva edir. Məzmunun istənilən dəyişikliyi `payloadHash`-i
dəyişir. Başlığın istənilən dəyişikliyi `eventHash`-i dəyişir; bu isə imzanı
və növbəti hadisənin bağlantısını pozur. Hadisənin silinməsi və ya əlavə
edilməsi sıra nömrələrini və bağlantıları pozur. Sistemdən kənarda saxlanılan
yoxlama nöqtələri (şahidlər) zəncirin kəsilməsini və geri qaytarılmasını üzə
çıxarır. Ətraflı: [kriptoqrafik model](docs/cryptographic-model.md) ·
[təhdid modeli](docs/threat-model.md).

DƏLİL müdaxilənin qarşısını almır, onu **aşkar edir**. O, tətbiqlərin
bildirdiklərini qeydə alır, bunların doğru olub-olmadığını isə yoxlamır.
[Nəyi sübut edib nəyi sübut etmədiyini](docs/legal.md) oxuyun.

## Sənədlər

Sənədlər hazırda ingilis dilindədir.

| | |
|---|---|
| [Arxitektura](docs/architecture.md) | komponentlər, verilənlər modeli, əlavə etmə protokolu, fon prosesləri |
| [Kriptoqrafik model](docs/cryptographic-model.md) | nə kanonikləşdirilir, heşlənir və imzalanır; yoxlama; sübut paketinin formatı |
| [Təhdid modeli](docs/threat-model.md) | düşmən modelləri, nə aşkar edilir, qalıq risklər |
| [Təhlükəsizlik əməliyyatları](docs/security.md) | sərtləşdirmə, açarlar, şahidlər, insidentə cavab |
| [Yerləşdirmə](docs/deployment.md) | istehsalat quraşdırması və bütün konfiqurasiya dəyişənləri |
| [Məxfilik](docs/privacy.md) | minimallaşdırma, redaksiya, silinmə və açıqlama |
| [Hüquqi məsələlər](docs/legal.md) | yoxlanılmış qeyd nəyi nümayiş etdirir |
| [İnkişaf](docs/development.md) | yığma, test, buraxılış |
| [Performans](docs/benchmarks.md) | ölçülmüş göstəricilər və onların təkrarlanması |

## Vəziyyət

Versiya 0.1, ilkin buraxılış. Bütövlük konstruksiyası (sxem versiyası 1)
sabitdir və dərc edilmiş test vektorları ilə əhatə olunub. 1.0-a qədər API-lər
dəyişə bilər. KMS/HSM açar provayderləri, yoxlama nöqtələrinin RFC 3161 vaxt
damğası və məzmunun "tombstone"larla silinməsi plandadır.

## Töhfə və təhlükəsizlik

Töhfələr xoş qarşılanır: [CONTRIBUTING.md](CONTRIBUTING.md) və
[davranış qaydaları](CODE_OF_CONDUCT.md). Zəiflikləri [SECURITY.md](SECURITY.md)
sənədində təsvir edildiyi kimi gizli şəkildə bildirin.

## Lisenziya

[Apache License 2.0](LICENSE).
