<div align="center">

# DƏLİL 🇦🇿

**Kriptoqrafik olaraq yoxlanıla bilən audit infrastrukturu**

İstifadəçilərin, auditorların və məhkəmələrin müstəqil şəkildə yoxlaya biləcəyi
audit hadisələrini qeydə alın. Hər dəyişiklik, silinmə, əlavə və ya sıranın
pozulması aşkar edilir və dəqiq yeri göstərilir.

[![CI](https://github.com/serxan22/delil/actions/workflows/ci.yml/badge.svg)](https://github.com/serxan22/delil/actions/workflows/ci.yml)
[![Security](https://github.com/serxan22/delil/actions/workflows/security.yml/badge.svg)](https://github.com/serxan22/delil/actions/workflows/security.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

[English](./README.md) | Azərbaycanca

</div>

---

DƏLİL Azərbaycanda hazırlanmış açıq mənbəli audit infrastrukturudur. Adı
Azərbaycan dilindəki "dəlil" sözündən gəlir.

Əksər audit jurnalları verilənlər bazasındakı adi sətirlərdir: kifayət qədər
girişi olan hər kəs onları heç kimin xəbəri olmadan dəyişə bilər. DƏLİL belə
dəyişikliyi **aşkar edilə bilən** edir. Tətbiqlər həssas audit hadisələrini
DƏLİL-ə göndərir. Hər hadisə kanonikləşdirilir (RFC 8785), hash-lənir
(SHA-256), öz stream-indəki əvvəlki hadisəyə bağlanır və rəqəmsal imza ilə
imzalanır (Ed25519). Yoxlama zamanı bunların hamısı yenidən hesablanır və
hansı qeydin necə dəyişdirildiyi dəqiq göstərilir. Yoxlamanı serverə etibar
etmədən, auditorun öz kompüterində də aparmaq olar.

```text
$ delil verify --stream payments --trusted-keys trusted-keys.json     # çıxış qısaldılıb

Hash chain:         VALID
Payload hashes:     INVALID
Digital signatures: VALID
Tampering detected: YES

First invalid event:
  Sequence:  17
  Failure:   payload hash mismatch
  Detail:    the event content does not match the payload hash committed in the
             signed header; the content was modified
```

## İmkanlar

- **Müdaxiləni aşkar etməyə imkan verən stream-lər.** Hər stream üçün Ed25519
  imzalı hash zənciri, imzalı checkpoint-lər, açar rotasiyası və açarın ləğvi.
  Dəyişdirilmiş məzmun, aktor və ya vaxt; silinmiş, əlavə edilmiş, yeri
  dəyişdirilmiş və sırası pozulmuş hadisələr; saxta imzalar; zəncirin sonunun
  kəsilməsi və (şahid checkpoint-ləri ilə) bazanın əvvəlki vəziyyətə
  qaytarılması aşkar edilir.
- **Müstəqil yoxlama.** `delil` CLI xam zənciri endirir və onu əvvəlcədən
  sabitlənmiş açıq açarlarla yerli olaraq yoxlayır. Ələ keçirilmiş server
  uğurlu nəticəni saxtalaşdıra bilməz.
- **Oflayn dəlil paketləri.** Seçici açıqlama ilə imzalı ZIP ixracı: qalan
  hadisələri göstərmədən konkret hadisələrin bütöv zəncirdə yer aldığını sübut
  edin. `delil verify-export` üçün nə server, nə də verilənlər bazası lazımdır.
- **Real istismar üçün hazırlanıb.** Yalnız əlavə etməyə (append-only) icazə
  verən trigger-lər və minimal hüquqlu iş rolu ilə PostgreSQL, təhlükəsiz
  paralel yazma, atomar batch-lər, idempotent təkrar cəhdlər, multi-tenant
  arxitektura, səlahiyyətləri məhdudlaşdırılmış API açarları, sorğu limitləri,
  hash-ləmədən əvvəl gizli məlumatların redaktəsi və Prometheus metrikləri.
- **Tam alətlər dəsti.** REST API ([OpenAPI](api/openapi.yaml)), TypeScript
  SDK, CLI, Next.js idarəetmə paneli, Docker image-ləri və işlək
  [nümunələr](examples).
- **Açıq və yoxlanıla bilən.** Sənədləşdirilmiş konstruksiya, müstəqil Node.js
  realizasiyası ilə təkrarlanan dərc edilmiş [test vektorları](docs/test-vectors.json)
  və yalnız standart kriptoqrafik primitivlər.

<p align="center">
  <img src="docs/assets/overview.png" alt="İdarəetmə panelinin ümumi görünüşü" width="49%">
  <img src="docs/assets/verification-failed.png" alt="Dəyişdirilmiş hadisənin yerini göstərən uğursuz yoxlama" width="49%">
</p>

## Sürətli başlanğıc

Compose dəstəkli Docker lazımdır.

```bash
git clone https://github.com/serxan22/delil && cd delil
cp .env.example .env
make dev                 # PostgreSQL, :8080-də API, :3000-də idarəetmə paneli
make credentials         # admin girişi və API açarı (bir dəfə göstərilir)
```

<http://localhost:3000> ünvanını açıb daxil olun. Demo təşkilatda dörd
stream-də bir aylıq nümunə fəaliyyəti var.

### Hadisəni qeydə alın

```bash
export DELIL_API_KEY=dlk_…        # make credentials əmrinin çıxışından

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
`payloadHash`, imza və imzalama açarının identifikatoru. TypeScript SDK ilə:

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

### Yoxlayın, sonra pozmağa çalışın

```bash
go build -o bin/delil ./cmd/delil         # və ya buraxılışdakı hazır binary faylı yükləyin
export DELIL_URL=http://localhost:8080

bin/delil keys export > trusted-keys.json # açıq açarları sabitləyin (bu faylı etibarlı yerdə saxlayın)
bin/delil verify --trusted-keys trusted-keys.json

make tamper-demo   # geri ödəniş məbləğini birbaşa PostgreSQL-də dəyişir və yenidən yoxlayır
```

Demo, superuser-in edə biləcəyi kimi, bazanın öz qoruma mexanizmlərini yan
keçir. Yoxlama gözlənilən və tapılan hash-ləri göstərərək məhz həmin sıra
nömrəsində uğursuz olur. `make reset` təmiz bazanı bərpa edir.

### Dəlil paketini ixrac edin

```bash
bin/delil export --stream contracts --resource-type contract --resource-id contract_813 -o contract-813.zip
bin/delil verify-export contract-813.zip --trusted-keys trusted-keys.json   # oflayn
```

## Necə işləyir

```text
payloadHash = SHA-256("delil:v1:payload" ‖ 0x00 ‖ JCS(content))
eventHash   = SHA-256("delil:v1:event"   ‖ 0x00 ‖ JCS(header))     header = {tenant, project, stream, sequence,
signature   = Ed25519(sk, "delil:v1:event-signature" ‖ 0x00 ‖ eventHash)    eventId, recordedAt, previousHash,
                                                                            payloadHash, keyId, schemaVersion}
 ┌────────────┐     ┌────────────┐     ┌────────────┐
 │ event #1   │◄────│ event #2   │◄────│ event #3   │◄── stream head ◄── signed checkpoints ──► witnesses
 │ prev = 0…0 │     │ prev = h1  │     │ prev = h2  │
 └────────────┘     └────────────┘     └────────────┘
```

Məzmunda edilən istənilən dəyişiklik onun `payloadHash`-ini dəyişir.
Başlıqdakı (header) istənilən dəyişiklik hadisə hash-ini (`eventHash`)
dəyişir; bu da imzanı və növbəti hadisə ilə bağlantını pozur. Hadisənin
silinməsi və ya əlavə edilməsi sıra nömrələrini və bağlantıları pozur. Sistemdən
kənarda saxlanılan checkpoint-lər (şahidlər) zəncirin sonunun kəsilməsini və
bazanın əvvəlki vəziyyətə qaytarılmasını üzə çıxarır. Ətraflı:
[kriptoqrafik model](docs/cryptographic-model.md) ·
[təhdid modeli](docs/threat-model.md).

## Nəyi sübut edir, nəyi sübut etmir

DƏLİL müdaxilənin qarşısını almır, onu **aşkar edir**. Sistem məlumatın
bütövlüyünün kriptoqrafik şəkildə yoxlanılmasına imkan verir: yoxlanılmış
qeydin imzalandıqdan sonra dəyişdirilmədiyini, silinmədiyini və sırasının
pozulmadığını göstərir.

DƏLİL tətbiqlərin bildirdiklərini qeydə alır, lakin özü-özlüyündə aşağıdakıları
sübut etmir:

- hadisənin həqiqətən baş verdiyini və ya məzmununun doğru olduğunu;
- `actor` kimi göstərilən şəxsin həmin hərəkəti həqiqətən etdiyini;
- məlumatın qanuni yolla toplandığını;
- qeydin istənilən yurisdiksiyada avtomatik olaraq məhkəmədə sübut kimi qəbul
  ediləcəyini;
- sistemin hər hansı uyğunluq (compliance) tələblərinə tam cavab verdiyini.

Ətraflı: [hüquqi məsələlər](docs/legal.md) (sənəd hüquqi məsləhət deyil).

## Sənədlər

Sənədlər hazırda ingilis dilindədir.

| | |
|---|---|
| [Arxitektura](docs/architecture.md) | komponentlər, verilənlər modeli, əlavə etmə protokolu, fon prosesləri |
| [Kriptoqrafik model](docs/cryptographic-model.md) | nəyin kanonikləşdirildiyi, hash-ləndiyi və imzalandığı; yoxlama; dəlil paketinin formatı |
| [Təhdid modeli](docs/threat-model.md) | hücum edənlər, nəyin aşkar edildiyi, qalıq risklər |
| [Təhlükəsizlik əməliyyatları](docs/security.md) | sərtləşdirmə, açarlar, şahidlər, insidentə cavab |
| [Yerləşdirmə](docs/deployment.md) | istismar mühitində quraşdırma və bütün konfiqurasiya dəyişənləri |
| [Məxfilik](docs/privacy.md) | minimallaşdırma, redaktə, silinmə və açıqlama |
| [Hüquqi məsələlər](docs/legal.md) | yoxlanılmış qeydin nəyi göstərdiyi |
| [İnkişaf](docs/development.md) | build, test, buraxılış |
| [Performans](docs/benchmarks.md) | ölçülmüş ötürmə qabiliyyəti və onu necə təkrarlamaq |
| [REST API](api/openapi.yaml) · [TypeScript SDK](sdk/typescript) · [Nümunələr](examples) | |

## Layihənin quruluşu

```text
cmd/        delil-server, delil (CLI), delil-bench
pkg/        jcs · integrity · verify · evidence · client    pure Go core, no I/O
internal/   API, storage, ingestion, keys, exports, workers
migrations/ PostgreSQL schema         api/  OpenAPI 3.1
sdk/        TypeScript SDK            apps/ dashboard (Next.js)
examples/   runnable integrations     docs/ documentation
```

## Vəziyyət

Versiya 0.1, ilkin buraxılış. Bütövlük konstruksiyası (sxem versiyası 1)
sabitdir və dərc edilmiş test vektorları ilə əhatə olunub. 1.0-a qədər API-lər
dəyişə bilər. KMS/HSM açar provayderləri, checkpoint-lər üçün RFC 3161 vaxt
damğası və məzmunun tombstone-larla silinməsi planlaşdırılır.

## Töhfə və təhlükəsizlik

Töhfələr xoş qarşılanır: [CONTRIBUTING.md](CONTRIBUTING.md) və
[davranış qaydaları](CODE_OF_CONDUCT.md). Zəiflikləri [SECURITY.md](SECURITY.md)
sənədində göstərildiyi kimi məxfi şəkildə bildirin.

## Lisenziya

[Apache License 2.0](LICENSE).

---

<sub>Azərbaycanda hazırlanıb 🇦🇿</sub>
