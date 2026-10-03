# Benchmarks

Numbers are only meaningful with their environment, so each table says where it
was measured. Reproduce them with `make benchmark` (micro-benchmarks plus the
engine benchmark) and `delil-bench -url …` against your own deployment.

## Engine (no I/O)

`go run ./cmd/delil-bench -events 100000` builds 100,000 realistic events
(about 540 bytes canonical, with before/after diffs), seals them into one chain,
verifies the chain, then modifies one event and checks that verification
pinpoints it.

| Step | 4 vCPU Xeon 2.8 GHz (cloud VM), Go 1.27.1 |
|---|---|
| Validate, diff, canonicalize | ≈ 41,000 events/s |
| Hash, link, sign **and self-verify** (one stream, one core) | ≈ 9,100 events/s |
| Full verification (payload, header, link, signature, order) | ≈ 34,000 events/s |
| Tamper check | modified sequence 50,001 → `payload_hash_mismatch` at 50,001 |

Verification parallelizes the per-record work (hashing and Ed25519) across
cores within each batch, so it scales with CPU count. On an Apple M2 laptop,
100,000 events verified in about 1.1 s. Sealing happens under the stream's
lock and is single-threaded per stream by design. Every signature is verified
before commit, which roughly doubles its cost and is deliberate.

`go test -bench . ./pkg/...` (`BenchmarkVerifyStream`, 10,000-event chains):
≈ 33,000 events/s on the same VM.

## HTTP ingestion and verification

`delil-bench -url http://127.0.0.1:8080 -events 20000 -concurrency 8 -batch 50 -streams 4`
against `delil-server` and PostgreSQL 16 on the same 4 vCPU VM (local key
provider, rate limit raised for the test). Every written stream was then
verified locally (downloading the raw chain, as `delil verify` does) and on the
server.

| Scenario | Throughput | Request latency p50 / p95 / p99 |
|---|---|---|
| Batches of 50, 8 workers, 4 streams | ≈ 5,300 events/s | 64 / 149 / 188 ms per batch |
| Single events, 8 workers, 1 stream | ≈ 590 events/s | 6 / 49 / 79 ms |

| Verification of a 5,000-event stream | Time |
|---|---|
| Local (CLI path: download and verify) | ≈ 360–400 ms |
| Server-side (database pages, recorded run) | ≈ 245–270 ms |

What this shows:

- **Batch.** Each request is one transaction, so batching amortizes the commit
  and the round trip. Batches are also atomic.
- **Spread load over streams.** Appends to one stream are serialized by its row
  lock. Separate streams append in parallel. Streams per tenant, per entity
  type or per shard key are all fine.
- The database is the bottleneck long before signing. Faster disks, `synchronous_commit`
  settings appropriate to your durability needs, and connection-pool sizing
  matter more than CPU.

## Running your own

```bash
# Engine only, any machine
go run ./cmd/delil-bench -events 100000 -json

# Against a deployment (use a dedicated project: the benchmark writes real events)
DELIL_API_KEY=dlk_… go run ./cmd/delil-bench -url https://delil.internal \
  -events 50000 -concurrency 16 -batch 100 -streams 8
```

HTTP-mode throughput is capped by `DELIL_RATE_LIMIT_RPS` (requests per second
per key). Rate-limited requests are retried with the same idempotency key and
counted in the output. Raise the limit for a benchmark project, or the numbers
will measure the limiter.
