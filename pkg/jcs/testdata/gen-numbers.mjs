// Regenerates numbers.txt, the conformance corpus for jcs.FormatNumber.
//
// RFC 8785 specifies number serialization by reference to ECMAScript's
// Number.prototype.toString, so the expected strings are produced by V8's
// JSON.stringify. The PRNG is seeded, so the output is reproducible:
//
//   node pkg/jcs/testdata/gen-numbers.mjs > pkg/jcs/testdata/numbers.txt
//
// Each line is "<IEEE-754 bits as 16 hex digits> <expected serialization>".

const view = new DataView(new ArrayBuffer(8));
const seen = new Set();
const lines = [];

function add(f) {
  if (!Number.isFinite(f)) return;
  view.setFloat64(0, f);
  const bits =
    view.getUint32(0).toString(16).padStart(8, "0") +
    view.getUint32(4).toString(16).padStart(8, "0");
  if (seen.has(bits)) return;
  seen.add(bits);
  lines.push(`${bits} ${JSON.stringify(f)}`);
}

function fromBits(hi, lo) {
  view.setUint32(0, hi >>> 0);
  view.setUint32(4, lo >>> 0);
  return view.getFloat64(0);
}

// mulberry32: small, deterministic PRNG (not for cryptographic use).
let state = 0x8785;
function rand32() {
  state = (state + 0x6d2b79f5) >>> 0;
  let t = state;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return (t ^ (t >>> 14)) >>> 0;
}
const rand = () => rand32() / 4294967296;

function neighbours(f) {
  view.setFloat64(0, f);
  const hi = view.getUint32(0);
  const lo = view.getUint32(4);
  add(fromBits(hi, lo + 1 > 0xffffffff ? 0 : lo + 1));
  add(fromBits(hi, lo === 0 ? 0 : lo - 1));
}

// 1. Uniformly random bit patterns (finite values only).
for (let i = 0; i < 2500; i++) add(fromBits(rand32(), rand32()));

// 2. Decimal-looking values of the kind applications actually send.
for (let i = 0; i < 1500; i++) {
  const digits = Math.floor(rand() * 16) + 1;
  const scale = Math.floor(rand() * 12);
  const mantissa = Math.floor(rand() * 10 ** digits);
  const sign = rand() < 0.3 ? -1 : 1;
  add((sign * mantissa) / 10 ** scale);
}

// 3. Powers of ten and their binary neighbours, across the exponent range.
for (let e = -324; e <= 308; e++) {
  const f = Number(`1e${e}`);
  add(f);
  add(-f);
  neighbours(f);
}

// 4. Thresholds where ECMAScript switches notation, and integer limits.
for (const f of [1e-6, 1e-7, 9.999999999999999e-7, 1e21, 9.99999999999999e20,
  2 ** 53, 2 ** 53 - 1, -(2 ** 53), 2 ** 52 + 0.5, Number.MIN_VALUE,
  Number.MAX_VALUE, Number.EPSILON, 0.1, 0.2, 0.30000000000000004, 1 / 3,
  2 / 3, 123456789.123456789, 4.35, 0.000001, 0.0000001]) {
  add(f);
  add(-f);
  neighbours(f);
}
for (let i = 0; i < 200; i++) add(2 ** 53 - i);

process.stdout.write(lines.join("\n") + "\n");
