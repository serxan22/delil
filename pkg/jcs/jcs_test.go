package jcs

import (
	"bufio"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
)

// esc expands "~uXXXX" into the JSON escape sequence backslash-u-XXXX.
// Test inputs are written this way so that the exact escapes under test stay
// visible in the source instead of being rendered as the characters they
// denote by editors and review tools.
func esc(s string) string { return strings.ReplaceAll(s, "~u", "\\u") }

// RFC 8785 Appendix B.
func TestFormatNumberRFC8785AppendixB(t *testing.T) {
	cases := []struct {
		bits string
		want string
	}{
		{"0000000000000000", "0"},
		{"8000000000000000", "0"},
		{"0000000000000001", "5e-324"},
		{"8000000000000001", "-5e-324"},
		{"7fefffffffffffff", "1.7976931348623157e+308"},
		{"ffefffffffffffff", "-1.7976931348623157e+308"},
		{"4340000000000000", "9007199254740992"},
		{"c340000000000000", "-9007199254740992"},
		{"4430000000000000", "295147905179352830000"},
		{"44b52d02c7e14af5", "9.999999999999997e+22"},
		{"44b52d02c7e14af6", "1e+23"},
		{"44b52d02c7e14af7", "1.0000000000000001e+23"},
		{"444b1ae4d6e2ef4e", "999999999999999700000"},
		{"444b1ae4d6e2ef4f", "999999999999999900000"},
		{"444b1ae4d6e2ef50", "1e+21"},
		{"3eb0c6f7a0b5ed8c", "9.999999999999997e-7"},
		{"3eb0c6f7a0b5ed8d", "0.000001"},
		{"41b3de4355555553", "333333333.3333332"},
		{"41b3de4355555554", "333333333.33333325"},
		{"41b3de4355555555", "333333333.3333333"},
		{"41b3de4355555556", "333333333.3333334"},
		{"41b3de4355555557", "333333333.33333343"},
		{"becbf647612f3696", "-0.0000033333333333333333"},
		{"43143ff3c1cb0959", "1424953923781206.2"},
	}
	for _, tc := range cases {
		got, err := FormatNumber(fromBits(t, tc.bits))
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.bits, err)
		}
		if got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.bits, got, tc.want)
		}
	}
	for _, bits := range []string{"7fffffffffffffff", "7ff0000000000000", "fff0000000000000"} {
		if _, err := FormatNumber(fromBits(t, bits)); err == nil {
			t.Errorf("%s: expected an error for NaN/Infinity", bits)
		}
	}
}

// numbers.txt is produced by V8 (see gen-numbers.mjs); FormatNumber must
// agree with it exactly.
func TestFormatNumberMatchesV8Corpus(t *testing.T) {
	f, err := os.Open("testdata/numbers.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	n := 0
	for scanner.Scan() {
		bits, want, ok := strings.Cut(scanner.Text(), " ")
		if !ok {
			t.Fatalf("malformed corpus line %q", scanner.Text())
		}
		got, err := FormatNumber(fromBits(t, bits))
		if err != nil {
			t.Fatalf("%s: %v", bits, err)
		}
		if got != want {
			t.Errorf("%s: got %s, want %s (V8)", bits, got, want)
		}
		n++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if n < 5000 {
		t.Fatalf("corpus unexpectedly small: %d lines", n)
	}
}

// RFC 8785 section 3.2.2 (sample canonicalization).
func TestCanonicalizeRFC8785Example(t *testing.T) {
	input := esc(`{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "~u20ac$~u000F~u000aA'~u0042~u0022~u005c\\\"\/",
  "literals": [null, true, false]
}`)
	want := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"` +
		"\xe2\x82\xac$" + esc(`~u000f\nA'B\"\\\\\"/"}`)
	got, err := Canonicalize([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// RFC 8785 section 3.2.3: members are sorted by UTF-16 code units, which puts
// U+1F600 (D83D DE00) before U+FB33 even though its code point is larger.
func TestCanonicalizeSortsByUTF16CodeUnits(t *testing.T) {
	input := esc(`{
  "~u20ac": "Euro Sign",
  "\r": "Carriage Return",
  "~ufb33": "Hebrew Letter Dalet With Dagesh",
  "1": "One",
  "~ud83d~ude00": "Emoji: Grinning Face",
  "~u0080": "Control",
  "~u00f6": "Latin Small Letter O With Diaeresis"
}`)
	got, err := Canonicalize([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	order := []string{
		"Carriage Return", "One", "Control", "Latin Small Letter O With Diaeresis",
		"Euro Sign", "Emoji: Grinning Face", "Hebrew Letter Dalet With Dagesh",
	}
	last := -1
	for _, v := range order {
		idx := strings.Index(string(got), v)
		if idx < 0 || idx < last {
			t.Fatalf("member %q out of order in %s", v, got)
		}
		last = idx
	}
}

func TestCanonicalizeStringEscaping(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"DEL is not escaped", esc(`"~u007f"`), "\"\x7f\""},
		{"line separators are not escaped", esc(`"~u2028~u2029"`), "\"\xe2\x80\xa8\xe2\x80\xa9\""},
		{"other controls use lowercase hex", esc(`"~u001F"`), esc(`"~u001f"`)},
		{"short escapes", `"\b\f\n\r\t"`, `"\b\f\n\r\t"`},
		{"solidus is not escaped", `"\/"`, `"/"`},
		{"ASCII escape is decoded", esc(`"a~u0041"`), `"aA"`},
		{"surrogate pair becomes UTF-8", esc(`"~ud83d~ude00"`), "\"\xf0\x9f\x98\x80\""},
		{"Azerbaijani letters stay verbatim", "\"D\xc9\x99lil \xc4\xb0\"", "\"D\xc9\x99lil \xc4\xb0\""},
		{"quote and backslash", `"quote\"back\\"`, `"quote\"back\\"`},
		{"Latin-1 escape is decoded", esc(`"~u00e9"`), "\"\xc3\xa9\""},
		{"NUL stays escaped", esc(`"~u0000"`), esc(`"~u0000"`)},
	}
	for _, tc := range cases {
		got, err := Canonicalize([]byte(tc.in))
		if err != nil {
			t.Errorf("%s: unexpected error %v", tc.name, err)
			continue
		}
		if string(got) != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
	if _, err := Canonicalize([]byte("\"tab\tinside\"")); err == nil {
		t.Error("an unescaped control character must be rejected")
	}
}

func TestCanonicalizeRejectsInvalidInput(t *testing.T) {
	cases := map[string]string{
		"duplicate member":        `{"a":1,"a":2}`,
		"duplicate after escape":  esc(`{"a":1,"~u0061":2}`),
		"invalid utf8":            "\"\xff\"",
		"overlong utf8":           "\"\xc0\xaf\"",
		"utf8 surrogate":          "\"\xed\xa0\x80\"",
		"lone high surrogate":     esc(`"~ud800"`),
		"lone low surrogate":      esc(`"~udc00"`),
		"high then non-low":       esc(`"~ud800~u0041"`),
		"high at end":             esc(`"~ud800`),
		"truncated escape":        esc(`"~u12"`),
		"bad hex in escape":       esc(`"~u12g4"`),
		"bad escape":              `"\x"`,
		"leading zero":            `01`,
		"trailing dot":            `1.`,
		"leading dot":             `.5`,
		"plus sign":               `+1`,
		"empty exponent":          `1e`,
		"bare minus":              `-`,
		"nan":                     `NaN`,
		"infinity":                `Infinity`,
		"overflow":                `1e400`,
		"trailing data":           `{} {}`,
		"trailing comma array":    `[1,]`,
		"trailing comma object":   `{"a":1,}`,
		"single quotes":           `{'a':1}`,
		"unquoted key":            `{a:1}`,
		"comment":                 `{"a":1 /* x */}`,
		"empty input":             ``,
		"whitespace only":         `   `,
		"unterminated string":     `"abc`,
		"unterminated object":     `{"a":1`,
		"literal typo":            `tru`,
		"vertical tab whitespace": "\v1",
	}
	for name, in := range cases {
		out, err := Canonicalize([]byte(in))
		if err == nil {
			t.Errorf("%s: expected error for %q, got %s", name, in, out)
			continue
		}
		var jerr *Error
		if !errors.As(err, &jerr) {
			t.Errorf("%s: error %v is not a *jcs.Error", name, err)
		}
	}
}

func TestMaxDepth(t *testing.T) {
	deep := strings.Repeat("[", 10) + strings.Repeat("]", 10)
	if _, err := ParseWithOptions([]byte(deep), Options{MaxDepth: 10}); err != nil {
		t.Fatalf("depth 10 should be accepted: %v", err)
	}
	if _, err := ParseWithOptions([]byte("["+deep+"]"), Options{MaxDepth: 10}); err == nil {
		t.Fatal("depth 11 should be rejected")
	}
	huge := strings.Repeat("[", 100000) + strings.Repeat("]", 100000)
	if _, err := Parse([]byte(huge)); err == nil {
		t.Fatal("pathological nesting must be rejected, not overflow the stack")
	}
}

func TestSafeNumbers(t *testing.T) {
	strict := Options{SafeNumbers: true}
	accept := []string{"0", "-0", "0.0", "0e10", "9007199254740992", "-9007199254740992",
		"9007199254740991", "1.5", "1e-300", "5e-324", "123.456e3", "1e15"}
	reject := []string{"9007199254740993", "-9007199254740993", "12345678901234567890",
		"1e16", "1e400", "1e-400", "-2.5e-500"}
	for _, in := range accept {
		if _, err := ParseWithOptions([]byte(in), strict); err != nil {
			t.Errorf("%s: should be accepted: %v", in, err)
		}
	}
	for _, in := range reject {
		if _, err := ParseWithOptions([]byte(in), strict); err == nil {
			t.Errorf("%s: should be rejected under SafeNumbers", in)
		}
	}
	// Without SafeNumbers, large magnitudes are legal RFC 8785 input.
	if out, err := Canonicalize([]byte("1e30")); err != nil || string(out) != "1e+30" {
		t.Fatalf("default options: got %s, %v", out, err)
	}
}

func TestDisallowNUL(t *testing.T) {
	opts := Options{DisallowNUL: true}
	if _, err := ParseWithOptions([]byte(esc(`"a~u0000b"`)), opts); err == nil {
		t.Fatal("U+0000 must be rejected when DisallowNUL is set")
	}
	if _, err := ParseWithOptions([]byte(esc(`{"~u0000":1}`)), opts); err == nil {
		t.Fatal("U+0000 in member names must be rejected when DisallowNUL is set")
	}
}

func TestCanonicalizeIsIdempotent(t *testing.T) {
	samples := []string{
		`{"b":[1,2.5,{"z":null,"a":true}],"a":"x","c":{"y":-0,"x":1e-7}}`,
		esc(`[1e21, 1e-7, 0.1, 100, "~u00e9", {"~ud83d~ude00": [], "~uffff": {}}]`),
		`{"nested":{"deeper":{"deepest":[[[["ok"]]]]}}}`,
		`"plain"`, `true`, `null`, `-1.5e-10`,
	}
	for _, s := range samples {
		once, err := Canonicalize([]byte(s))
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		twice, err := Canonicalize(once)
		if err != nil {
			t.Fatalf("re-canonicalizing %s: %v", once, err)
		}
		if string(once) != string(twice) {
			t.Fatalf("not idempotent:\n%s\n%s", once, twice)
		}
	}
}

func TestMarshalGoValues(t *testing.T) {
	type nested struct {
		Z string `json:"z"`
		A int    `json:"a"`
	}
	v := map[string]any{
		"int":    42,
		"int64":  int64(-7),
		"uint":   uint32(9),
		"float":  0.5,
		"number": json.Number("1.50"),
		"raw":    json.RawMessage(`{"b":2,"a":1}`),
		"strs":   []string{"x", "y"},
		"smap":   map[string]string{"k": "v"},
		"struct": nested{Z: "last", A: 1},
		"html":   "<a&b>",
		"nil":    nil,
	}
	got, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"float":0.5,"html":"<a&b>","int":42,"int64":-7,"nil":null,"number":1.5,"raw":{"a":1,"b":2},"smap":{"k":"v"},"strs":["x","y"],"struct":{"a":1,"z":"last"},"uint":9}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if _, err := Marshal(int64(1 << 54)); err == nil {
		t.Fatal("integers above 2^53 must be rejected")
	}
	if _, err := Marshal(uint64(math.MaxUint64)); err == nil {
		t.Fatal("integers above 2^53 must be rejected")
	}
	if _, err := Marshal(math.NaN()); err == nil {
		t.Fatal("NaN must be rejected")
	}
	if _, err := Marshal("\xff"); err == nil {
		t.Fatal("invalid UTF-8 must be rejected")
	}
}

func FuzzCanonicalize(f *testing.F) {
	seeds := []string{
		`{"a":1}`, `[1,2,3]`, `"x"`, `1e21`, `-0`, esc(`{"~ud83d~ude00":"~u20ac"}`),
		`{"z":{"y":[true,false,null]}}`, `0.000001`, `123456789012345678`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		once, err := Canonicalize(data)
		if err != nil {
			return
		}
		twice, err := Canonicalize(once)
		if err != nil {
			t.Fatalf("canonical output %q failed to parse: %v", once, err)
		}
		if string(once) != string(twice) {
			t.Fatalf("not idempotent: %q vs %q", once, twice)
		}
		// Canonical output must be valid JSON for other parsers too.
		if !json.Valid(once) {
			t.Fatalf("canonical output is not valid JSON: %q", once)
		}
		// SafeNumbers output must be accepted again under SafeNumbers.
		if strict, err := CanonicalizeWithOptions(data, Options{SafeNumbers: true}); err == nil {
			if _, err := CanonicalizeWithOptions(strict, Options{SafeNumbers: true}); err != nil {
				t.Fatalf("strict canonical output %q rejected under strict options: %v", strict, err)
			}
		}
	})
}

func fromBits(t *testing.T, hexBits string) float64 {
	t.Helper()
	u, err := strconv.ParseUint(hexBits, 16, 64)
	if err != nil {
		t.Fatalf("bad bits %q: %v", hexBits, err)
	}
	return math.Float64frombits(u)
}
