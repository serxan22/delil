// Package jcs implements the JSON Canonicalization Scheme (JCS) defined in
// RFC 8785, together with the strict JSON parser DƏLİL uses for every value
// that is hashed or signed.
//
// Canonicalization turns semantically equal JSON documents into identical
// byte sequences: object members are sorted by the UTF-16 code units of their
// names, strings use minimal escaping, numbers are serialized with the
// ECMAScript Number.prototype.toString algorithm and insignificant whitespace
// is removed.
//
// The parser never "repairs" input. Invalid UTF-8, duplicate member names,
// unpaired surrogate escapes and numbers that overflow binary64 are errors,
// because silently altering data before it is hashed would make the resulting
// hash attest to something the producer never sent. Callers that ingest
// untrusted data can additionally enable Options.SafeNumbers and
// Options.DisallowNUL.
package jcs

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// DefaultMaxDepth is the nesting limit applied when Options.MaxDepth is zero.
// It is a resource safeguard, not part of RFC 8785.
const DefaultMaxDepth = 128

// maxSafeMagnitude is 2^53: every integer with a magnitude up to this value is
// exactly representable as an IEEE-754 binary64 number.
const maxSafeMagnitude = 1 << 53

// maxSafeIntegerLiteral is the decimal form of 2^53.
const maxSafeIntegerLiteral = "9007199254740992"

// Options controls the strictness of parsing.
type Options struct {
	// MaxDepth limits the nesting of arrays and objects. Zero means
	// DefaultMaxDepth.
	MaxDepth int
	// SafeNumbers rejects numbers whose magnitude exceeds 2^53, integer
	// literals that cannot be represented exactly, and non-zero literals that
	// underflow to zero. Values outside this range must be transported as
	// strings. Canonical output produced from input accepted under this option
	// is always accepted again under it.
	SafeNumbers bool
	// DisallowNUL rejects U+0000 inside strings. PostgreSQL text and jsonb
	// cannot store it reliably.
	DisallowNUL bool
}

// Error describes why input was rejected. Offset is the byte offset at which
// the problem was detected.
type Error struct {
	Offset int
	Msg    string
}

func (e *Error) Error() string {
	return fmt.Sprintf("jcs: %s (at byte %d)", e.Msg, e.Offset)
}

// Parse parses data as a single JSON value under the default options and
// returns it as a tree of map[string]any, []any, string, float64, bool and nil.
func Parse(data []byte) (any, error) {
	return ParseWithOptions(data, Options{})
}

// ParseWithOptions parses data as a single JSON value under opts.
func ParseWithOptions(data []byte, opts Options) (any, error) {
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = DefaultMaxDepth
	}
	p := &parser{data: data, opts: opts}
	v, err := p.parseValue()
	if err != nil {
		return nil, err
	}
	p.skipWhitespace()
	if p.pos != len(p.data) {
		return nil, p.errorf("unexpected data after the top-level value")
	}
	return v, nil
}

// Canonicalize parses data under the default options and returns its RFC 8785
// canonical form.
func Canonicalize(data []byte) ([]byte, error) {
	return CanonicalizeWithOptions(data, Options{})
}

// CanonicalizeWithOptions parses data under opts and returns its RFC 8785
// canonical form.
func CanonicalizeWithOptions(data []byte, opts Options) ([]byte, error) {
	v, err := ParseWithOptions(data, opts)
	if err != nil {
		return nil, err
	}
	return Marshal(v)
}

// Marshal returns the RFC 8785 canonical encoding of v.
//
// v may be a tree produced by Parse, or be built from nil, bool, string,
// float64, float32, the integer types (whose magnitude must not exceed 2^53),
// json.Number, json.RawMessage, map[string]any, map[string]string, []any and
// []string. Any other value is first encoded with encoding/json and the result
// is parsed strictly, which supports structs with json tags.
func Marshal(v any) ([]byte, error) {
	return appendValue(make([]byte, 0, 256), v, 0)
}

// FormatNumber serializes f exactly as ECMAScript's Number.prototype.toString
// does, as required by RFC 8785 section 3.2.2.3. NaN and infinities are errors and
// negative zero is serialized as "0".
func FormatNumber(f float64) (string, error) {
	b, err := appendNumber(nil, f)
	return string(b), err
}

// ---------------------------------------------------------------------------
// Parsing

type parser struct {
	data  []byte
	pos   int
	depth int
	opts  Options
}

func (p *parser) errorf(format string, args ...any) error {
	return &Error{Offset: p.pos, Msg: fmt.Sprintf(format, args...)}
}

func (p *parser) errorAt(offset int, format string, args ...any) error {
	return &Error{Offset: offset, Msg: fmt.Sprintf(format, args...)}
}

// peek returns the next byte, or -1 at the end of input.
func (p *parser) peek() int {
	if p.pos >= len(p.data) {
		return -1
	}
	return int(p.data[p.pos])
}

func (p *parser) skipWhitespace() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) parseValue() (any, error) {
	p.skipWhitespace()
	switch c := p.peek(); {
	case c == -1:
		return nil, p.errorf("unexpected end of input")
	case c == '{':
		return p.parseObject()
	case c == '[':
		return p.parseArray()
	case c == '"':
		return p.parseString()
	case c == 't':
		return p.parseLiteral("true", true)
	case c == 'f':
		return p.parseLiteral("false", false)
	case c == 'n':
		return p.parseLiteral("null", nil)
	case c == '-' || (c >= '0' && c <= '9'):
		return p.parseNumber()
	default:
		return nil, p.errorf("unexpected character %q", rune(c))
	}
}

func (p *parser) enter() error {
	p.depth++
	if p.depth > p.opts.MaxDepth {
		return p.errorf("nesting depth exceeds %d", p.opts.MaxDepth)
	}
	return nil
}

func (p *parser) leave() { p.depth-- }

func (p *parser) parseObject() (any, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.leave()
	p.pos++ // '{'
	obj := make(map[string]any)
	p.skipWhitespace()
	if p.peek() == '}' {
		p.pos++
		return obj, nil
	}
	for {
		p.skipWhitespace()
		if p.peek() != '"' {
			return nil, p.errorf("expected a string member name")
		}
		nameOffset := p.pos
		name, err := p.parseString()
		if err != nil {
			return nil, err
		}
		if _, dup := obj[name]; dup {
			return nil, p.errorAt(nameOffset, "duplicate member name %q", name)
		}
		p.skipWhitespace()
		if p.peek() != ':' {
			return nil, p.errorf("expected ':' after member name")
		}
		p.pos++
		value, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		obj[name] = value
		p.skipWhitespace()
		switch p.peek() {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return obj, nil
		default:
			return nil, p.errorf("expected ',' or '}' in object")
		}
	}
}

func (p *parser) parseArray() (any, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.leave()
	p.pos++ // '['
	arr := make([]any, 0)
	p.skipWhitespace()
	if p.peek() == ']' {
		p.pos++
		return arr, nil
	}
	for {
		value, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		arr = append(arr, value)
		p.skipWhitespace()
		switch p.peek() {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return arr, nil
		default:
			return nil, p.errorf("expected ',' or ']' in array")
		}
	}
}

func (p *parser) parseLiteral(word string, value any) (any, error) {
	if len(p.data)-p.pos < len(word) || string(p.data[p.pos:p.pos+len(word)]) != word {
		return nil, p.errorf("invalid literal")
	}
	p.pos += len(word)
	return value, nil
}

func (p *parser) parseString() (string, error) {
	start := p.pos
	p.pos++ // opening quote
	var buf []byte
	chunk := p.pos
	for {
		if p.pos >= len(p.data) {
			return "", p.errorAt(start, "unterminated string")
		}
		c := p.data[p.pos]
		switch {
		case c == '"':
			var s string
			if buf == nil {
				s = string(p.data[chunk:p.pos])
			} else {
				s = string(append(buf, p.data[chunk:p.pos]...))
			}
			p.pos++
			return s, nil
		case c == '\\':
			buf = append(buf, p.data[chunk:p.pos]...)
			escOffset := p.pos
			r, err := p.parseEscape()
			if err != nil {
				return "", err
			}
			if r == 0 && p.opts.DisallowNUL {
				return "", p.errorAt(escOffset, "U+0000 is not allowed in strings")
			}
			buf = utf8.AppendRune(buf, r)
			chunk = p.pos
		case c < 0x20:
			return "", p.errorf("unescaped control character in string")
		case c < utf8.RuneSelf:
			p.pos++
		default:
			r, size := utf8.DecodeRune(p.data[p.pos:])
			if r == utf8.RuneError && size <= 1 {
				return "", p.errorf("invalid UTF-8 in string")
			}
			p.pos += size
		}
	}
}

func (p *parser) parseEscape() (rune, error) {
	p.pos++ // backslash
	if p.pos >= len(p.data) {
		return 0, p.errorf("unterminated escape sequence")
	}
	c := p.data[p.pos]
	p.pos++
	switch c {
	case '"':
		return '"', nil
	case '\\':
		return '\\', nil
	case '/':
		return '/', nil
	case 'b':
		return '\b', nil
	case 'f':
		return '\f', nil
	case 'n':
		return '\n', nil
	case 'r':
		return '\r', nil
	case 't':
		return '\t', nil
	case 'u':
		r1, err := p.parseHex4()
		if err != nil {
			return 0, err
		}
		if !utf16.IsSurrogate(r1) {
			return r1, nil
		}
		if r1 >= 0xDC00 {
			return 0, p.errorf("unpaired low surrogate")
		}
		if p.pos+1 >= len(p.data) || p.data[p.pos] != '\\' || p.data[p.pos+1] != 'u' {
			return 0, p.errorf("unpaired high surrogate")
		}
		p.pos += 2
		r2, err := p.parseHex4()
		if err != nil {
			return 0, err
		}
		if r2 < 0xDC00 || r2 > 0xDFFF {
			return 0, p.errorf("invalid surrogate pair")
		}
		return utf16.DecodeRune(r1, r2), nil
	default:
		return 0, p.errorAt(p.pos-1, "invalid escape character %q", rune(c))
	}
}

func (p *parser) parseHex4() (rune, error) {
	if len(p.data)-p.pos < 4 {
		return 0, p.errorf("truncated \\u escape")
	}
	var r rune
	for i := 0; i < 4; i++ {
		c := p.data[p.pos+i]
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v = c - 'A' + 10
		default:
			return 0, p.errorAt(p.pos+i, "invalid hex digit in \\u escape")
		}
		r = r<<4 | rune(v)
	}
	p.pos += 4
	return r, nil
}

func (p *parser) consumeDigits() int {
	n := 0
	for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
		p.pos++
		n++
	}
	return n
}

func (p *parser) parseNumber() (any, error) {
	start := p.pos
	if p.peek() == '-' {
		p.pos++
	}
	intStart := p.pos
	switch c := p.peek(); {
	case c == '0':
		p.pos++
	case c >= '1' && c <= '9':
		p.consumeDigits()
	default:
		return nil, p.errorf("invalid number")
	}
	intDigits := string(p.data[intStart:p.pos])
	isInteger := true
	if p.peek() == '.' {
		isInteger = false
		p.pos++
		if p.consumeDigits() == 0 {
			return nil, p.errorf("expected digits after decimal point")
		}
	}
	if c := p.peek(); c == 'e' || c == 'E' {
		isInteger = false
		p.pos++
		if c := p.peek(); c == '+' || c == '-' {
			p.pos++
		}
		if p.consumeDigits() == 0 {
			return nil, p.errorf("expected digits in exponent")
		}
	}
	literal := string(p.data[start:p.pos])
	f, err := strconv.ParseFloat(literal, 64)
	if err != nil {
		// The grammar was validated above, so the only possible error is a
		// range error: the value overflows binary64.
		return nil, p.errorAt(start, "number %s is outside the binary64 range", literal)
	}
	if p.opts.SafeNumbers {
		if math.Abs(f) > maxSafeMagnitude {
			return nil, p.errorAt(start, "number %s exceeds 2^53 in magnitude; send large values as strings", literal)
		}
		if isInteger && !integerLiteralIsSafe(intDigits) {
			return nil, p.errorAt(start, "integer %s cannot be represented exactly; send it as a string", literal)
		}
		if f == 0 && mantissaHasNonZeroDigit(literal) {
			return nil, p.errorAt(start, "number %s underflows to zero", literal)
		}
	}
	return f, nil
}

func integerLiteralIsSafe(digits string) bool {
	switch {
	case len(digits) < len(maxSafeIntegerLiteral):
		return true
	case len(digits) > len(maxSafeIntegerLiteral):
		return false
	default:
		return digits <= maxSafeIntegerLiteral
	}
}

func mantissaHasNonZeroDigit(literal string) bool {
	for i := 0; i < len(literal); i++ {
		switch c := literal[i]; {
		case c == 'e' || c == 'E':
			return false
		case c >= '1' && c <= '9':
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Serialization

const hexDigits = "0123456789abcdef"

func appendValue(b []byte, v any, depth int) ([]byte, error) {
	if depth > DefaultMaxDepth {
		return nil, fmt.Errorf("jcs: nesting depth exceeds %d", DefaultMaxDepth)
	}
	switch x := v.(type) {
	case nil:
		return append(b, "null"...), nil
	case bool:
		if x {
			return append(b, "true"...), nil
		}
		return append(b, "false"...), nil
	case string:
		if !utf8.ValidString(x) {
			return nil, fmt.Errorf("jcs: string contains invalid UTF-8")
		}
		return appendString(b, x), nil
	case float64:
		return appendNumber(b, x)
	case float32:
		return appendNumber(b, float64(x))
	case int:
		return appendInteger(b, int64(x))
	case int8:
		return appendInteger(b, int64(x))
	case int16:
		return appendInteger(b, int64(x))
	case int32:
		return appendInteger(b, int64(x))
	case int64:
		return appendInteger(b, x)
	case uint:
		return appendUnsigned(b, uint64(x))
	case uint8:
		return appendUnsigned(b, uint64(x))
	case uint16:
		return appendUnsigned(b, uint64(x))
	case uint32:
		return appendUnsigned(b, uint64(x))
	case uint64:
		return appendUnsigned(b, x)
	case json.Number:
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil {
			return nil, fmt.Errorf("jcs: invalid number %q", string(x))
		}
		return appendNumber(b, f)
	case json.RawMessage:
		parsed, err := Parse(x)
		if err != nil {
			return nil, err
		}
		return appendValue(b, parsed, depth)
	case map[string]any:
		return appendObject(b, x, depth)
	case map[string]string:
		m := make(map[string]any, len(x))
		for k, s := range x {
			m[k] = s
		}
		return appendObject(b, m, depth)
	case []any:
		b = append(b, '[')
		for i, elem := range x {
			if i > 0 {
				b = append(b, ',')
			}
			var err error
			if b, err = appendValue(b, elem, depth+1); err != nil {
				return nil, err
			}
		}
		return append(b, ']'), nil
	case []string:
		b = append(b, '[')
		for i, s := range x {
			if i > 0 {
				b = append(b, ',')
			}
			if !utf8.ValidString(s) {
				return nil, fmt.Errorf("jcs: string contains invalid UTF-8")
			}
			b = appendString(b, s)
		}
		return append(b, ']'), nil
	default:
		raw, err := json.Marshal(x)
		if err != nil {
			return nil, fmt.Errorf("jcs: cannot encode %T: %w", v, err)
		}
		parsed, err := Parse(raw)
		if err != nil {
			return nil, err
		}
		return appendValue(b, parsed, depth)
	}
}

func appendObject(b []byte, m map[string]any, depth int) ([]byte, error) {
	type member struct {
		name  string
		units []uint16
	}
	members := make([]member, 0, len(m))
	for name := range m {
		if !utf8.ValidString(name) {
			return nil, fmt.Errorf("jcs: member name contains invalid UTF-8")
		}
		members = append(members, member{name: name, units: utf16.Encode([]rune(name))})
	}
	sort.Slice(members, func(i, j int) bool {
		return lessUTF16(members[i].units, members[j].units)
	})
	b = append(b, '{')
	for i, mem := range members {
		if i > 0 {
			b = append(b, ',')
		}
		b = appendString(b, mem.name)
		b = append(b, ':')
		var err error
		if b, err = appendValue(b, m[mem.name], depth+1); err != nil {
			return nil, err
		}
	}
	return append(b, '}'), nil
}

// lessUTF16 orders strings by their UTF-16 code units, as RFC 8785 section
// 3.2.3 requires. This differs from code point order for characters outside
// the Basic Multilingual Plane.
func lessUTF16(a, b []uint16) bool {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// appendString applies the escaping rules of RFC 8785 section 3.2.2.2: only
// '"', '\\' and control characters are escaped; the short forms \b \f \n \r \t
// are used where they exist and everything else below U+0020 is written as a
// lowercase \u00xx escape. All other characters are emitted verbatim.
func appendString(b []byte, s string) []byte {
	b = append(b, '"')
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c != '"' && c != '\\' {
			continue
		}
		b = append(b, s[start:i]...)
		switch c {
		case '"':
			b = append(b, '\\', '"')
		case '\\':
			b = append(b, '\\', '\\')
		case '\b':
			b = append(b, '\\', 'b')
		case '\f':
			b = append(b, '\\', 'f')
		case '\n':
			b = append(b, '\\', 'n')
		case '\r':
			b = append(b, '\\', 'r')
		case '\t':
			b = append(b, '\\', 't')
		default:
			b = append(b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xF])
		}
		start = i + 1
	}
	b = append(b, s[start:]...)
	return append(b, '"')
}

// appendNumber implements the ECMAScript Number::toString algorithm for
// binary64 values. Go's shortest round-trip formatting produces the same
// digits; only the choice between fixed and exponential notation and the
// exponent format need adjusting.
func appendNumber(b []byte, f float64) ([]byte, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return nil, fmt.Errorf("jcs: NaN and Infinity cannot be represented in JSON")
	}
	if f == 0 {
		// Covers negative zero, which RFC 8785 serializes as "0".
		return append(b, '0'), nil
	}
	format := byte('f')
	if abs := math.Abs(f); abs < 1e-6 || abs >= 1e21 {
		format = 'e'
	}
	start := len(b)
	b = strconv.AppendFloat(b, f, format, -1, 64)
	if format == 'e' {
		// Go writes a two-digit exponent ("1e-07"); ECMAScript does not.
		n := len(b)
		if n-start >= 4 && b[n-4] == 'e' && b[n-3] == '-' && b[n-2] == '0' {
			b[n-2] = b[n-1]
			b = b[:n-1]
		}
	}
	return b, nil
}

func appendInteger(b []byte, i int64) ([]byte, error) {
	if i > maxSafeMagnitude || i < -maxSafeMagnitude {
		return nil, fmt.Errorf("jcs: integer %d exceeds 2^53 in magnitude and cannot be represented exactly", i)
	}
	return strconv.AppendInt(b, i, 10), nil
}

func appendUnsigned(b []byte, u uint64) ([]byte, error) {
	if u > maxSafeMagnitude {
		return nil, fmt.Errorf("jcs: integer %d exceeds 2^53 and cannot be represented exactly", u)
	}
	return strconv.AppendUint(b, u, 10), nil
}
