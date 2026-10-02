package audit

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// defaultDenyKeys are redacted unless a project disables defaults. Keys are
// compared after normalizeKey (lowercase, alphanumerics only).
var defaultDenyKeys = []string{
	"password", "passwd", "pwd", "passphrase", "secret", "clientsecret", "token", "accesstoken",
	"refreshtoken", "idtoken", "sessiontoken", "csrftoken", "apikey", "xapikey", "authorization",
	"proxyauthorization", "cookie", "setcookie", "privatekey", "creditcard", "creditcardnumber",
	"cardnumber", "cvv", "cvc", "ssn", "otp", "mfacode", "totp", "pin",
}

// defaultDenySuffixes catch compound names such as "newPassword",
// "githubToken" or "stripe_api_key" without matching "secretary".
var defaultDenySuffixes = []string{"password", "passwd", "secret", "token", "apikey", "privatekey"}

func normalizeKey(k string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(k) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Redactor applies a project's redaction settings to content trees.
type Redactor struct {
	keys     map[string]bool
	suffixes []string
	paths    map[string]bool
	mode     string
}

// NewRedactor builds a redactor from settings.
func NewRedactor(s RedactionSettings) *Redactor {
	r := &Redactor{keys: map[string]bool{}, paths: map[string]bool{}, mode: s.Mode}
	if r.mode == "" {
		r.mode = RedactReplace
	}
	if !s.DisableDefaults {
		for _, k := range defaultDenyKeys {
			r.keys[k] = true
		}
		r.suffixes = defaultDenySuffixes
	}
	for _, k := range s.Keys {
		r.keys[normalizeKey(k)] = true
	}
	for _, p := range s.Paths {
		r.paths[p] = true
	}
	return r
}

func (r *Redactor) sensitive(key string) bool {
	n := normalizeKey(key)
	if n == "" {
		return false
	}
	if r.keys[n] {
		return true
	}
	for _, suf := range r.suffixes {
		if strings.HasSuffix(n, suf) {
			return true
		}
	}
	return false
}

// Apply redacts value in place (maps are modified) and returns the possibly
// replaced value together with the JSON Pointers that were redacted. path is
// the pointer of value inside the event content, e.g. "/after".
func (r *Redactor) Apply(path string, value any) (any, []string) {
	var redacted []string
	out := r.walk(path, value, &redacted)
	sort.Strings(redacted)
	return out, redacted
}

func (r *Redactor) walk(path string, value any, redacted *[]string) any {
	if r.paths[path] {
		*redacted = append(*redacted, path)
		return r.replacement(value)
	}
	switch v := value.(type) {
	case map[string]any:
		for _, k := range sortedKeys(v) {
			child := path + "/" + escapePointer(k)
			if r.sensitive(k) || r.paths[child] {
				*redacted = append(*redacted, child)
				if r.mode == RedactRemove {
					delete(v, k)
				} else {
					v[k] = r.replacement(v[k])
				}
				continue
			}
			v[k] = r.walk(child, v[k], redacted)
		}
		return v
	case []any:
		for i := range v {
			v[i] = r.walk(path+"/"+itoa(i), v[i], redacted)
		}
		return v
	default:
		return v
	}
}

func (r *Redactor) replacement(value any) any {
	if r.mode == RedactMask {
		if s, ok := value.(string); ok {
			return mask(s)
		}
	}
	return RedactedValue
}

// mask keeps the last four characters of strings longer than eight
// characters and replaces everything else with asterisks.
func mask(s string) string {
	n := utf8.RuneCountInString(s)
	if n <= 8 {
		return strings.Repeat("*", n)
	}
	runes := []rune(s)
	return strings.Repeat("*", n-4) + string(runes[n-4:])
}

func escapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}

// RedactChange redacts the values of one diff entry. A change is sensitive
// when any member name along its path is sensitive or when a configured path
// covers it; then both values are replaced (never removed, so the diff still
// shows that the member changed). Otherwise nested values are walked like
// before/after. It returns the logical content paths that were redacted.
func (r *Redactor) RedactChange(c *Change) []string {
	before, after := "/before"+c.Path, "/after"+c.Path
	sensitive := r.coveredByPath(before) || r.coveredByPath(after)
	for _, seg := range splitPointer(c.Path) {
		if r.sensitive(seg) {
			sensitive = true
			break
		}
	}
	var redacted []string
	if sensitive {
		replace := func(v any) any {
			if r.mode == RedactMask {
				if s, ok := v.(string); ok {
					return mask(s)
				}
			}
			return RedactedValue
		}
		if c.Op != OpAdd {
			c.From = replace(c.From)
			redacted = append(redacted, before)
		}
		if c.Op != OpRemove {
			c.To = replace(c.To)
			redacted = append(redacted, after)
		}
		return redacted
	}
	if c.Op != OpAdd {
		var paths []string
		c.From, paths = r.Apply(before, c.From)
		redacted = append(redacted, paths...)
	}
	if c.Op != OpRemove {
		var paths []string
		c.To, paths = r.Apply(after, c.To)
		redacted = append(redacted, paths...)
	}
	return redacted
}

// coveredByPath reports whether p or one of its ancestors is a configured path.
func (r *Redactor) coveredByPath(p string) bool {
	for {
		if r.paths[p] {
			return true
		}
		i := strings.LastIndexByte(p, '/')
		if i <= 0 {
			return false
		}
		p = p[:i]
	}
}

func splitPointer(p string) []string {
	if p == "" {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for i, s := range parts {
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(s, "~1", "/"), "~0", "~")
	}
	return parts
}

// DeepCopy copies a JSON tree.
func DeepCopy(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, val := range x {
			m[k] = DeepCopy(val)
		}
		return m
	case []any:
		s := make([]any, len(x))
		for i, val := range x {
			s[i] = DeepCopy(val)
		}
		return s
	default:
		return x
	}
}
