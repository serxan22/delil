// Package id generates prefixed, sortable identifiers such as
// "evt_01J9ZQ4M3F5X8B7K2N6R0T1V3W": a short type prefix and a ULID (48-bit
// millisecond timestamp, 80 bits from crypto/rand, Crockford base32).
//
// Identifiers are not secrets and carry no integrity meaning; event order is
// defined by stream sequence numbers, never by identifier order.
package id

import (
	"crypto/rand"
	"encoding/binary"
	"regexp"
	"time"
)

// Prefixes used across DƏLİL.
const (
	Tenant       = "org"
	Project      = "prj"
	Stream       = "str"
	Event        = "evt"
	APIKey       = "key"
	User         = "usr"
	Session      = "ses"
	Verification = "vrf"
	Export       = "exp"
	Checkpoint   = "chk"
	Anchor       = "anc"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var pattern = regexp.MustCompile(`^[a-z]{3}_[0-9A-HJKMNP-TV-Z]{26}$`)

// New returns a new identifier with the given prefix.
func New(prefix string) string {
	return prefix + "_" + ulid(time.Now())
}

// Valid reports whether s is a well-formed identifier with the given prefix.
func Valid(prefix, s string) bool {
	return len(s) == len(prefix)+27 && s[:len(prefix)] == prefix && pattern.MatchString(s)
}

func ulid(t time.Time) string {
	var b [16]byte
	var ts [8]byte
	ms := t.UnixMilli()
	if ms < 0 {
		ms = 0
	}
	binary.BigEndian.PutUint64(ts[:], uint64(ms)) //nolint:gosec // ms is non-negative
	copy(b[0:6], ts[2:8])                         // the low 48 bits
	if _, err := rand.Read(b[6:]); err != nil {
		panic("id: crypto/rand failed: " + err.Error())
	}
	// 128 bits -> 26 base32 characters (the first carries only 3 bits).
	var out [26]byte
	hi := binary.BigEndian.Uint64(b[0:8])
	lo := binary.BigEndian.Uint64(b[8:16])
	for i := 25; i >= 0; i-- {
		out[i] = crockford[lo&31]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(out[:])
}
