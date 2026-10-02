// Package auth implements credentials: project API keys, dashboard passwords
// and session tokens, scopes and roles, and rate limiting.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Scopes grant access to API operations.
const (
	ScopeEventsWrite   = "events:write"
	ScopeEventsRead    = "events:read"
	ScopeVerify        = "verify"
	ScopeExports       = "exports"
	ScopeKeysRead      = "keys:read"
	ScopeKeysRotate    = "keys:rotate"
	ScopeAPIKeysManage = "api_keys:manage"
	ScopeProjectManage = "project:manage"
	ScopeTenantManage  = "tenant:manage"
)

// APIKeyScopes are the scopes an API key may hold.
var APIKeyScopes = []string{ScopeEventsWrite, ScopeEventsRead, ScopeVerify, ScopeExports, ScopeKeysRead,
	ScopeKeysRotate, ScopeAPIKeysManage}

// Roles of dashboard users.
const (
	RoleAdmin   = "admin"
	RoleAuditor = "auditor"
	RoleViewer  = "viewer"
)

// RoleScopes maps dashboard roles to scopes. Dashboard sessions never write
// events: events come from applications.
var RoleScopes = map[string][]string{
	RoleAdmin: {ScopeEventsRead, ScopeVerify, ScopeExports, ScopeKeysRead, ScopeKeysRotate, ScopeAPIKeysManage,
		ScopeProjectManage, ScopeTenantManage},
	RoleAuditor: {ScopeEventsRead, ScopeVerify, ScopeExports, ScopeKeysRead},
	RoleViewer:  {ScopeEventsRead, ScopeKeysRead},
}

// ValidRole reports whether role exists.
func ValidRole(role string) bool { _, ok := RoleScopes[role]; return ok }

// NormalizeScopes validates and sorts API key scopes.
func NormalizeScopes(scopes []string) ([]string, error) {
	allowed := map[string]bool{}
	for _, s := range APIKeyScopes {
		allowed[s] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if !allowed[s] {
			return nil, fmt.Errorf("unknown scope %q (valid: %s)", s, strings.Join(APIKeyScopes, ", "))
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one scope is required")
	}
	sort.Strings(out)
	return out, nil
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("auth: crypto/rand failed: " + err.Error())
	}
	return strings.ToLower(b32.EncodeToString(b))
}

// API keys look like dlk_<16 lowercase base32>_<52 lowercase base32>. The
// first part is a public lookup identifier; the second carries 256 bits of
// entropy. The prefix makes leaked keys easy to recognise for secret
// scanners.
const APIKeyPrefix = "dlk_"

var apiKeyPattern = regexp.MustCompile(`^dlk_([a-z2-7]{16})_([a-z2-7]{52})$`)

// NewAPIKey returns a new raw key, its lookup id and the hash to store.
func NewAPIKey() (raw, lookupID string, hash [32]byte) {
	lookupID = randomToken(10)
	secret := randomToken(32)
	raw = APIKeyPrefix + lookupID + "_" + secret
	return raw, lookupID, HashToken(raw)
}

// ParseAPIKey extracts the lookup id from a raw key.
func ParseAPIKey(raw string) (lookupID string, ok bool) {
	m := apiKeyPattern.FindStringSubmatch(raw)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// DisplayPrefix is a non-secret label for a key ("dlk_abcd2345...").
func DisplayPrefix(lookupID string) string { return APIKeyPrefix + lookupID }

// HashToken hashes an API key or session token for storage. Tokens carry 256
// bits of entropy, so a fast hash is appropriate (no brute-force risk).
func HashToken(raw string) [32]byte { return sha256.Sum256([]byte(raw)) }

// EqualHash compares two hashes in constant time.
func EqualHash(a []byte, b [32]byte) bool { return subtle.ConstantTimeCompare(a, b[:]) == 1 }

// SessionPrefix marks dashboard session tokens.
const SessionPrefix = "dls_"

var sessionPattern = regexp.MustCompile(`^dls_[a-z2-7]{52}$`)

// NewSessionToken returns a new session token and its hash.
func NewSessionToken() (string, [32]byte) {
	raw := SessionPrefix + randomToken(32)
	return raw, HashToken(raw)
}

// ValidSessionToken reports whether raw has the session token format.
func ValidSessionToken(raw string) bool { return sessionPattern.MatchString(raw) }

// GeneratePassword returns a random password for bootstrap accounts.
func GeneratePassword() string {
	return randomToken(15)
}
