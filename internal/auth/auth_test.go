package auth

import (
	"strings"
	"testing"
	"time"
)

func TestAPIKeys(t *testing.T) {
	raw, lookup, hash := NewAPIKey()
	if !strings.HasPrefix(raw, "dlk_") || len(raw) != 4+16+1+52 {
		t.Fatalf("unexpected key format %q", raw)
	}
	got, ok := ParseAPIKey(raw)
	if !ok || got != lookup {
		t.Fatalf("parse: %q %v", got, ok)
	}
	if !EqualHash(hash[:], HashToken(raw)) {
		t.Fatal("hash mismatch")
	}
	other, _, _ := NewAPIKey()
	if EqualHash(hash[:], HashToken(other)) {
		t.Fatal("different keys must hash differently")
	}
	for _, bad := range []string{"", "dlk_", raw + "x", strings.ToUpper(raw), "dls_" + raw[4:], raw[:20]} {
		if _, ok := ParseAPIKey(bad); ok {
			t.Errorf("ParseAPIKey(%q) should fail", bad)
		}
	}
}

func TestSessionTokens(t *testing.T) {
	tok, hash := NewSessionToken()
	if !ValidSessionToken(tok) || HashToken(tok) != hash {
		t.Fatalf("token %q", tok)
	}
	if ValidSessionToken("dls_short") {
		t.Fatal("short tokens are invalid")
	}
}

func TestScopes(t *testing.T) {
	got, err := NormalizeScopes([]string{"verify", "events:write", "verify"})
	if err != nil || strings.Join(got, ",") != "events:write,verify" {
		t.Fatalf("normalize: %v %v", got, err)
	}
	if _, err := NormalizeScopes([]string{"events:*"}); err == nil {
		t.Fatal("wildcards are not scopes")
	}
	if _, err := NormalizeScopes(nil); err == nil {
		t.Fatal("empty scope sets are rejected")
	}
	if _, err := NormalizeScopes([]string{ScopeTenantManage}); err == nil {
		t.Fatal("tenant management is not an API key scope")
	}
	for role, scopes := range RoleScopes {
		for _, s := range scopes {
			if s == ScopeEventsWrite {
				t.Fatalf("role %s must not write events", role)
			}
		}
	}
}

func TestPasswords(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("unexpected encoding %q", hash)
	}
	if ok, err := VerifyPassword(hash, "correct horse battery staple"); err != nil || !ok {
		t.Fatalf("verify: %v %v", ok, err)
	}
	if ok, _ := VerifyPassword(hash, "correct horse battery stapler"); ok {
		t.Fatal("wrong password accepted")
	}
	for _, bad := range []string{"", "$argon2i$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA", "$argon2id$v=19$m=99999999,t=1,p=1$c2FsdA$aGFzaA"} {
		if _, err := VerifyPassword(bad, "x"); err == nil {
			t.Errorf("malformed hash %q must be rejected", bad)
		}
	}
	if CheckPasswordPolicy("short") == nil || CheckPasswordPolicy(strings.Repeat("a", 129)) == nil {
		t.Fatal("length policy")
	}
	if CheckPasswordPolicy("twelve chars") != nil {
		t.Fatal("12 characters is enough")
	}
}

func TestLimiter(t *testing.T) {
	l := NewWindowLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("ip:1"); !ok {
			t.Fatalf("request %d should pass", i)
		}
	}
	ok, retry := l.Allow("ip:1")
	if ok || retry <= 0 {
		t.Fatal("fourth request must be limited with a retry hint")
	}
	if ok, _ := l.Allow("ip:2"); !ok {
		t.Fatal("keys are independent")
	}
	var nilLimiter *Limiter
	if ok, _ := nilLimiter.Allow("x"); !ok {
		t.Fatal("a nil limiter allows everything")
	}
}
