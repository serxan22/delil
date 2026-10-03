package config

import (
	"strings"
	"testing"
)

func baseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DELIL_ENV", "development")
	t.Setenv("DELIL_DATABASE_URL", "postgres://localhost/delil")
}

func TestDefaults(t *testing.T) {
	baseEnv(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.DBMaxConns != 20 || c.MaxEventBytes != 256*1024 || c.MaxBatchEvents != 500 || c.RateLimitBurst != 200 ||
		c.LoginRateLimit != 10 || c.MaxStreamsPerProject != 1000 {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestIntegerBounds(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		ok          bool
	}{
		{"DELIL_DB_MAX_CONNS", "1000", true},
		{"DELIL_DB_MAX_CONNS", "1001", false},
		{"DELIL_DB_MAX_CONNS", "4294967316", false}, // would wrap to 20 as int32
		{"DELIL_MAX_BATCH_EVENTS", "10000", true},
		{"DELIL_MAX_BATCH_EVENTS", "10001", false},
		{"DELIL_MAX_EVENT_BYTES", "9223372036854775807", false},
		{"DELIL_RATE_LIMIT_BURST", "-1", false},
		{"DELIL_LOGIN_RATE_LIMIT", "abc", false},
		{"DELIL_MAX_STREAMS_PER_PROJECT", "1000000", true},
		{"DELIL_MAX_STREAMS_PER_PROJECT", "1000001", false},
	} {
		t.Run(tc.name+"="+tc.value, func(t *testing.T) {
			baseEnv(t)
			t.Setenv(tc.name, tc.value)
			_, err := Load()
			if tc.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.ok && (err == nil || !strings.Contains(err.Error(), tc.name)) {
				t.Fatalf("expected an error naming %s, got %v", tc.name, err)
			}
		})
	}
}

func TestProductionRequiresMasterKey(t *testing.T) {
	baseEnv(t)
	t.Setenv("DELIL_ENV", "production")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DELIL_MASTER_KEY") {
		t.Fatalf("expected a master key error, got %v", err)
	}
	t.Setenv("DELIL_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
}
