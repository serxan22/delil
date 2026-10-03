// Package config reads server configuration from environment variables. Every
// variable is documented in .env.example and docs/deployment.md.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Environments.
const (
	EnvDevelopment = "development"
	EnvProduction  = "production"
)

// Config is the complete server configuration.
type Config struct {
	Env      string
	HTTPAddr string

	DatabaseURL          string
	MigrationDatabaseURL string
	AutoMigrate          bool
	DBAppRole            string
	DBMaxConns           int32

	KeyProvider   string
	MasterKey     []byte
	MasterKeyFile string
	KeyDir        string

	DataDir   string
	ExportDir string
	ExportTTL time.Duration
	AnchorDir string

	CheckpointEvery  int64
	CheckpointMaxAge time.Duration
	CheckpointPoll   time.Duration
	VerifyInterval   time.Duration

	MaxEventBytes        int
	MaxBatchEvents       int
	MaxRequestBytes      int64
	MaxStreamsPerProject int
	IdempotencyTTL       time.Duration

	RateLimitRPS    float64
	RateLimitBurst  int
	LoginRateLimit  int
	SessionTTL      time.Duration
	CORSOrigins     []string
	TrustedProxies  []netip.Prefix
	MetricsAddr     string
	MetricsToken    string
	LogLevel        string
	LogFormat       string
	ShutdownTimeout time.Duration

	Bootstrap              bool
	BootstrapOrgName       string
	BootstrapProjectName   string
	BootstrapAdminEmail    string
	BootstrapAdminPassword string
	DemoData               bool
}

// IsDevelopment reports whether development conveniences are enabled.
func (c *Config) IsDevelopment() bool { return c.Env == EnvDevelopment }

type reader struct {
	errs []string
}

func (r *reader) str(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func (r *reader) boolean(name string, def bool) bool {
	v := r.str(name, "")
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		r.errs = append(r.errs, fmt.Sprintf("%s: expected true or false", name))
		return def
	}
	return b
}

func (r *reader) integer(name string, def int64) int64 {
	v := r.str(name, "")
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		r.errs = append(r.errs, fmt.Sprintf("%s: expected a non-negative integer", name))
		return def
	}
	return n
}

// intUpTo reads an int in [0, limit]. strconv.Atoi already returns an int,
// so no narrowing conversion can wrap on 32-bit platforms.
func (r *reader) intUpTo(name string, def, limit int) int {
	v := r.str(name, "")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > limit {
		r.errs = append(r.errs, fmt.Sprintf("%s: expected an integer between 0 and %d", name, limit))
		return def
	}
	return n
}

// int32UpTo reads an int32 in [0, limit].
func (r *reader) int32UpTo(name string, def, limit int32) int32 {
	v := r.str(name, "")
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 32)
	if err != nil || n < 0 || n > int64(limit) {
		r.errs = append(r.errs, fmt.Sprintf("%s: expected an integer between 0 and %d", name, limit))
		return def
	}
	return int32(n)
}

func (r *reader) float(name string, def float64) float64 {
	v := r.str(name, "")
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f < 0 {
		r.errs = append(r.errs, fmt.Sprintf("%s: expected a non-negative number", name))
		return def
	}
	return f
}

func (r *reader) duration(name string, def time.Duration) time.Duration {
	v := r.str(name, "")
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		r.errs = append(r.errs, fmt.Sprintf("%s: expected a duration such as 30s, 15m or 6h", name))
		return def
	}
	return d
}

func (r *reader) list(name string) []string {
	var out []string
	for _, p := range strings.Split(r.str(name, ""), ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Load reads the environment.
func Load() (*Config, error) {
	r := &reader{}
	c := &Config{
		Env:      r.str("DELIL_ENV", EnvProduction),
		HTTPAddr: r.str("DELIL_HTTP_ADDR", ":8080"),

		DatabaseURL:          r.str("DELIL_DATABASE_URL", ""),
		MigrationDatabaseURL: r.str("DELIL_MIGRATION_DATABASE_URL", ""),
		AutoMigrate:          r.boolean("DELIL_AUTO_MIGRATE", false),
		DBAppRole:            r.str("DELIL_DB_APP_ROLE", ""),
		DBMaxConns:           r.int32UpTo("DELIL_DB_MAX_CONNS", 20, 1000),

		KeyProvider:   r.str("DELIL_KEY_PROVIDER", "local"),
		MasterKeyFile: r.str("DELIL_MASTER_KEY_FILE", ""),
		KeyDir:        r.str("DELIL_KEY_DIR", ""),

		DataDir:   r.str("DELIL_DATA_DIR", "/var/lib/delil"),
		ExportTTL: r.duration("DELIL_EXPORT_TTL", 7*24*time.Hour),
		AnchorDir: r.str("DELIL_ANCHOR_DIR", ""),

		CheckpointEvery:  r.integer("DELIL_CHECKPOINT_EVERY", 1000),
		CheckpointMaxAge: r.duration("DELIL_CHECKPOINT_MAX_AGE", time.Hour),
		CheckpointPoll:   r.duration("DELIL_CHECKPOINT_POLL", 30*time.Second),
		VerifyInterval:   r.duration("DELIL_VERIFY_INTERVAL", 6*time.Hour),

		MaxEventBytes:        r.intUpTo("DELIL_MAX_EVENT_BYTES", 256*1024, 16<<20),
		MaxBatchEvents:       r.intUpTo("DELIL_MAX_BATCH_EVENTS", 500, 10000),
		MaxRequestBytes:      r.integer("DELIL_MAX_REQUEST_BYTES", 4*1024*1024),
		MaxStreamsPerProject: r.intUpTo("DELIL_MAX_STREAMS_PER_PROJECT", 1000, 1_000_000),
		IdempotencyTTL:       r.duration("DELIL_IDEMPOTENCY_TTL", 7*24*time.Hour),

		RateLimitRPS:    r.float("DELIL_RATE_LIMIT_RPS", 100),
		RateLimitBurst:  r.intUpTo("DELIL_RATE_LIMIT_BURST", 200, 1_000_000),
		LoginRateLimit:  r.intUpTo("DELIL_LOGIN_RATE_LIMIT", 10, 1_000_000),
		SessionTTL:      r.duration("DELIL_SESSION_TTL", 12*time.Hour),
		CORSOrigins:     r.list("DELIL_CORS_ALLOWED_ORIGINS"),
		MetricsAddr:     r.str("DELIL_METRICS_ADDR", ""),
		MetricsToken:    r.str("DELIL_METRICS_TOKEN", ""),
		LogLevel:        r.str("DELIL_LOG_LEVEL", "info"),
		LogFormat:       r.str("DELIL_LOG_FORMAT", "json"),
		ShutdownTimeout: r.duration("DELIL_SHUTDOWN_TIMEOUT", 20*time.Second),

		Bootstrap:              r.boolean("DELIL_BOOTSTRAP", false),
		BootstrapOrgName:       r.str("DELIL_BOOTSTRAP_ORG_NAME", "LegalFlow Demo"),
		BootstrapProjectName:   r.str("DELIL_BOOTSTRAP_PROJECT_NAME", "LegalFlow"),
		BootstrapAdminEmail:    strings.ToLower(r.str("DELIL_BOOTSTRAP_ADMIN_EMAIL", "admin@delil.local")),
		BootstrapAdminPassword: r.str("DELIL_BOOTSTRAP_ADMIN_PASSWORD", ""),
		DemoData:               r.boolean("DELIL_DEMO_DATA", false),
	}
	c.ExportDir = r.str("DELIL_EXPORT_DIR", filepath.Join(c.DataDir, "exports"))
	if c.MigrationDatabaseURL == "" {
		c.MigrationDatabaseURL = c.DatabaseURL
	}
	for _, s := range r.list("DELIL_TRUSTED_PROXIES") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			if a, aerr := netip.ParseAddr(s); aerr == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			} else {
				r.errs = append(r.errs, fmt.Sprintf("DELIL_TRUSTED_PROXIES: %q is not an address or CIDR", s))
				continue
			}
		}
		c.TrustedProxies = append(c.TrustedProxies, p.Masked())
	}
	if raw := r.str("DELIL_MASTER_KEY", ""); raw != "" {
		key, err := DecodeMasterKey(raw)
		if err != nil {
			r.errs = append(r.errs, "DELIL_MASTER_KEY: "+err.Error())
		}
		c.MasterKey = key
	}
	if c.MasterKey == nil && c.MasterKeyFile != "" {
		data, err := os.ReadFile(c.MasterKeyFile)
		if err != nil {
			r.errs = append(r.errs, "DELIL_MASTER_KEY_FILE: "+err.Error())
		} else if key, err := DecodeMasterKey(strings.TrimSpace(string(data))); err != nil {
			r.errs = append(r.errs, "DELIL_MASTER_KEY_FILE: "+err.Error())
		} else {
			c.MasterKey = key
		}
	}
	c.validate(r)
	if len(r.errs) > 0 {
		return nil, errors.New("invalid configuration:\n  - " + strings.Join(r.errs, "\n  - "))
	}
	return c, nil
}

func (c *Config) validate(r *reader) {
	switch c.Env {
	case EnvDevelopment, EnvProduction:
	default:
		r.errs = append(r.errs, "DELIL_ENV: must be development or production")
	}
	if c.DatabaseURL == "" {
		r.errs = append(r.errs, "DELIL_DATABASE_URL: required")
	}
	switch c.KeyProvider {
	case "local":
		if c.MasterKey == nil && c.Env == EnvProduction {
			r.errs = append(r.errs, "DELIL_MASTER_KEY or DELIL_MASTER_KEY_FILE: required in production for the local key provider "+
				"(generate one with: openssl rand -base64 32)")
		}
	case "file":
		if c.KeyDir == "" {
			r.errs = append(r.errs, "DELIL_KEY_DIR: required for the file key provider")
		}
	default:
		r.errs = append(r.errs, "DELIL_KEY_PROVIDER: must be local or file")
	}
	if c.MaxEventBytes < 1024 || c.MaxEventBytes > 16<<20 {
		r.errs = append(r.errs, "DELIL_MAX_EVENT_BYTES: must be between 1024 and 16777216")
	}
	if c.MaxBatchEvents < 1 || c.MaxBatchEvents > 10000 {
		r.errs = append(r.errs, "DELIL_MAX_BATCH_EVENTS: must be between 1 and 10000")
	}
	if c.MaxRequestBytes < int64(c.MaxEventBytes) {
		r.errs = append(r.errs, "DELIL_MAX_REQUEST_BYTES: must be at least DELIL_MAX_EVENT_BYTES")
	}
	if c.LogFormat != "json" && c.LogFormat != "text" {
		r.errs = append(r.errs, "DELIL_LOG_FORMAT: must be json or text")
	}
	if c.CheckpointEvery < 1 {
		r.errs = append(r.errs, "DELIL_CHECKPOINT_EVERY: must be at least 1")
	}
	for _, o := range c.CORSOrigins {
		if o == "*" {
			r.errs = append(r.errs, "DELIL_CORS_ALLOWED_ORIGINS: '*' is not allowed; list explicit origins")
		}
	}
}

// DecodeMasterKey accepts standard or URL-safe base64 (padded or not) of
// exactly 32 bytes.
func DecodeMasterKey(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if key, err := enc.DecodeString(s); err == nil {
			if len(key) != 32 {
				return nil, fmt.Errorf("must decode to 32 bytes, got %d", len(key))
			}
			return key, nil
		}
	}
	return nil, errors.New("must be base64 (generate with: openssl rand -base64 32)")
}
