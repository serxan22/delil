package audit

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Retention modes for before/after states.
const (
	RetainFull = "full"
	RetainDiff = "diff"
)

// Redaction modes.
const (
	RedactReplace = "redact"
	RedactRemove  = "remove"
	RedactMask    = "mask"
)

// RedactedValue replaces redacted values in "redact" mode.
const RedactedValue = "[REDACTED]"

// Settings are per-project ingestion settings stored in projects.settings.
type Settings struct {
	Redaction RedactionSettings `json:"redaction"`
	// RetainStates controls whether before/after are stored ("full") or only
	// the computed diff ("diff", data minimisation).
	RetainStates string `json:"retainStates"`
	// MaxEventBytes optionally lowers the server-wide event size limit.
	MaxEventBytes int `json:"maxEventBytes,omitempty"`
}

// RedactionSettings configure redaction before persistence.
type RedactionSettings struct {
	// Keys are additional member names to redact anywhere in before, after,
	// data and metadata. Matching ignores case and non-alphanumerics.
	Keys []string `json:"keys"`
	// Paths are exact JSON Pointers into the event content, e.g.
	// "/after/customer/iban".
	Paths []string `json:"paths"`
	// Mode is "redact" (default), "remove" or "mask" (keep the last four
	// characters of strings).
	Mode string `json:"mode"`
	// DisableDefaults turns off the built-in denylist (not recommended).
	DisableDefaults bool `json:"disableDefaults"`
}

// DefaultSettings returns the settings used when a project has none.
func DefaultSettings() Settings {
	return Settings{RetainStates: RetainFull, Redaction: RedactionSettings{Mode: RedactReplace, Keys: []string{}, Paths: []string{}}}
}

// ParseSettings parses and validates a settings document. Missing members
// take their defaults; unknown members are rejected.
func ParseSettings(raw json.RawMessage) (Settings, error) {
	s := DefaultSettings()
	if len(raw) == 0 || string(raw) == "{}" || string(raw) == "null" {
		return s, nil
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Settings{}, fmt.Errorf("invalid project settings: %w", err)
	}
	if s.RetainStates == "" {
		s.RetainStates = RetainFull
	}
	if s.Redaction.Mode == "" {
		s.Redaction.Mode = RedactReplace
	}
	if s.Redaction.Keys == nil {
		s.Redaction.Keys = []string{}
	}
	if s.Redaction.Paths == nil {
		s.Redaction.Paths = []string{}
	}
	return s, s.Validate()
}

// Validate checks the settings.
func (s Settings) Validate() error {
	switch s.RetainStates {
	case RetainFull, RetainDiff:
	default:
		return fmt.Errorf("retainStates must be %q or %q", RetainFull, RetainDiff)
	}
	switch s.Redaction.Mode {
	case RedactReplace, RedactRemove, RedactMask:
	default:
		return fmt.Errorf("redaction.mode must be %q, %q or %q", RedactReplace, RedactRemove, RedactMask)
	}
	if len(s.Redaction.Keys) > 200 || len(s.Redaction.Paths) > 200 {
		return fmt.Errorf("at most 200 redaction keys and 200 paths are allowed")
	}
	for _, k := range s.Redaction.Keys {
		if normalizeKey(k) == "" || len(k) > 128 {
			return fmt.Errorf("invalid redaction key %q", k)
		}
	}
	for _, p := range s.Redaction.Paths {
		if !strings.HasPrefix(p, "/") || len(p) > 512 {
			return fmt.Errorf("redaction path %q must be a JSON Pointer starting with '/'", p)
		}
		root := strings.SplitN(p[1:], "/", 2)[0]
		switch root {
		case "before", "after", "data", "metadata":
		default:
			return fmt.Errorf("redaction path %q must start with /before, /after, /data or /metadata", p)
		}
	}
	if s.MaxEventBytes < 0 {
		return fmt.Errorf("maxEventBytes must not be negative")
	}
	return nil
}
