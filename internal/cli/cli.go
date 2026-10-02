// Package cli implements the delil command-line tool.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/serxan22/delil/internal/version"
	"github.com/serxan22/delil/pkg/client"
	"github.com/serxan22/delil/pkg/verify"
)

// Exit codes.
const (
	ExitOK       = 0
	ExitFailed   = 1 // verification failed
	ExitUsage    = 2
	ExitAPIError = 3
)

// ExitError carries an exit code.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit %d", e.Code)
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error { return e.Err }

// Config is stored in the user's config directory with 0600 permissions.
type Config struct {
	URL    string `json:"url"`
	APIKey string `json:"apiKey,omitempty"`
}

// app holds global state for one invocation.
type app struct {
	out, errOut io.Writer
	jsonOut     bool
	noColor     bool
	url, apiKey string
	timeout     time.Duration
	configPath  string
}

func (a *app) style() verify.Style {
	if a.noColor || os.Getenv("NO_COLOR") != "" || !isTerminal(a.out) {
		return verify.Style{}
	}
	c := func(code string) func(string) string {
		return func(s string) string { return "\x1b[" + code + "m" + s + "\x1b[0m" }
	}
	return verify.Style{Bold: c("1"), Good: c("1;32"), Bad: c("1;31"), Warn: c("33"), Muted: c("2")}
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd())) //nolint:gosec // fd fits in int
}

func defaultConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "delil", "config.json")
}

func (a *app) loadConfig() Config {
	var c Config
	if data, err := os.ReadFile(a.configPath); err == nil {
		_ = json.Unmarshal(data, &c)
	}
	return c
}

func (a *app) saveConfig(c Config) error {
	if err := os.MkdirAll(filepath.Dir(a.configPath), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(c, "", "  ") //nolint:gosec // the key is stored on purpose, in a 0600 file
	return os.WriteFile(a.configPath, append(data, '\n'), 0o600)
}

// client resolves URL and key from flags, environment and config file.
func (a *app) client() (*client.Client, error) {
	cfg := a.loadConfig()
	url := firstNonEmpty(a.url, os.Getenv("DELIL_URL"), cfg.URL, "http://localhost:8080")
	key := firstNonEmpty(a.apiKey, os.Getenv("DELIL_API_KEY"), cfg.APIKey)
	if key == "" {
		return nil, &ExitError{Code: ExitUsage, Err: errors.New("no API key: set DELIL_API_KEY or run `delil login`")}
	}
	c := client.New(url, key)
	c.HTTP.Timeout = a.timeout
	c.UserAgent = "delil-cli/" + version.Version
	c.ClientName = "cli"
	return c, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func (a *app) printJSON(v any) error {
	enc := json.NewEncoder(a.out)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func apiErr(err error) error {
	if err == nil {
		return nil
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		return err
	}
	return &ExitError{Code: ExitAPIError, Err: err}
}

// Run executes the CLI and returns the process exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	a := &app{out: stdout, errOut: stderr, configPath: defaultConfigPath()}
	root := &cobra.Command{
		Use:           "delil",
		Short:         "DƏLİL — cryptographically verifiable audit infrastructure",
		Long:          "delil talks to a DƏLİL server and verifies audit streams and evidence packages independently.",
		Version:       version.String(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	pf := root.PersistentFlags()
	pf.StringVar(&a.url, "url", "", "server URL (env DELIL_URL)")
	pf.StringVar(&a.apiKey, "api-key", "", "API key (prefer env DELIL_API_KEY; flags can leak into shell history)")
	pf.BoolVar(&a.jsonOut, "json", false, "machine-readable JSON output")
	pf.BoolVar(&a.noColor, "no-color", false, "disable colors (also NO_COLOR)")
	pf.DurationVar(&a.timeout, "timeout", 2*time.Minute, "HTTP timeout")
	pf.StringVar(&a.configPath, "config", a.configPath, "config file")
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs(args)
	root.AddCommand(a.versionCmd(), a.healthCmd(), a.loginCmd(), a.statusCmd(), a.eventsCmd(), a.inspectCmd(),
		a.verifyCmd(), a.verifyExportCmd(), a.exportCmd(), a.keysCmd(), a.checkpointsCmd())
	err := root.ExecuteContext(ctx)
	if err == nil {
		return ExitOK
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		if ee.Err != nil {
			fmt.Fprintln(stderr, "error:", ee.Err)
		}
		return ee.Code
	}
	fmt.Fprintln(stderr, "error:", err)
	if strings.Contains(err.Error(), "unknown command") || strings.Contains(err.Error(), "flag") ||
		strings.Contains(err.Error(), "arg(s)") {
		return ExitUsage
	}
	return ExitAPIError
}

func (a *app) versionCmd() *cobra.Command {
	return &cobra.Command{Use: "version", Short: "Print the CLI version", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if a.jsonOut {
				return a.printJSON(map[string]string{"version": version.Version, "commit": version.Commit})
			}
			fmt.Fprintln(a.out, "delil", version.String())
			return nil
		}}
}

func (a *app) healthCmd() *cobra.Command {
	return &cobra.Command{Use: "health", Short: "Check that the server is reachable", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c := client.New(firstNonEmpty(a.url, os.Getenv("DELIL_URL"), a.loadConfig().URL, "http://localhost:8080"), "")
			c.HTTP.Timeout = a.timeout
			h, err := c.Health(cmd.Context())
			if err != nil {
				return apiErr(err)
			}
			if a.jsonOut {
				return a.printJSON(h)
			}
			fmt.Fprintf(a.out, "%s is healthy (server %v)\n", c.BaseURL, h["version"])
			return nil
		}}
}

func (a *app) loginCmd() *cobra.Command {
	return &cobra.Command{Use: "login", Short: "Store the server URL and API key in the config file", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := a.loadConfig()
			url := firstNonEmpty(a.url, os.Getenv("DELIL_URL"), cfg.URL, "http://localhost:8080")
			key := firstNonEmpty(a.apiKey, os.Getenv("DELIL_API_KEY"))
			if key == "" {
				fd := int(os.Stdin.Fd()) //nolint:gosec // fd fits in int
				if !term.IsTerminal(fd) {
					return &ExitError{Code: ExitUsage, Err: errors.New("provide the key with DELIL_API_KEY when stdin is not a terminal")}
				}
				fmt.Fprint(a.errOut, "API key (input hidden): ")
				raw, err := term.ReadPassword(fd)
				fmt.Fprintln(a.errOut)
				if err != nil {
					return err
				}
				key = strings.TrimSpace(string(raw))
			}
			c := client.New(url, key)
			c.HTTP.Timeout = a.timeout
			p, err := c.Project(cmd.Context())
			if err != nil {
				return apiErr(fmt.Errorf("the key was rejected: %w", err))
			}
			if err := a.saveConfig(Config{URL: url, APIKey: key}); err != nil {
				return err
			}
			fmt.Fprintf(a.out, "Logged in to %s (project %s). Credentials saved to %s (mode 0600).\n", url, p.Name, a.configPath)
			return nil
		}}
}
