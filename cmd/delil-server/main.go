// Command delil-server runs the DƏLİL API and provides operator commands.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/serxan22/delil/internal/app"
	"github.com/serxan22/delil/internal/auth"
	"github.com/serxan22/delil/internal/bootstrap"
	"github.com/serxan22/delil/internal/config"
	"github.com/serxan22/delil/internal/db"
	"github.com/serxan22/delil/internal/demo"
	"github.com/serxan22/delil/internal/id"
	"github.com/serxan22/delil/internal/store"
	"github.com/serxan22/delil/internal/verification"
	"github.com/serxan22/delil/internal/version"
	"github.com/serxan22/delil/pkg/verify"
)

func main() {
	root := &cobra.Command{
		Use:           "delil-server",
		Short:         "DƏLİL — cryptographically verifiable audit infrastructure (server)",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.String(),
	}
	root.AddCommand(serveCmd(), migrateCmd(), bootstrapCmd(), demoCmd(), apiKeysCmd(), usersCmd(), keysCmd(),
		verifyCmd(), healthcheckCmd(), versionCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		var exit exitError
		if errors.As(err, &exit) {
			os.Exit(int(exit))
		}
		os.Exit(1)
	}
}

type exitError int

func (e exitError) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func load() (*config.Config, error) { return config.Load() }

func withApp(fn func(ctx context.Context, a *app.App) error) error {
	cfg, err := load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log := app.NewLogger(cfg)
	a, err := app.New(ctx, cfg, log, version.Version)
	if err != nil {
		return err
	}
	defer a.Close()
	return fn(ctx, a)
}

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the API server and background workers",
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg, err := load()
			if err != nil {
				return err
			}
			log := app.NewLogger(cfg)
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			if cfg.AutoMigrate {
				if err := app.Migrate(ctx, cfg, log); err != nil {
					return fmt.Errorf("migrate: %w", err)
				}
			}
			a, err := app.New(ctx, cfg, log, version.Version)
			if err != nil {
				return err
			}
			defer a.Close()
			if ok, err := db.UpToDate(ctx, a.Pool); err != nil || !ok {
				return errors.New("the database schema is not up to date; run `delil-server migrate` (or set DELIL_AUTO_MIGRATE=true)")
			}
			if cfg.Bootstrap {
				if err := runBootstrap(ctx, a, cfg, os.Stdout); err != nil {
					return fmt.Errorf("bootstrap: %w", err)
				}
			}

			srv := &http.Server{
				Addr:              cfg.HTTPAddr,
				Handler:           a.API.Handler(),
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       60 * time.Second,
				WriteTimeout:      15 * time.Minute,
				IdleTimeout:       2 * time.Minute,
				MaxHeaderBytes:    64 << 10,
			}
			errc := make(chan error, 2)
			go func() { errc <- srv.ListenAndServe() }()
			var msrv *http.Server
			if cfg.MetricsAddr != "" {
				mux := http.NewServeMux()
				mux.Handle("GET /metrics", a.API.MetricsHandler())
				msrv = &http.Server{Addr: cfg.MetricsAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
				go func() { errc <- msrv.ListenAndServe() }()
			}
			workers, cancelWorkers := context.WithCancel(ctx)
			defer cancelWorkers()
			a.RunWorkers(workers)
			log.Info("DƏLİL server started", "addr", cfg.HTTPAddr, "version", version.Version, "env", cfg.Env,
				"key_provider", cfg.KeyProvider)

			select {
			case err := <-errc:
				if !errors.Is(err, http.ErrServerClosed) {
					return err
				}
			case <-ctx.Done():
			}
			log.Info("shutting down")
			cancelWorkers()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
			defer cancel()
			if msrv != nil {
				_ = msrv.Shutdown(shutdownCtx)
			}
			return srv.Shutdown(shutdownCtx)
		},
	}
}

func runBootstrap(ctx context.Context, a *app.App, cfg *config.Config, out io.Writer) error {
	opts := bootstrap.Options{OrgName: cfg.BootstrapOrgName, ProjectName: cfg.BootstrapProjectName,
		AdminEmail: cfg.BootstrapAdminEmail, AdminPassword: cfg.BootstrapAdminPassword}
	now := time.Now().UTC()
	if cfg.DemoData {
		opts.KeyActivation = demo.Start(now)
	}
	res, err := bootstrap.Run(ctx, a, opts)
	if err != nil {
		return err
	}
	if !res.Created {
		a.Log.Info("bootstrap skipped: the installation already has an organization")
		return nil
	}
	if cfg.DemoData {
		n, err := demo.Seed(ctx, a, res.TenantID, res.ProjectID, now)
		if err != nil {
			return fmt.Errorf("demo data: %w", err)
		}
		a.Log.Info("LegalFlow demo data seeded", "events", n)
	}
	printCredentials(out, res)
	return nil
}

func printCredentials(out io.Writer, res bootstrap.Result) {
	line := strings.Repeat("=", 74)
	fmt.Fprintf(out, "\n%s\n DƏLİL bootstrap complete. These credentials are shown ONCE; store them now.\n%s\n", line, strings.Repeat("-", 74))
	fmt.Fprintf(out, " Organization: %s\n Project:      %s\n", res.TenantID, res.ProjectID)
	fmt.Fprintf(out, " Admin email:  %s\n", res.AdminEmail)
	if res.PasswordGenerated {
		fmt.Fprintf(out, " Password:     %s\n", res.AdminPassword)
	} else {
		fmt.Fprintf(out, " Password:     (from DELIL_BOOTSTRAP_ADMIN_PASSWORD)\n")
	}
	fmt.Fprintf(out, " API key:      %s\n", res.APIKey)
	fmt.Fprintf(out, "               (all scopes; create narrower keys for applications)\n%s\n\n", line)
}

func migrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Apply database migrations (uses DELIL_MIGRATION_DATABASE_URL)",
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg, err := load()
			if err != nil {
				return err
			}
			return app.Migrate(context.Background(), cfg, app.NewLogger(cfg))
		},
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show applied and pending migrations",
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg, err := load()
			if err != nil {
				return err
			}
			ctx := context.Background()
			pool, err := db.Connect(ctx, cfg.MigrationDatabaseURL, db.Options{MaxConns: 2})
			if err != nil {
				return err
			}
			defer pool.Close()
			states, err := db.Status(ctx, pool)
			if err != nil {
				return err
			}
			for _, s := range states {
				status := "pending"
				switch {
				case s.Modified:
					status = "MODIFIED AFTER APPLYING"
				case s.Applied:
					status = "applied " + s.AppliedAt.UTC().Format(time.RFC3339)
				}
				fmt.Printf("%04d  %-28s %s\n", s.Version, s.Name, status)
			}
			return nil
		},
	})
	return cmd
}

func bootstrapCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "bootstrap",
		Short: "Create the first organization, project, administrator and API key",
		RunE: func(_ *cobra.Command, _ []string) error {
			return withApp(func(ctx context.Context, a *app.App) error {
				return runBootstrap(ctx, a, a.Config, os.Stdout)
			})
		},
	}
}

func demoCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "demo", Short: "Demo data"}
	var project string
	seed := &cobra.Command{
		Use:   "seed",
		Short: "Seed the LegalFlow demo dataset into an empty project",
		RunE: func(_ *cobra.Command, _ []string) error {
			return withApp(func(ctx context.Context, a *app.App) error {
				p, err := findProject(ctx, a, project)
				if err != nil {
					return err
				}
				streams, err := a.Store.ListStreams(ctx, p.TenantID, p.ID)
				if err != nil {
					return err
				}
				if len(streams) > 0 {
					return errors.New("the project already has streams; demo data is only seeded into empty projects")
				}
				n, err := demo.Seed(ctx, a, p.TenantID, p.ID, time.Now().UTC())
				if err == nil {
					fmt.Printf("seeded %d demo events into %s\n", n, p.ID)
				}
				return err
			})
		},
	}
	seed.Flags().StringVar(&project, "project", "", "project id or slug (required)")
	_ = seed.MarkFlagRequired("project")
	cmd.AddCommand(seed)
	return cmd
}

func findProject(ctx context.Context, a *app.App, ref string) (store.Project, error) {
	if id.Valid(id.Project, ref) {
		var tenantID string
		if err := a.Pool.QueryRow(ctx, `SELECT tenant_id FROM projects WHERE id = $1`, ref).Scan(&tenantID); err != nil {
			return store.Project{}, fmt.Errorf("project %s not found", ref)
		}
		return a.Store.GetProject(ctx, tenantID, ref)
	}
	ps, err := a.Store.FindProjectBySlug(ctx, ref)
	if err != nil {
		return store.Project{}, err
	}
	switch len(ps) {
	case 0:
		return store.Project{}, fmt.Errorf("project %q not found", ref)
	case 1:
		return ps[0], nil
	default:
		return store.Project{}, fmt.Errorf("slug %q is ambiguous across organizations; use the project id", ref)
	}
}

func apiKeysCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "apikeys", Short: "Manage API keys"}
	var project, name string
	var scopes []string
	create := &cobra.Command{
		Use:   "create",
		Short: "Create an API key (the secret is printed once)",
		RunE: func(_ *cobra.Command, _ []string) error {
			return withApp(func(ctx context.Context, a *app.App) error {
				p, err := findProject(ctx, a, project)
				if err != nil {
					return err
				}
				sc, err := auth.NormalizeScopes(scopes)
				if err != nil {
					return err
				}
				raw, lookup, hash := auth.NewAPIKey()
				k := store.APIKey{ID: id.New(id.APIKey), TenantID: p.TenantID, ProjectID: p.ID, Name: name, LookupID: lookup,
					SecretHash: hash[:], Scopes: sc, CreatedBy: "system:cli", CreatedAt: time.Now().UTC()}
				if err := a.Store.CreateAPIKey(ctx, a.Pool, k); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "Created API key %s for project %s with scopes %s.\nThe secret is shown once:\n",
					k.ID, p.ID, strings.Join(sc, ", "))
				fmt.Println(raw)
				return nil
			})
		},
	}
	create.Flags().StringVar(&project, "project", "", "project id or slug (required)")
	create.Flags().StringVar(&name, "name", "cli", "key name")
	create.Flags().StringSliceVar(&scopes, "scopes", []string{auth.ScopeEventsWrite, auth.ScopeEventsRead, auth.ScopeVerify},
		"comma-separated scopes: "+strings.Join(auth.APIKeyScopes, ", "))
	_ = create.MarkFlagRequired("project")
	cmd.AddCommand(create)
	return cmd
}

func usersCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "users", Short: "Manage dashboard users"}
	var project, email, name, role string
	create := &cobra.Command{
		Use:   "create",
		Short: "Create a dashboard user in the organization that owns --project",
		RunE: func(_ *cobra.Command, _ []string) error {
			return withApp(func(ctx context.Context, a *app.App) error {
				p, err := findProject(ctx, a, project)
				if err != nil {
					return err
				}
				if !auth.ValidRole(role) {
					return errors.New("role must be admin, auditor or viewer")
				}
				password, generated, err := readPassword()
				if err != nil {
					return err
				}
				hash, err := auth.HashPassword(password)
				if err != nil {
					return err
				}
				u := store.User{ID: id.New(id.User), TenantID: p.TenantID, Email: strings.ToLower(strings.TrimSpace(email)),
					DisplayName: name, PasswordHash: hash, Role: role, CreatedAt: time.Now().UTC()}
				if err := a.Store.CreateUser(ctx, a.Pool, u); err != nil {
					return err
				}
				fmt.Printf("created %s (%s) as %s\n", u.Email, u.ID, role)
				if generated {
					fmt.Printf("generated password (shown once): %s\n", password)
				}
				return nil
			})
		},
	}
	create.Flags().StringVar(&project, "project", "", "a project of the user's organization (required)")
	create.Flags().StringVar(&email, "email", "", "email (required)")
	create.Flags().StringVar(&name, "name", "", "display name (required)")
	create.Flags().StringVar(&role, "role", "viewer", "admin, auditor or viewer")
	for _, f := range []string{"project", "email", "name"} {
		_ = create.MarkFlagRequired(f)
	}
	cmd.AddCommand(create)
	return cmd
}

// readPassword prompts on a terminal, or generates a password otherwise.
func readPassword() (string, bool, error) {
	fd := int(os.Stdin.Fd()) //nolint:gosec // file descriptors fit in int
	if !term.IsTerminal(fd) {
		return auth.GeneratePassword(), true, nil
	}
	fmt.Fprint(os.Stderr, "Password (empty to generate): ")
	pw, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", false, err
	}
	if len(pw) == 0 {
		return auth.GeneratePassword(), true, nil
	}
	if err := auth.CheckPasswordPolicy(string(pw)); err != nil {
		return "", false, err
	}
	return string(pw), false, nil
}

func keysCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "keys", Short: "Manage signing keys"}
	var project string
	rotate := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate a project's signing key",
		RunE: func(_ *cobra.Command, _ []string) error {
			return withApp(func(ctx context.Context, a *app.App) error {
				p, err := findProject(ctx, a, project)
				if err != nil {
					return err
				}
				res, err := a.Keys.Rotate(ctx, p.TenantID, p.ID)
				if err != nil {
					return err
				}
				fmt.Printf("retired %s\nactive  %s (fingerprint %s)\n", res.Previous.ID, res.Current.ID, res.Current.Fingerprint)
				return nil
			})
		},
	}
	rotate.Flags().StringVar(&project, "project", "", "project id or slug (required)")
	_ = rotate.MarkFlagRequired("project")
	cmd.AddCommand(rotate)
	return cmd
}

func verifyCmd() *cobra.Command {
	var project, stream string
	var record bool
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify streams directly against the database (operators)",
		RunE: func(_ *cobra.Command, _ []string) error {
			return withApp(func(ctx context.Context, a *app.App) error {
				p, err := findProject(ctx, a, project)
				if err != nil {
					return err
				}
				var names []string
				if stream != "" {
					names = []string{stream}
				} else {
					streams, err := a.Store.ListStreams(ctx, p.TenantID, p.ID)
					if err != nil {
						return err
					}
					for _, st := range streams {
						names = append(names, st.Name)
					}
				}
				failed := false
				for i, name := range names {
					rep, st, err := a.Verifier.VerifyStream(ctx, p.TenantID, p.ID, name, verification.StreamOptions{})
					if err != nil {
						return fmt.Errorf("%s: %w", name, err)
					}
					if i > 0 {
						fmt.Println()
					}
					verify.WriteText(os.Stdout, rep, verify.Style{})
					failed = failed || !rep.Valid
					if record {
						if _, err := a.Verifier.RecordStream(ctx, p.TenantID, p.ID, st, rep, verification.Trigger{Kind: "system", By: "delil-server"}); err != nil {
							return err
						}
					}
				}
				if failed {
					return exitError(1)
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "project id or slug (required)")
	cmd.Flags().StringVar(&stream, "stream", "", "verify only this stream")
	cmd.Flags().BoolVar(&record, "record", false, "store the result as a verification run")
	_ = cmd.MarkFlagRequired("project")
	return cmd
}

func healthcheckCmd() *cobra.Command {
	var url string
	cmd := &cobra.Command{
		Use:   "healthcheck",
		Short: "Exit 0 if the server answers /health (for container health checks)",
		RunE: func(_ *cobra.Command, _ []string) error {
			client := &http.Client{Timeout: 3 * time.Second}
			resp, err := client.Get(url) //nolint:noctx // short-lived probe with a client timeout
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("health endpoint returned %s", resp.Status)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&url, "url", "http://127.0.0.1:8080/health", "health endpoint")
	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println("delil-server", version.String())
		},
	}
}
