package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/serxan22/delil/internal/version"
	"github.com/serxan22/delil/pkg/client"
	"github.com/serxan22/delil/pkg/evidence"
	"github.com/serxan22/delil/pkg/integrity"
	"github.com/serxan22/delil/pkg/verify"
)

var cliVerifier = &verify.VerifierInfo{Name: "delil-cli", Version: version.Version, Location: "cli"}

// loadTrustedKeys reads a trusted-keys file (the format of `delil keys export`
// and evidence packages' public-keys.json).
func loadTrustedKeys(path string) (*integrity.KeySet, error) {
	data, err := os.ReadFile(path) //nolint:gosec // user-chosen file
	if err != nil {
		return nil, err
	}
	var kf evidence.KeysFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(kf.Keys) == 0 {
		return nil, fmt.Errorf("%s contains no keys", path)
	}
	return integrity.NewKeySet(kf.Keys...)
}

// loadWitness reads a saved checkpoint.
func loadWitness(path string) (integrity.Checkpoint, error) {
	var cp integrity.Checkpoint
	data, err := os.ReadFile(path) //nolint:gosec // user-chosen file
	if err != nil {
		return cp, err
	}
	if err := json.Unmarshal(data, &cp); err != nil {
		return cp, fmt.Errorf("%s: %w", path, err)
	}
	return cp, nil
}

type verifyFlags struct {
	stream, event string
	remote        bool
	trustedKeys   string
	witnesses     []string
}

func (a *app) verifyCmd() *cobra.Command {
	f := &verifyFlags{}
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify streams independently (downloads records and checks them locally)",
		Long: `Verifies the integrity of audit streams. By default delil downloads the raw
chain records and verifies hashes, links and signatures locally, so a
compromised server cannot fake a positive result. Pin the public keys with
--trusted-keys and detect rollbacks with --witness (a checkpoint saved earlier).

  delil verify                     every stream of the project
  delil verify stream contracts    one stream (also: --stream contracts)
  delil verify event evt_...       one event and its links (also: --event)`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			switch {
			case f.event != "":
				return a.verifyEvent(cmd.Context(), f)
			case f.stream != "":
				return a.verifyStreams(cmd.Context(), f, []string{f.stream})
			default:
				return a.verifyStreams(cmd.Context(), f, nil)
			}
		},
	}
	fl := cmd.PersistentFlags()
	fl.StringVar(&f.stream, "stream", "", "verify one stream")
	fl.StringVar(&f.event, "event", "", "verify one event")
	fl.BoolVar(&f.remote, "remote", false, "ask the server to verify instead of verifying locally")
	fl.StringVar(&f.trustedKeys, "trusted-keys", "", "pinned public keys (from `delil keys export`)")
	fl.StringSliceVar(&f.witnesses, "witness", nil, "saved checkpoint file(s) that must still be part of the chain")
	cmd.AddCommand(&cobra.Command{Use: "stream <name>", Short: "Verify one stream", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.verifyStreams(cmd.Context(), f, args)
		}})
	cmd.AddCommand(&cobra.Command{Use: "event <id>", Short: "Verify one event", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f.event = args[0]
			return a.verifyEvent(cmd.Context(), f)
		}})
	return cmd
}

func (a *app) keySet(ctx context.Context, c *client.Client, path string) (*integrity.KeySet, []integrity.KeyProblem, string, error) {
	if path != "" {
		ks, err := loadTrustedKeys(path)
		return ks, nil, "pinned (" + path + ")", err
	}
	kf, err := c.TrustedKeys(ctx)
	if err != nil {
		return nil, nil, "", err
	}
	ks, problems := integrity.NewKeySetLenient(kf.Keys...)
	return ks, problems, "fetched from the server (not pinned; use --trusted-keys)", nil
}

func (a *app) verifyLocal(ctx context.Context, c *client.Client, stream string, f *verifyFlags) (*verify.Report, error) {
	keys, problems, source, err := a.keySet(ctx, c, f.trustedKeys)
	if err != nil {
		return nil, err
	}
	var witnesses []integrity.Checkpoint
	for _, w := range f.witnesses {
		cp, err := loadWitness(w)
		if err != nil {
			return nil, err
		}
		if cp.Stream == stream {
			witnesses = append(witnesses, cp)
		}
	}
	checkpoints, err := c.Checkpoints(ctx, stream)
	if err != nil {
		return nil, err
	}
	return c.VerifyStreamLocal(ctx, stream, verify.StreamOptions{
		Keys: keys, KeySource: source, RejectedKeys: problems,
		Checkpoints: checkpoints, Witnesses: witnesses, Verifier: cliVerifier,
	})
}

func (a *app) verifyStreams(ctx context.Context, f *verifyFlags, names []string) error {
	c, err := a.client()
	if err != nil {
		return err
	}
	if len(names) == 0 && f.remote {
		run, err := c.VerifyProjectRemote(ctx)
		if err != nil {
			return apiErr(err)
		}
		return a.renderRemoteRun(run)
	}
	if len(names) == 0 {
		streams, err := c.Streams(ctx)
		if err != nil {
			return apiErr(err)
		}
		for _, s := range streams {
			names = append(names, s.Name)
		}
		if len(names) == 0 {
			fmt.Fprintln(a.out, "The project has no streams yet.")
			return nil
		}
	}
	var reports []*verify.Report
	for _, name := range names {
		var rep *verify.Report
		if f.remote {
			run, err := c.VerifyStreamRemote(ctx, name)
			if err != nil {
				return apiErr(err)
			}
			rep = &verify.Report{}
			if err := json.Unmarshal(run.Report, rep); err != nil {
				return err
			}
		} else if rep, err = a.verifyLocal(ctx, c, name, f); err != nil {
			return apiErr(fmt.Errorf("%s: %w", name, err))
		}
		reports = append(reports, rep)
	}
	failed := false
	for _, r := range reports {
		failed = failed || !r.Valid
	}
	if a.jsonOut {
		if len(reports) == 1 {
			err = a.printJSON(reports[0])
		} else {
			err = a.printJSON(map[string]any{"valid": !failed, "streams": reports})
		}
	} else {
		st := a.style()
		for i, r := range reports {
			if i > 0 {
				fmt.Fprintln(a.out)
			}
			verify.WriteText(a.out, r, st)
		}
		if len(reports) > 1 {
			fmt.Fprintln(a.out)
			tw := tabwriter.NewWriter(a.out, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "STREAM\tEVENTS\tRESULT")
			for _, r := range reports {
				res := st.Good
				label := "VALID"
				if !r.Valid {
					res, label = st.Bad, "FAILED"
				}
				if res == nil {
					res = func(s string) string { return s }
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Stream, verify.Thousands(r.EventsChecked), res(label))
			}
			_ = tw.Flush()
		}
	}
	if err != nil {
		return err
	}
	if failed {
		return &ExitError{Code: ExitFailed}
	}
	return nil
}

func (a *app) renderRemoteRun(run *client.VerificationRun) error {
	if a.jsonOut {
		return a.printJSON(run)
	}
	fmt.Fprintf(a.out, "Server-side verification %s: %s (%d streams, %s events, %d failures)\n",
		run.ID, run.Status, run.StreamsChecked, verify.Thousands(run.EventsChecked), run.FailureCount)
	fmt.Fprintln(a.out, "Note: this result was computed by the server. Run without --remote to verify independently.")
	if run.Status != "passed" {
		return &ExitError{Code: ExitFailed}
	}
	return nil
}

func (a *app) verifyEvent(ctx context.Context, f *verifyFlags) error {
	c, err := a.client()
	if err != nil {
		return err
	}
	var rep *verify.Report
	if f.remote {
		if rep, err = c.VerifyEventRemote(ctx, f.event); err != nil {
			return apiErr(err)
		}
	} else {
		ev, err := c.GetEvent(ctx, f.event)
		if err != nil {
			return apiErr(err)
		}
		keys, problems, source, err := a.keySet(ctx, c, f.trustedKeys)
		if err != nil {
			return apiErr(err)
		}
		page, err := c.Chain(ctx, ev.Stream, max(ev.Sequence-2, 0), 3)
		if err != nil {
			return apiErr(err)
		}
		var prev, target, next *verify.Item
		for i := range page.Records {
			it := &verify.Item{Record: page.Records[i]}
			switch it.Record.Sequence {
			case ev.Sequence - 1:
				prev = it
			case ev.Sequence:
				target = it
			case ev.Sequence + 1:
				next = it
			}
		}
		if target == nil {
			return apiErr(errors.New("the server did not return the event's chain record"))
		}
		rep = verify.VerifyEvent(*target, prev, next, verify.EventOptions{TenantID: page.TenantID, ProjectID: page.ProjectID,
			Stream: ev.Stream, Keys: keys, KeySource: source, RejectedKeys: problems, Verifier: cliVerifier})
	}
	if a.jsonOut {
		err = a.printJSON(rep)
	} else {
		verify.WriteText(a.out, rep, a.style())
	}
	if err != nil {
		return err
	}
	if !rep.Valid {
		return &ExitError{Code: ExitFailed}
	}
	return nil
}

func (a *app) verifyExportCmd() *cobra.Command {
	var trusted string
	cmd := &cobra.Command{
		Use:   "verify-export <package.zip>",
		Short: "Verify an evidence package offline (no server or database needed)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			opts := evidence.Options{Verifier: &verify.VerifierInfo{Name: "delil-cli", Version: version.Version, Location: "offline"}}
			if trusted != "" {
				ks, err := loadTrustedKeys(trusted)
				if err != nil {
					return &ExitError{Code: ExitUsage, Err: err}
				}
				opts.TrustedKeys = ks
			}
			res, err := evidence.VerifyFile(args[0], opts)
			if err != nil {
				return &ExitError{Code: ExitUsage, Err: err}
			}
			if a.jsonOut {
				err = a.printJSON(res)
			} else {
				a.writePackageText(res)
			}
			if err != nil {
				return err
			}
			if !res.Valid {
				return &ExitError{Code: ExitFailed}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&trusted, "trusted-keys", "", "pinned public keys; without it the package's own keys are used")
	return cmd
}

func (a *app) writePackageText(res *evidence.Result) {
	p := res.Package
	st := a.style()
	fmt.Fprintf(a.out, "Package:           %s\n", p.PackageID)
	fmt.Fprintf(a.out, "Created:           %s by %s %s\n", p.CreatedAt, p.Generator.Name, p.Generator.Version)
	fmt.Fprintf(a.out, "Organization:      %s (%s)\n", p.Tenant.Name, p.Tenant.ID)
	fmt.Fprintf(a.out, "Selection:         sequences %d..%d, %d event(s) disclosed\n",
		p.Selection.FromSequence, p.Selection.ToSequence, p.Selection.DisclosedEvents)
	if p.SignedBy != "" {
		fmt.Fprintf(a.out, "Manifest signed by %s\n", p.SignedBy)
	}
	if !p.KeysTrusted {
		warn := "warning: keys were taken from the package itself; pass --trusted-keys to check who signed it"
		if st.Warn != nil {
			warn = st.Warn(warn)
		}
		fmt.Fprintln(a.out, warn)
	}
	fmt.Fprintln(a.out)
	verify.WriteText(a.out, res.Report, st)
}
