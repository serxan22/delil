package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/serxan22/delil/pkg/client"
	"github.com/serxan22/delil/pkg/evidence"
	"github.com/serxan22/delil/pkg/verify"
)

func (a *app) statusCmd() *cobra.Command {
	return &cobra.Command{Use: "status", Short: "Show the project, streams and integrity status", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.client()
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			p, err := c.Project(ctx)
			if err != nil {
				return apiErr(err)
			}
			o, err := c.Overview(ctx)
			if err != nil {
				return apiErr(err)
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{"server": c.BaseURL, "project": p, "overview": o})
			}
			tw := tabwriter.NewWriter(a.out, 0, 2, 2, ' ', 0)
			fmt.Fprintf(tw, "Server\t%s\n", c.BaseURL)
			if p.Tenant != nil {
				fmt.Fprintf(tw, "Organization\t%s\n", p.Tenant.Name)
			}
			fmt.Fprintf(tw, "Project\t%s (%s)\n", p.Name, p.ID)
			fmt.Fprintf(tw, "Streams\t%d (%d active in the last 7 days)\n", o.Stats.Streams, o.Stats.ActiveStreams)
			fmt.Fprintf(tw, "Events\t%s total, %s today\n", verify.Thousands(o.Stats.EventsTotal), verify.Thousands(o.Stats.EventsToday))
			fmt.Fprintf(tw, "Integrity\t%s (%d passing, %d failing, %d unverified streams)\n", strings.ToUpper(o.Verification.Status),
				o.Verification.StreamsPassing, o.Verification.StreamsFailing, o.Verification.StreamsUnverified)
			if r := o.Verification.LatestRun; r != nil {
				fmt.Fprintf(tw, "Last verification\t%s %s (%s, %s events)\n", r.Status, r.CompletedAt, r.Trigger, verify.Thousands(r.EventsChecked))
			}
			if k := o.SigningKey; k != nil {
				fmt.Fprintf(tw, "Signing key\t%s (fingerprint %s…)\n", k.ID, k.Fingerprint[:16])
			}
			return tw.Flush()
		}}
}

func (a *app) eventsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "events", Short: "List and inspect events"}
	var q client.EventQuery
	var all bool
	list := &cobra.Command{Use: "list", Short: "List events, newest first", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.client()
			if err != nil {
				return err
			}
			var events []client.StoredEvent
			for {
				page, err := c.ListEvents(cmd.Context(), q)
				if err != nil {
					return apiErr(err)
				}
				events = append(events, page.Data...)
				if !all || !page.HasMore {
					break
				}
				q.Cursor = page.NextCursor
			}
			if a.jsonOut {
				return a.printJSON(events)
			}
			tw := tabwriter.NewWriter(a.out, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "RECORDED (UTC)\tSTREAM\tSEQ\tACTION\tACTOR\tRESOURCE\tSTATUS\tID")
			for _, e := range events {
				res := ""
				if e.Resource != nil {
					res = e.Resource.Type + ":" + e.Resource.ID
				}
				status := ""
				if e.Verification != nil {
					status = e.Verification.Status
				}
				fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n", shortTime(e.RecordedAt), e.Stream, e.Sequence, e.Action,
					e.Actor.ID, res, status, e.ID)
			}
			return tw.Flush()
		}}
	f := list.Flags()
	f.StringVar(&q.Stream, "stream", "", "stream name")
	f.StringVar(&q.ActorID, "actor", "", "actor id")
	f.StringVar(&q.Action, "action", "", "action (a trailing * matches a prefix)")
	f.StringVar(&q.ResourceType, "resource-type", "", "resource type")
	f.StringVar(&q.ResourceID, "resource-id", "", "resource id")
	f.StringVar(&q.From, "from", "", "recorded at or after (RFC 3339 or YYYY-MM-DD)")
	f.StringVar(&q.To, "to", "", "recorded before (RFC 3339 or YYYY-MM-DD)")
	f.StringVar(&q.VerificationStatus, "status", "", "verified, failed or unverified")
	f.IntVar(&q.Limit, "limit", 25, "page size (max 200)")
	f.BoolVar(&all, "all", false, "follow pagination until the end")
	cmd.AddCommand(list, a.inspectCmd())
	return cmd
}

func shortTime(s string) string {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return s
	}
	return t.UTC().Format("2006-01-02 15:04:05")
}

func (a *app) inspectCmd() *cobra.Command {
	return &cobra.Command{Use: "inspect <event-id>", Short: "Show one event with its integrity data", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.client()
			if err != nil {
				return err
			}
			e, err := c.GetEvent(cmd.Context(), args[0])
			if err != nil {
				return apiErr(err)
			}
			if a.jsonOut {
				return a.printJSON(e)
			}
			st := a.style()
			bold := st.Bold
			if bold == nil {
				bold = func(s string) string { return s }
			}
			fmt.Fprintf(a.out, "%s  %s\n\n", bold(e.Action), e.ID)
			tw := tabwriter.NewWriter(a.out, 0, 2, 2, ' ', 0)
			fmt.Fprintf(tw, "Stream\t%s #%d\n", e.Stream, e.Sequence)
			actor := e.Actor.Type + ":" + e.Actor.ID
			if e.Actor.DisplayName != "" {
				actor += " (" + e.Actor.DisplayName + ")"
			}
			fmt.Fprintf(tw, "Actor\t%s\n", actor)
			if e.Resource != nil {
				fmt.Fprintf(tw, "Resource\t%s:%s\n", e.Resource.Type, e.Resource.ID)
			}
			if e.OccurredAt != "" {
				fmt.Fprintf(tw, "Occurred at\t%s (asserted by the application)\n", e.OccurredAt)
			}
			fmt.Fprintf(tw, "Recorded at\t%s\n", e.RecordedAt)
			if e.Context != nil {
				fmt.Fprintf(tw, "Source\t%s %s %s\n", e.Context.SourceIP, e.Context.RequestID, e.Context.UserAgent)
			}
			if e.Verification != nil {
				fmt.Fprintf(tw, "Verification\t%s %s\n", e.Verification.Status, e.Verification.VerifiedAt)
			}
			_ = tw.Flush()
			for _, part := range []struct {
				name string
				raw  json.RawMessage
			}{{"Changes", e.Changes}, {"Before", e.Before}, {"After", e.After}, {"Data", e.Data}, {"Metadata", e.Metadata}} {
				if len(part.raw) == 0 {
					continue
				}
				var buf bytes.Buffer
				_ = json.Indent(&buf, part.raw, "  ", "  ")
				fmt.Fprintf(a.out, "\n%s\n  %s\n", bold(part.name), buf.String())
			}
			if len(e.Redactions) > 0 {
				fmt.Fprintf(a.out, "\n%s\n  %s\n", bold("Redacted before storage"), strings.Join(e.Redactions, ", "))
			}
			fmt.Fprintf(a.out, "\n%s\n", bold("Integrity"))
			tw = tabwriter.NewWriter(a.out, 0, 2, 2, ' ', 0)
			fmt.Fprintf(tw, "  Previous hash\t%s\n  Payload hash\t%s\n  Event hash\t%s\n  Signature\t%s\n  Signing key\t%s (%s)\n",
				e.Integrity.PreviousHash, e.Integrity.PayloadHash, e.Integrity.EventHash, e.Integrity.Signature,
				e.Integrity.SigningKeyID, e.Integrity.Algorithm)
			_ = tw.Flush()
			fmt.Fprintf(a.out, "\nVerify it: delil verify event %s\n", e.ID)
			return nil
		}}
}

func (a *app) exportCmd() *cobra.Command {
	var req client.ExportRequest
	var from, to string
	var fromSeq, toSeq int64
	var out string
	var noVerify bool
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Create, download and verify an evidence package",
		Example: "  delil export --stream contracts --from 2026-09-01 --to 2026-10-01\n" +
			"  delil export --stream cases --resource-type case --resource-id case_2026_0142 -o case-0142.zip",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if req.Stream == "" {
				return &ExitError{Code: ExitUsage, Err: errors.New("--stream is required")}
			}
			req.From, req.To = from, to
			if fromSeq > 0 {
				req.FromSequence = &fromSeq
			}
			if toSeq > 0 {
				req.ToSequence = &toSeq
			}
			c, err := a.client()
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			x, err := c.CreateExport(ctx, req)
			if err != nil {
				return apiErr(err)
			}
			fmt.Fprintf(a.errOut, "Export %s queued; waiting for the server to build it...\n", x.ID)
			if x, err = c.WaitForExport(ctx, x.ID, time.Second); err != nil {
				return apiErr(err)
			}
			if out == "" {
				out = fmt.Sprintf("delil-evidence-%s-%s.zip", req.Stream, x.ID)
			}
			file, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // user-chosen path
			if err != nil {
				return &ExitError{Code: ExitUsage, Err: err}
			}
			n, err := c.DownloadExport(ctx, x.ID, file)
			if cerr := file.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				_ = os.Remove(out)
				return apiErr(err)
			}
			fmt.Fprintf(a.errOut, "Saved %s (%d bytes, %d events disclosed, chain %d..%d)\n", out, n, x.DisclosedEvents,
				x.FirstSequence, x.LastSequence)
			if noVerify {
				return nil
			}
			res, err := evidence.VerifyFile(out, evidence.Options{Verifier: cliVerifier})
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(res)
			}
			fmt.Fprintln(a.out)
			a.writePackageText(res)
			if !res.Valid {
				return &ExitError{Code: ExitFailed}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&req.Stream, "stream", "", "stream to export (required)")
	f.StringVar(&from, "from", "", "recorded at or after (RFC 3339 or YYYY-MM-DD)")
	f.StringVar(&to, "to", "", "recorded before (RFC 3339 or YYYY-MM-DD)")
	f.Int64Var(&fromSeq, "from-seq", 0, "first sequence")
	f.Int64Var(&toSeq, "to-seq", 0, "last sequence")
	f.StringVar(&req.ActorID, "actor", "", "disclose only events by this actor")
	f.StringVar(&req.Action, "action", "", "disclose only this action")
	f.StringVar(&req.ResourceType, "resource-type", "", "disclose only this resource type")
	f.StringVar(&req.ResourceID, "resource-id", "", "disclose only this resource id")
	f.StringVarP(&out, "output", "o", "", "output file")
	f.BoolVar(&noVerify, "no-verify", false, "skip verifying the downloaded package")
	return cmd
}

func (a *app) keysCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "keys", Short: "Signing keys"}
	cmd.AddCommand(&cobra.Command{Use: "list", Short: "List signing keys", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.client()
			if err != nil {
				return err
			}
			keys, err := c.SigningKeys(cmd.Context())
			if err != nil {
				return apiErr(err)
			}
			if a.jsonOut {
				return a.printJSON(keys)
			}
			tw := tabwriter.NewWriter(a.out, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "KEY ID\tSTATUS\tACTIVATED\tRETIRED\tEVENTS\tFINGERPRINT (SHA-256)")
			for _, k := range keys {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", k.ID, k.Status, shortTime(k.ActivatedAt), shortTime(k.RetiredAt),
					strconv.FormatInt(k.EventsSigned, 10), k.Fingerprint)
			}
			return tw.Flush()
		}})
	var out string
	export := &cobra.Command{Use: "export", Short: "Write the public keys as a trusted-keys file for pinning", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.client()
			if err != nil {
				return err
			}
			kf, err := c.TrustedKeys(cmd.Context())
			if err != nil {
				return apiErr(err)
			}
			data, _ := json.MarshalIndent(kf, "", "  ")
			if out == "" {
				_, err = a.out.Write(append(data, '\n'))
				return err
			}
			if err := os.WriteFile(out, append(data, '\n'), 0o644); err != nil { //nolint:gosec // public keys
				return err
			}
			fmt.Fprintf(a.errOut, "Wrote %d public key(s) to %s. Store this file where the server cannot change it.\n", len(kf.Keys), out)
			return nil
		}}
	export.Flags().StringVarP(&out, "output", "o", "", "output file (default stdout)")
	var yes bool
	rotate := &cobra.Command{Use: "rotate", Short: "Rotate the project's signing key", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !yes {
				return &ExitError{Code: ExitUsage, Err: errors.New("rotation retires the active key; re-run with --yes to confirm")}
			}
			c, err := a.client()
			if err != nil {
				return err
			}
			prev, cur, err := c.RotateSigningKey(cmd.Context())
			if err != nil {
				return apiErr(err)
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{"previous": prev, "current": cur})
			}
			fmt.Fprintf(a.out, "Retired %s\nActive  %s\nFingerprint %s\nRe-export pinned keys: delil keys export -o trusted-keys.json\n",
				prev.ID, cur.ID, cur.Fingerprint)
			return nil
		}}
	rotate.Flags().BoolVar(&yes, "yes", false, "confirm the rotation")
	cmd.AddCommand(export, rotate)
	return cmd
}

func (a *app) checkpointsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "checkpoints", Short: "Signed checkpoints and witnesses"}
	var stream, out string
	list := &cobra.Command{Use: "list", Short: "List a stream's checkpoints", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.client()
			if err != nil {
				return err
			}
			cps, err := c.Checkpoints(cmd.Context(), stream)
			if err != nil {
				return apiErr(err)
			}
			if a.jsonOut {
				return a.printJSON(cps)
			}
			tw := tabwriter.NewWriter(a.out, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "SEQUENCE\tCREATED\tHEAD HASH\tCHECKPOINT")
			for _, cp := range cps {
				fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", cp.Sequence, shortTime(cp.CreatedAt), cp.HeadHash.String(), cp.CheckpointID)
			}
			return tw.Flush()
		}}
	save := &cobra.Command{
		Use:   "save",
		Short: "Create a checkpoint at the current head and save it as a witness file",
		Long: `Saves a signed statement of the stream's current head. Keep the file
outside the DƏLİL deployment; later, "delil verify --witness <file>" proves the
stream still contains that exact history (detects rollback and truncation).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.client()
			if err != nil {
				return err
			}
			cp, err := c.CreateCheckpoint(cmd.Context(), stream)
			if err != nil {
				return apiErr(err)
			}
			if out == "" {
				out = fmt.Sprintf("witness-%s-%d.json", stream, cp.Sequence)
			}
			data, _ := json.MarshalIndent(cp, "", "  ")
			if err := os.WriteFile(out, append(data, '\n'), 0o644); err != nil { //nolint:gosec // not secret
				return err
			}
			fmt.Fprintf(a.out, "Saved checkpoint of %s at sequence %d to %s\n", stream, cp.Sequence, out)
			return nil
		}}
	for _, c := range []*cobra.Command{list, save} {
		c.Flags().StringVar(&stream, "stream", "", "stream name (required)")
		_ = c.MarkFlagRequired("stream")
	}
	save.Flags().StringVarP(&out, "output", "o", "", "output file")
	cmd.AddCommand(list, save)
	return cmd
}
