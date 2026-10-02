// Package demo seeds the "LegalFlow Demo" dataset: a month of realistic audit
// activity for a fictional legal-operations company, across four streams.
//
// All people and companies are fictional. Events are appended through the
// normal appender (hashed, linked and signed) with a simulated clock that
// walks through the last 30 days; the signing key is rotated half-way so the
// dashboard shows key history. Nothing here is reachable through the API.
package demo

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"sort"
	"time"

	"github.com/serxan22/delil/internal/app"
	"github.com/serxan22/delil/internal/audit"
	"github.com/serxan22/delil/internal/verification"
)

// Start returns the beginning of the demo timeline for a given "now".
func Start(now time.Time) time.Time { return now.Add(-30 * 24 * time.Hour).Truncate(time.Hour) }

type person struct {
	id, name, kind string
	ip             string
}

var (
	leyla   = person{"user_leyla.hasanova", "Leyla Hasanova", "user", "203.0.113.24"}
	rashad  = person{"user_rashad.mammadli", "Rashad Mammadli", "user", "203.0.113.31"}
	nigar   = person{"user_nigar.guliyeva", "Nigar Guliyeva", "user", "203.0.113.47"}
	elvin   = person{"user_elvin.karimov", "Elvin Karimov", "user", "198.51.100.12"}
	sarah   = person{"user_sarah.mitchell", "Sarah Mitchell", "user", "198.51.100.88"}
	tomasz  = person{"user_tomasz.nowak", "Tomasz Nowak", "user", "198.51.100.140"}
	aysel   = person{"user_aysel.rzayeva", "Aysel Rzayeva", "user", "203.0.113.66"}
	billing = person{"billing-service", "Billing service", "service", "10.20.0.14"}
	esign   = person{"esign-gateway", "E-signature gateway", "service", "10.20.0.31"}
	intake  = person{"case-intake-bot", "Case intake automation", "service", "10.20.0.52"}
)

type event struct {
	at     time.Time
	stream string
	body   map[string]any
}

type builder struct {
	rng    *rand.Rand
	events []event
	start  time.Time
	req    int
}

func (b *builder) add(day float64, stream string, actor person, action string, resource map[string]any, extra map[string]any) {
	at := b.start.Add(time.Duration(day * float64(24*time.Hour))).Add(time.Duration(b.rng.IntN(3600)) * time.Second)
	b.req++
	body := map[string]any{
		"stream": stream,
		"actor":  map[string]any{"type": actor.kind, "id": actor.id, "displayName": actor.name},
		"action": action,
		"context": map[string]any{
			"requestId": fmt.Sprintf("req_%06d", 4100+b.req),
			"sourceIp":  actor.ip,
			"userAgent": userAgent(actor),
		},
		"occurredAt": at.Add(-time.Duration(b.rng.IntN(4000)) * time.Millisecond).Format(time.RFC3339Nano),
	}
	if resource != nil {
		body["resource"] = resource
	}
	for k, v := range extra {
		body[k] = v
	}
	b.events = append(b.events, event{at: at, stream: stream, body: body})
}

func userAgent(p person) string {
	switch p.kind {
	case "service":
		return "legalflow-" + p.id + "/2.8.1"
	default:
		return "LegalFlow Web/4.12 (Chrome 141; macOS 26)"
	}
}

func res(kind, id, name string) map[string]any {
	return map[string]any{"type": kind, "id": id, "displayName": name}
}

type contract struct {
	id, title, counterparty string
	amount                  float64
	currency                string
}

var contracts = []contract{
	{"ctr_2026_0812", "Master Services Agreement", "Caspian Logistics LLC", 184000, "AZN"},
	{"ctr_2026_0813", "Mutual NDA", "Baku Fintech Hub", 0, "AZN"},
	{"ctr_2026_0814", "Office Lease, Floor 12", "Port Baku Tower", 96000, "USD"},
	{"ctr_2026_0815", "Software License Agreement", "Nordlicht GmbH", 42500, "EUR"},
	{"ctr_2026_0816", "Data Processing Addendum", "Atlas Health Systems", 0, "EUR"},
	{"ctr_2026_0817", "Supplier Agreement", "Ganja Textile Works", 61200, "AZN"},
	{"ctr_2026_0818", "Consulting Agreement", "Silk Way Advisory", 28800, "USD"},
	{"ctr_2026_0819", "Settlement Agreement, matter 2026-0142", "Absheron Builders", 150000, "AZN"},
	{"ctr_2026_0820", "Employment Agreement, Senior Counsel", "Confidential candidate", 0, "AZN"},
	{"ctr_2026_0821", "Distribution Agreement", "Shirvan Foods", 73000, "AZN"},
}

type matter struct {
	id, title, client string
}

var matters = []matter{
	{"case_2026_0142", "Absheron Builders v. Kur Concrete", "Absheron Builders"},
	{"case_2026_0151", "Employment dispute, Caspian Logistics", "Caspian Logistics LLC"},
	{"case_2026_0157", "Trademark opposition: SILKWAY", "Silk Way Advisory"},
	{"case_2026_0163", "Regulatory inquiry, Atlas Health", "Atlas Health Systems"},
	{"case_2026_0170", "Lease renegotiation, Port Baku Tower", "Port Baku Tower"},
	{"case_2026_0174", "Debt recovery, Shirvan Foods", "Shirvan Foods"},
}

func (b *builder) contracts() {
	for i, c := range contracts {
		day := float64(i)*2.4 + b.rng.Float64()
		draft := map[string]any{"title": c.title, "counterparty": c.counterparty, "status": "draft", "owner": rashad.name}
		if c.amount > 0 {
			draft["value"] = map[string]any{"amount": c.amount, "currency": c.currency}
		}
		r := res("contract", c.id, c.title+", "+c.counterparty)
		b.add(day, "contracts", rashad, "contract.created", r, map[string]any{"before": nil, "after": draft})
		if c.amount > 0 && i%3 == 0 {
			revised := clone(draft)
			revised["value"] = map[string]any{"amount": c.amount * 0.94, "currency": c.currency}
			revised["discountApprovedBy"] = leyla.name
			b.add(day+0.6, "contracts", rashad, "contract.updated", r, map[string]any{"before": draft, "after": revised})
			draft = revised
		}
		review := clone(draft)
		review["status"] = "in_review"
		b.add(day+1.1, "contracts", nigar, "contract.submitted_for_review", r, map[string]any{"before": draft, "after": review})
		approved := clone(review)
		approved["status"] = "approved"
		approved["approvedBy"] = leyla.name
		b.add(day+1.9, "contracts", leyla, "contract.approved", r, map[string]any{"before": review, "after": approved,
			"metadata": map[string]any{"approvalPolicy": "two-person-rule", "riskTier": []string{"low", "medium", "high"}[i%3]}})
		if i%4 != 3 {
			signed := clone(approved)
			signed["status"] = "signed"
			b.add(day+3.2, "contracts", esign, "contract.signed", r, map[string]any{"before": approved, "after": signed,
				"data": map[string]any{"envelopeId": fmt.Sprintf("env_%08x", b.rng.Uint32()), "signatories": 2,
					"certificateSha256": fmt.Sprintf("%016x%016x", b.rng.Uint64(), b.rng.Uint64())}})
		}
	}
	// A terminated contract closes the month.
	c := contracts[6]
	b.add(27.5, "contracts", leyla, "contract.terminated", res("contract", c.id, c.title+", "+c.counterparty),
		map[string]any{"before": map[string]any{"status": "signed"}, "after": map[string]any{"status": "terminated"},
			"metadata": map[string]any{"reason": "mutual agreement", "noticeDays": 30}})
}

func (b *builder) permissions() {
	type change struct {
		day           float64
		actor         person
		action        string
		subject       person
		before, after map[string]any
		meta          map[string]any
	}
	changes := []change{
		{0.4, tomasz, "user.invited", sarah, nil, map[string]any{"email": "sarah.mitchell@legalflow.example", "role": "associate", "office": "London"}, nil},
		{0.9, tomasz, "role.granted", sarah, map[string]any{"roles": []any{"associate"}}, map[string]any{"roles": []any{"associate", "matter:case_2026_0157"}}, nil},
		{3.2, tomasz, "mfa.enabled", sarah, map[string]any{"mfa": false}, map[string]any{"mfa": true, "method": "webauthn"}, nil},
		{6.7, leyla, "role.granted", nigar, map[string]any{"roles": []any{"paralegal"}}, map[string]any{"roles": []any{"paralegal", "billing:read"}}, map[string]any{"ticket": "IT-2291"}},
		{9.1, tomasz, "permission.changed", rashad, map[string]any{"matterAccess": []any{"case_2026_0142"}}, map[string]any{"matterAccess": []any{"case_2026_0142", "case_2026_0163"}}, nil},
		{12.3, aysel, "mfa.disabled", elvin, map[string]any{"mfa": true, "method": "totp"}, map[string]any{"mfa": false}, map[string]any{"reason": "device replacement", "temporaryUntil": "48h"}},
		{13.8, elvin, "mfa.enabled", elvin, map[string]any{"mfa": false}, map[string]any{"mfa": true, "method": "webauthn"}, nil},
		{16.4, leyla, "role.granted", rashad, map[string]any{"roles": []any{"counsel"}}, map[string]any{"roles": []any{"counsel", "approver"}}, map[string]any{"ticket": "IT-2340"}},
		{19.0, tomasz, "role.revoked", nigar, map[string]any{"roles": []any{"paralegal", "billing:read"}}, map[string]any{"roles": []any{"paralegal"}}, map[string]any{"reason": "access review Q4"}},
		{21.6, aysel, "access_review.completed", aysel, nil, map[string]any{"usersReviewed": 47, "accessRemoved": 6}, nil},
		{24.2, tomasz, "user.deactivated", person{"user_ilkin.babayev", "Ilkin Babayev", "user", ""}, map[string]any{"status": "active"}, map[string]any{"status": "deactivated"}, map[string]any{"reason": "employment ended"}},
		{26.9, tomasz, "sso.configuration_changed", tomasz, map[string]any{"provider": "saml", "enforced": false}, map[string]any{"provider": "saml", "enforced": true}, nil},
	}
	for _, c := range changes {
		extra := map[string]any{"before": c.before, "after": c.after}
		if c.before == nil {
			delete(extra, "before")
			extra = map[string]any{"data": c.after}
		}
		if c.meta != nil {
			extra["metadata"] = c.meta
		}
		r := res("user", c.subject.id, c.subject.name)
		if c.action == "access_review.completed" {
			r = res("access_review", "review_2026_q4", "Quarterly access review")
		}
		if c.action == "sso.configuration_changed" {
			r = res("identity_provider", "idp_legalflow_saml", "LegalFlow SAML")
		}
		b.add(c.day, "permissions", c.actor, c.action, r, extra)
	}
}

func (b *builder) payments() {
	for i := 0; i < 14; i++ {
		day := float64(i)*2.0 + b.rng.Float64()
		c := contracts[i%len(contracts)]
		if c.amount == 0 {
			c = contracts[0]
		}
		inv := fmt.Sprintf("inv_2026_%04d", 3300+i)
		amount := float64(int(c.amount/12*100)) / 100
		r := res("invoice", inv, fmt.Sprintf("Invoice %d, %s", 3300+i, c.counterparty))
		b.add(day, "payments", billing, "invoice.issued", r, map[string]any{"before": nil,
			"after": map[string]any{"amount": amount, "currency": c.currency, "status": "open", "dueInDays": 30}})
		if i%5 == 2 {
			b.add(day+0.7, "payments", elvin, "invoice.modified", r, map[string]any{
				"before":   map[string]any{"amount": amount, "status": "open"},
				"after":    map[string]any{"amount": float64(int(amount*0.9*100)) / 100, "status": "open"},
				"metadata": map[string]any{"reason": "volume discount", "approvedBy": leyla.name}})
		}
		if i%3 != 1 {
			b.add(day+2.5, "payments", billing, "payment.received", r, map[string]any{
				"before": map[string]any{"status": "open"}, "after": map[string]any{"status": "paid"},
				// card_number is redacted by default before persistence.
				"data": map[string]any{"method": "card", "card_number": "4111111111111111", "processorRef": fmt.Sprintf("ch_%010d", b.rng.IntN(1e9))}})
		}
	}
	b.add(18.2, "payments", elvin, "refund.issued", res("invoice", "inv_2026_3304", "Invoice 3304, Port Baku Tower"),
		map[string]any{"before": map[string]any{"status": "paid", "refunded": 0}, "after": map[string]any{"status": "partially_refunded", "refunded": 1200},
			"metadata": map[string]any{"reason": "service credit", "approvedBy": leyla.name}})
	b.add(23.7, "payments", elvin, "payment.status_overridden", res("invoice", "inv_2026_3309", "Invoice 3309, Shirvan Foods"),
		map[string]any{"before": map[string]any{"status": "open"}, "after": map[string]any{"status": "paid"},
			"metadata": map[string]any{"reason": "payment confirmed by bank statement", "ticket": "FIN-884"}})
}

func (b *builder) cases() {
	stages := []string{"intake", "active", "discovery", "negotiation", "settlement", "closed"}
	for i, m := range matters {
		day := float64(i)*3.1 + b.rng.Float64()
		r := res("case", m.id, m.title)
		b.add(day, "cases", intake, "case.opened", r, map[string]any{"before": nil,
			"after": map[string]any{"title": m.title, "client": m.client, "status": "intake", "practiceArea": []string{"litigation", "employment", "ip", "regulatory"}[i%4]}})
		b.add(day+0.4, "cases", leyla, "case.assigned", r, map[string]any{
			"before": map[string]any{"leadCounsel": nil}, "after": map[string]any{"leadCounsel": []string{rashad.name, sarah.name}[i%2]}})
		last := 2 + i%4
		for s := 1; s <= last && s < len(stages); s++ {
			actor := []person{rashad, sarah, nigar}[s%3]
			b.add(day+float64(s)*1.3, "cases", actor, "case.status_changed", r, map[string]any{
				"before": map[string]any{"status": stages[s-1]}, "after": map[string]any{"status": stages[s]}})
			if s == 2 {
				b.add(day+float64(s)*1.3+0.2, "cases", nigar, "document.attached", r, map[string]any{
					"data": map[string]any{"documentId": fmt.Sprintf("doc_%06d", 70000+i*10+s), "name": "Statement of claim.pdf",
						"sha256":         fmt.Sprintf("%016x%016x%016x%016x", b.rng.Uint64(), b.rng.Uint64(), b.rng.Uint64(), b.rng.Uint64()),
						"classification": "privileged"}})
			}
		}
		if i%2 == 0 {
			b.add(day+4.6, "cases", sarah, "hearing.scheduled", r, map[string]any{
				"data": map[string]any{"court": "Baku Court of Appeal", "date": b.start.Add(time.Duration(day+20) * 24 * time.Hour).Format("2006-01-02")}})
		}
	}
}

func clone(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Seed appends the demo events for the project, rotates the key half-way,
// checkpoints every stream and records a verification run. It returns the
// number of events written.
func Seed(ctx context.Context, a *app.App, tenantID, projectID string, now time.Time) (int, error) {
	// A seeded, non-cryptographic generator: the demo must be reproducible.
	b := &builder{rng: rand.New(rand.NewPCG(2026, 10)), start: Start(now)} //nolint:gosec // not security-relevant
	b.contracts()
	b.permissions()
	b.payments()
	b.cases()
	sort.SliceStable(b.events, func(i, j int) bool { return b.events[i].at.Before(b.events[j].at) })

	var clock time.Time
	appender := audit.NewAppender(a.Store, a.Keys, audit.AppenderOptions{Now: func() time.Time { return clock }})
	settings := audit.DefaultSettings()
	rotated := false
	rotateAt := b.start.Add(15 * 24 * time.Hour)
	written := 0
	for _, ev := range b.events {
		if ev.at.After(now) {
			continue
		}
		if !rotated && ev.at.After(rotateAt) {
			if _, err := a.Keys.RotateAt(ctx, tenantID, projectID, rotateAt); err != nil {
				return written, fmt.Errorf("rotate demo key: %w", err)
			}
			rotated = true
		}
		raw, err := json.Marshal(ev.body)
		if err != nil {
			return written, err
		}
		tree, _, err := audit.ParseRequestBody(raw)
		if err != nil {
			return written, err
		}
		in, err := audit.DecodeEvent(tree)
		if err != nil {
			return written, fmt.Errorf("demo event %s: %w", ev.body["action"], err)
		}
		prepared, err := audit.Prepare(in, settings, 256*1024)
		if err != nil {
			return written, err
		}
		clock = ev.at
		if _, err := appender.Append(ctx, audit.AppendRequest{TenantID: tenantID, ProjectID: projectID,
			Events: []audit.Prepared{prepared}}); err != nil {
			return written, err
		}
		written++
	}

	streams, err := a.Store.ListStreams(ctx, tenantID, projectID)
	if err != nil {
		return written, err
	}
	for _, st := range streams {
		if _, _, err := a.Checkpoints.CreateForStream(ctx, st.Stream); err != nil {
			return written, err
		}
	}
	pr, err := a.Verifier.VerifyProject(ctx, tenantID, projectID)
	if err != nil {
		return written, err
	}
	if _, err := a.Verifier.RecordProject(ctx, tenantID, projectID, pr, verification.Trigger{Kind: "system", By: "demo-seed"}); err != nil {
		return written, err
	}
	if !pr.Valid {
		return written, fmt.Errorf("demo data failed verification (%d failures)", pr.FailureCount)
	}
	return written, nil
}
