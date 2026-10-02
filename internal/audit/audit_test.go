package audit

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/serxan22/delil/pkg/integrity"
)

func decode(t *testing.T, body string) (EventInput, error) {
	t.Helper()
	tree, _, err := ParseRequestBody([]byte(body))
	if err != nil {
		return EventInput{}, err
	}
	return DecodeEvent(tree)
}

func fieldErrors(err error) map[string]string {
	out := map[string]string{}
	var ve *ValidationError
	if errors.As(err, &ve) {
		for _, fe := range ve.Errors {
			out[fe.Field] = fe.Message
		}
	}
	return out
}

func TestDecodeValidEvent(t *testing.T) {
	in, err := decode(t, `{"stream":"contracts","actor":{"type":"user","id":"user_128","displayName":"Sarkhan Mahabbatli"},
		"action":"contract.approved","resource":{"type":"contract","id":"contract_813"},
		"before":{"status":"pending"},"after":{"status":"approved"},"metadata":{"requestId":"req_123"},
		"context":{"sourceIp":"::ffff:203.0.113.7","userAgent":"curl/8"},"occurredAt":"2026-10-02T13:15:00.123456789+04:00"}`)
	if err != nil {
		t.Fatal(err)
	}
	if in.Stream != "contracts" || in.Actor.ID != "user_128" || in.Resource.ID != "contract_813" || !in.HasBefore || !in.HasAfter {
		t.Fatalf("decoded: %+v", in)
	}
	if in.Context.SourceIP != "203.0.113.7" {
		t.Fatalf("IPv4-mapped addresses must be normalized, got %s", in.Context.SourceIP)
	}
	if got := integrity.FormatTime(*in.OccurredAt); got != "2026-10-02T09:15:00.123456Z" {
		t.Fatalf("occurredAt must be normalized to UTC microseconds, got %s", got)
	}
}

func TestDecodeRejectsInvalidEvents(t *testing.T) {
	cases := map[string]struct {
		body  string
		field string
	}{
		"missing stream":      {`{"actor":{"type":"user","id":"u"},"action":"a"}`, "stream"},
		"bad stream":          {`{"stream":"Contracts","actor":{"type":"user","id":"u"},"action":"a"}`, "stream"},
		"reserved stream":     {`{"stream":"delil.system","actor":{"type":"user","id":"u"},"action":"a"}`, "stream"},
		"missing actor":       {`{"stream":"s","action":"a"}`, "actor"},
		"missing actor id":    {`{"stream":"s","actor":{"type":"user"},"action":"a"}`, "actor.id"},
		"blank actor id":      {`{"stream":"s","actor":{"type":"user","id":"  "},"action":"a"}`, "actor.id"},
		"bad actor type":      {`{"stream":"s","actor":{"type":"a b","id":"u"},"action":"a"}`, "actor.type"},
		"unknown actor field": {`{"stream":"s","actor":{"type":"user","id":"u","email":"x"},"action":"a"}`, "actor.email"},
		"missing action":      {`{"stream":"s","actor":{"type":"user","id":"u"}}`, "action"},
		"bad action":          {`{"stream":"s","actor":{"type":"user","id":"u"},"action":"contract approved"}`, "action"},
		"unknown field":       {`{"stream":"s","actor":{"type":"user","id":"u"},"action":"a","extra":1}`, "extra"},
		"case variant field":  {`{"stream":"s","Stream":"t","actor":{"type":"user","id":"u"},"action":"a"}`, "Stream"},
		"metadata not object": {`{"stream":"s","actor":{"type":"user","id":"u"},"action":"a","metadata":[1]}`, "metadata"},
		"bad ip":              {`{"stream":"s","actor":{"type":"user","id":"u"},"action":"a","context":{"sourceIp":"nope"}}`, "context.sourceIp"},
		"bad occurredAt":      {`{"stream":"s","actor":{"type":"user","id":"u"},"action":"a","occurredAt":"yesterday"}`, "occurredAt"},
		"control char":        {`{"stream":"s","actor":{"type":"user","id":"u\tv"},"action":"a"}`, "actor.id"},
		"resource without id": {`{"stream":"s","actor":{"type":"user","id":"u"},"action":"a","resource":{"type":"doc"}}`, "resource.id"},
		"not an object":       {`[1,2]`, "body"},
		"huge integer":        {`{"stream":"s","actor":{"type":"user","id":"u"},"action":"a","data":{"n":12345678901234567890}}`, "body"},
		"duplicate member":    {`{"stream":"s","stream":"t","actor":{"type":"user","id":"u"},"action":"a"}`, "body"},
		"too long actor id":   {`{"stream":"s","actor":{"type":"user","id":"` + strings.Repeat("x", 257) + `"},"action":"a"}`, "actor.id"},
	}
	for name, tc := range cases {
		_, err := decode(t, tc.body)
		if err == nil {
			t.Errorf("%s: expected a validation error", name)
			continue
		}
		if _, ok := fieldErrors(err)[tc.field]; !ok {
			t.Errorf("%s: expected an error for field %q, got %v", name, tc.field, err)
		}
	}
}

func TestDecodeBatch(t *testing.T) {
	tree, _, err := ParseRequestBody([]byte(`{"events":[
		{"stream":"a","actor":{"type":"user","id":"u"},"action":"x"},
		{"stream":"b","actor":{"type":"user"},"action":"y"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeBatch(tree, 10)
	if _, ok := fieldErrors(err)["events[1].actor.id"]; !ok {
		t.Fatalf("batch errors must carry the index: %v", err)
	}
	tree, _, _ = ParseRequestBody([]byte(`{"events":[]}`))
	if _, err := DecodeBatch(tree, 10); err == nil {
		t.Fatal("empty batch must be rejected")
	}
	tree, _, _ = ParseRequestBody([]byte(`{"events":[{},{},{}]}`))
	if _, err := DecodeBatch(tree, 2); err == nil {
		t.Fatal("oversized batch must be rejected")
	}
}

func TestRequestHashIgnoresFormatting(t *testing.T) {
	_, h1, _ := ParseRequestBody([]byte(`{"b":1,"a":[1,2]}`))
	_, h2, _ := ParseRequestBody([]byte("{ \"a\" : [1, 2],\n \"b\" : 1.0 }"))
	_, h3, _ := ParseRequestBody([]byte(`{"a":[2,1],"b":1}`))
	if h1 != h2 || h1 == h3 {
		t.Fatal("request hash must depend on meaning only")
	}
}

func TestDiff(t *testing.T) {
	var before, after any
	_ = json.Unmarshal([]byte(`{"status":"pending","owner":{"id":"u1","team":"legal"},"tags":["a"],"gone":true}`), &before)
	_ = json.Unmarshal([]byte(`{"status":"approved","owner":{"id":"u2","team":"legal"},"tags":["a","b"],"new/field":1}`), &after)
	got := Diff(before, after)
	want := []Change{
		{Op: OpRemove, Path: "/gone", From: true},
		{Op: OpAdd, Path: "/new~1field", To: 1.0},
		{Op: OpReplace, Path: "/owner/id", From: "u1", To: "u2"},
		{Op: OpReplace, Path: "/status", From: "pending", To: "approved"},
		{Op: OpReplace, Path: "/tags", From: []any{"a"}, To: []any{"a", "b"}},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d changes: %+v", len(got), got)
	}
	for i := range want {
		g, _ := json.Marshal(got[i].Tree())
		w, _ := json.Marshal(want[i].Tree())
		if string(g) != string(w) {
			t.Errorf("change %d: got %s want %s", i, g, w)
		}
	}
	// Creation and deletion produce per-member changes.
	if c := Diff(nil, map[string]any{"a": 1.0, "b": 2.0}); len(c) != 2 || c[0].Op != OpAdd {
		t.Fatalf("creation diff: %+v", c)
	}
	if c := Diff(map[string]any{"a": 1.0}, nil); len(c) != 1 || c[0].Op != OpRemove {
		t.Fatalf("deletion diff: %+v", c)
	}
	if c := Diff(map[string]any{"a": 1.0}, map[string]any{"a": 1.0}); len(c) != 0 {
		t.Fatalf("identical states: %+v", c)
	}
	if c := Diff("x", "y"); len(c) != 1 || c[0].Path != "" {
		t.Fatalf("scalar root: %+v", c)
	}
}

func prepareBody(t *testing.T, body string, s Settings) map[string]any {
	t.Helper()
	in, err := decode(t, body)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Prepare(in, s, 256*1024)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(p.Content, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPrepareRedactsSecretsBeforePersistence(t *testing.T) {
	body := `{"stream":"users","actor":{"type":"user","id":"u1"},"action":"user.updated",
		"before":{"email":"a@example.com","password":"hunter2-old","profile":{"apiKey":"k1","bio":"hi"}},
		"after":{"email":"b@example.com","password":"hunter2-new","profile":{"apiKey":"k2","bio":"hello"}},
		"data":{"Authorization":"Bearer abc","secretary":"Leyla"},
		"metadata":{"githubToken":"ghp_x","requestId":"r1"}}`
	c := prepareBody(t, body, DefaultSettings())
	raw, _ := json.Marshal(c)
	for _, secret := range []string{"hunter2", "k1", "k2", "Bearer abc", "ghp_x"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("secret %q survived redaction: %s", secret, raw)
		}
	}
	for _, kept := range []string{"a@example.com", "b@example.com", "Leyla", "r1", "hello"} {
		if !strings.Contains(string(raw), kept) {
			t.Fatalf("non-sensitive value %q was removed: %s", kept, raw)
		}
	}
	// The password change is still visible in the diff, without values.
	found := false
	for _, ch := range c["changes"].([]any) {
		m := ch.(map[string]any)
		if m["path"] == "/password" {
			found = m["from"] == RedactedValue && m["to"] == RedactedValue && m["op"] == OpReplace
		}
	}
	if !found {
		t.Fatalf("redacted change missing from diff: %v", c["changes"])
	}
	redactions := c["redactions"].([]any)
	if len(redactions) == 0 || redactions[0] != "/after/password" {
		t.Fatalf("redactions must be listed: %v", redactions)
	}
}

func TestPrepareRedactionModesAndPaths(t *testing.T) {
	body := `{"stream":"payments","actor":{"type":"service","id":"billing"},"action":"refund.issued",
		"data":{"card_number":"4111111111111111","customer":{"iban":"AZ21NABZ00000000137010001944","name":"Elvin"}}}`
	s := DefaultSettings()
	s.Redaction.Mode = RedactMask
	s.Redaction.Paths = []string{"/data/customer/iban"}
	c := prepareBody(t, body, s)
	data := c["data"].(map[string]any)
	if data["card_number"] != "************1111" {
		t.Fatalf("mask mode: %v", data["card_number"])
	}
	if iban := data["customer"].(map[string]any)["iban"]; iban != "************************1944" {
		t.Fatalf("path rule: %v", iban)
	}
	s.Redaction.Mode = RedactRemove
	c = prepareBody(t, body, s)
	if _, ok := c["data"].(map[string]any)["card_number"]; ok {
		t.Fatal("remove mode must drop the member")
	}
	s = DefaultSettings()
	s.Redaction.DisableDefaults = true
	c = prepareBody(t, body, s)
	if c["data"].(map[string]any)["card_number"] != "4111111111111111" {
		t.Fatal("defaults can be disabled explicitly")
	}
}

func TestPrepareDiffRetention(t *testing.T) {
	body := `{"stream":"cases","actor":{"type":"user","id":"u"},"action":"case.status_changed",
		"before":{"status":"open","assignee":"u1","notes":"long text"},"after":{"status":"closed","assignee":"u1","notes":"long text"}}`
	full := prepareBody(t, body, DefaultSettings())
	if full["before"] == nil || full["after"] == nil || len(full["changes"].([]any)) != 1 {
		t.Fatalf("full retention: %v", full)
	}
	s := DefaultSettings()
	s.RetainStates = RetainDiff
	diffOnly := prepareBody(t, body, s)
	if _, ok := diffOnly["before"]; ok {
		t.Fatal("diff retention must drop before")
	}
	if _, ok := diffOnly["after"]; ok {
		t.Fatal("diff retention must drop after")
	}
	if len(diffOnly["changes"].([]any)) != 1 {
		t.Fatalf("diff retention keeps changes: %v", diffOnly)
	}
}

func TestPrepareOmitsAbsentMembersAndKeepsNull(t *testing.T) {
	c := prepareBody(t, `{"stream":"docs","actor":{"type":"user","id":"u"},"action":"document.created","before":null,"after":{"title":"NDA"}}`, DefaultSettings())
	if v, ok := c["before"]; !ok || v != nil {
		t.Fatalf("explicit null must be kept: %v", c)
	}
	for _, absent := range []string{"resource", "data", "metadata", "context", "occurredAt", "redactions"} {
		if _, ok := c[absent]; ok {
			t.Errorf("absent member %q must be omitted", absent)
		}
	}
}

func TestPrepareSizeLimit(t *testing.T) {
	in, err := decode(t, `{"stream":"s","actor":{"type":"user","id":"u"},"action":"a","data":{"blob":"`+strings.Repeat("x", 2000)+`"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(in, DefaultSettings(), 1000); !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("expected ErrEventTooLarge, got %v", err)
	}
	s := DefaultSettings()
	s.MaxEventBytes = 500
	if _, err := Prepare(in, s, 1<<20); !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("project limit must apply, got %v", err)
	}
}

func TestSettingsValidation(t *testing.T) {
	if _, err := ParseSettings(json.RawMessage(`{"retainStates":"diff","redaction":{"keys":["iban"],"paths":["/after/x"],"mode":"mask"}}`)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{"retainStates":"none"}`, `{"redaction":{"mode":"hash"}}`,
		`{"redaction":{"paths":["/actor/id"]}}`, `{"unknown":true}`, `{"redaction":{"paths":["after/x"]}}`} {
		if _, err := ParseSettings(json.RawMessage(bad)); err == nil {
			t.Errorf("settings %s should be rejected", bad)
		}
	}
	s, err := ParseSettings(nil)
	if err != nil || s.RetainStates != RetainFull || s.Redaction.Mode != RedactReplace {
		t.Fatalf("defaults: %+v %v", s, err)
	}
}
