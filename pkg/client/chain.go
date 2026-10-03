package client

import (
	"context"

	"github.com/serxan22/delil/pkg/integrity"
	"github.com/serxan22/delil/pkg/verify"
)

// ChainPageSize is how many records ChainSource requests per page.
const ChainPageSize = 2000

// ChainSource pages through /v1/streams/{name}/chain and feeds the raw records
// to pkg/verify. After the first call to Next, Head, TenantID and ProjectID
// describe the stream as reported by the server.
type ChainSource struct {
	Client *Client
	Stream string

	Head      *verify.Head
	TenantID  string
	ProjectID string

	after int64
	done  bool
}

// Next returns the next page of records, or nil when the chain is exhausted.
func (s *ChainSource) Next(ctx context.Context) ([]verify.Item, error) {
	if s.done {
		return nil, nil
	}
	page, err := s.Client.Chain(ctx, s.Stream, s.after, ChainPageSize)
	if err != nil {
		return nil, err
	}
	if s.Head == nil {
		h, err := integrity.ParseHash(page.Head.Hash)
		if err != nil {
			return nil, err
		}
		s.Head = &verify.Head{Sequence: page.Head.Sequence, Hash: h}
		s.TenantID, s.ProjectID = page.TenantID, page.ProjectID
	}
	s.done = !page.HasMore
	s.after = page.NextAfterSequence
	items := make([]verify.Item, len(page.Records))
	for i := range page.Records {
		items[i] = verify.Item{Record: page.Records[i]}
	}
	return items, nil
}

// VerifyStreamLocal downloads a stream's raw chain and verifies it on this
// machine, so the result does not depend on trusting the server. opts supplies
// the trusted keys, checkpoints and witnesses; the tenant, project and head are
// taken from the server's first chain page, and content is required.
func (c *Client) VerifyStreamLocal(ctx context.Context, stream string, opts verify.StreamOptions) (*verify.Report, error) {
	src := &ChainSource{Client: c, Stream: stream}
	first, err := src.Next(ctx)
	if err != nil {
		return nil, err
	}
	opts.TenantID, opts.ProjectID, opts.Stream, opts.Head = src.TenantID, src.ProjectID, stream, src.Head
	opts.RequireContent = true
	v := verify.NewStreamVerifier(opts)
	v.Add(first)
	for {
		items, err := src.Next(ctx)
		if err != nil {
			return nil, err
		}
		if len(items) == 0 {
			return v.Finish(), nil
		}
		v.Add(items)
	}
}
