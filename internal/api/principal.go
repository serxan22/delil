package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/serxan22/delil/internal/auth"
	"github.com/serxan22/delil/internal/id"
	"github.com/serxan22/delil/internal/store"
)

// Principal kinds.
const (
	KindAPIKey  = "api_key"
	KindSession = "session"
)

// Principal is the authenticated caller.
type Principal struct {
	Kind      string
	TenantID  string
	ProjectID string
	Scopes    map[string]bool
	UserID    string
	SessionID string
	Role      string
	Email     string

	// actor is fixed when the principal is authenticated: "api_key:<record
	// id>" or "user:<id>". It never contains a secret.
	actor string
}

// Can reports whether the principal holds scope.
func (p *Principal) Can(scope string) bool { return p.Scopes[scope] }

// Actor identifies the principal in logs and history (never a secret).
func (p *Principal) Actor() string { return p.actor }

// RateKey groups requests for rate limiting.
func (p *Principal) RateKey() string { return p.Actor() }

type principalHolder struct{ p *Principal }

const ctxPrincipal ctxKey = 100

func setPrincipal(r *http.Request, p *Principal) {
	if h, ok := r.Context().Value(ctxPrincipal).(*principalHolder); ok {
		h.p = p
	}
}

func principalFrom(r *http.Request) *Principal {
	if h, ok := r.Context().Value(ctxPrincipal).(*principalHolder); ok {
		return h.p
	}
	return nil
}

func withPrincipalHolder(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxPrincipal, &principalHolder{})
}

var errBadCredentials = unauthorized("missing, invalid, expired or revoked credentials")

// authenticate resolves the bearer token to a principal. API keys and
// session tokens are distinguished by prefix; both are compared by hash.
func (s *Server) authenticate(r *http.Request) (*Principal, error) {
	header := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(header, "Bearer ")
	if !ok || token == "" {
		return nil, unauthorized("an Authorization: Bearer token is required")
	}
	ctx := r.Context()
	now := s.now()
	switch {
	case strings.HasPrefix(token, auth.APIKeyPrefix):
		lookup, ok := auth.ParseAPIKey(token)
		if !ok {
			return nil, errBadCredentials
		}
		k, err := s.store.GetAPIKeyByLookupID(ctx, lookup)
		if errors.Is(err, store.ErrNotFound) {
			return nil, errBadCredentials
		}
		if err != nil {
			return nil, err
		}
		if !auth.EqualHash(k.SecretHash, auth.HashToken(token)) || k.RevokedAt != nil ||
			(k.ExpiresAt != nil && now.After(*k.ExpiresAt)) {
			return nil, errBadCredentials
		}
		s.touch("key:"+k.ID, func(ctx context.Context, at time.Time) error { return s.store.TouchAPIKey(ctx, k.ID, at) })
		scopes := map[string]bool{}
		for _, sc := range k.Scopes {
			scopes[sc] = true
		}
		return &Principal{Kind: KindAPIKey, TenantID: k.TenantID, ProjectID: k.ProjectID, Scopes: scopes,
			actor: "api_key:" + k.ID}, nil

	case strings.HasPrefix(token, auth.SessionPrefix):
		if !auth.ValidSessionToken(token) {
			return nil, errBadCredentials
		}
		h := auth.HashToken(token)
		sess, user, err := s.store.GetActiveSession(ctx, h[:], now)
		if errors.Is(err, store.ErrNotFound) {
			return nil, errBadCredentials
		}
		if err != nil {
			return nil, err
		}
		s.touch("ses:"+sess.ID, func(ctx context.Context, at time.Time) error { return s.store.TouchSession(ctx, sess.ID, at) })
		scopes := map[string]bool{}
		for _, sc := range auth.RoleScopes[user.Role] {
			scopes[sc] = true
		}
		return &Principal{Kind: KindSession, TenantID: user.TenantID, Scopes: scopes, UserID: user.ID,
			SessionID: sess.ID, Role: user.Role, Email: user.Email, actor: "user:" + user.ID}, nil
	}
	return nil, errBadCredentials
}

// resolveProject binds the request to a project: the API key's own project,
// or for dashboard sessions the project named in the Delil-Project header,
// which must belong to the user's tenant.
func (s *Server) resolveProject(r *http.Request, p *Principal) error {
	if p.Kind == KindAPIKey {
		return nil
	}
	projectID := r.Header.Get("Delil-Project")
	if projectID == "" {
		return badRequest("the Delil-Project header is required for dashboard sessions")
	}
	if !id.Valid(id.Project, projectID) {
		return notFound("project")
	}
	if _, err := s.store.GetProject(r.Context(), p.TenantID, projectID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return notFound("project")
		}
		return err
	}
	p.ProjectID = projectID
	return nil
}
