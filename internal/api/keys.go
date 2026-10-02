package api

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/serxan22/delil/internal/auth"
	"github.com/serxan22/delil/internal/id"
	"github.com/serxan22/delil/internal/store"
	"github.com/serxan22/delil/pkg/evidence"
	"github.com/serxan22/delil/pkg/integrity"
)

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

type createAPIKeyRequest struct {
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	ExpiresAt string   `json:"expiresAt"`
}

func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request, p *Principal) error {
	var req createAPIKeyRequest
	if err := decodeJSON(w, r, 16<<10, &req); err != nil {
		return err
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 100 {
		return badRequest("name is required (at most 100 characters)")
	}
	scopes, err := auth.NormalizeScopes(req.Scopes)
	if err != nil {
		return badRequest("%v", err)
	}
	// No privilege escalation: an API key can only mint keys with scopes it
	// holds itself. Dashboard admins may grant any API key scope.
	if p.Kind == KindAPIKey {
		for _, sc := range scopes {
			if !p.Can(sc) {
				return forbidden("cannot grant scope %q that this key does not hold", sc)
			}
		}
	}
	var expires *time.Time
	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil || !t.After(s.now()) {
			return badRequest("expiresAt must be a future RFC 3339 timestamp")
		}
		u := t.UTC()
		expires = &u
	}
	raw, lookup, hash := auth.NewAPIKey()
	k := store.APIKey{ID: id.New(id.APIKey), TenantID: p.TenantID, ProjectID: p.ProjectID, Name: req.Name,
		LookupID: lookup, SecretHash: hash[:], Scopes: scopes, CreatedBy: p.Actor(), CreatedAt: s.now().UTC(),
		ExpiresAt: expires}
	if err := s.store.CreateAPIKey(r.Context(), s.store.Pool, k); err != nil {
		return err
	}
	view := renderAPIKey(k)
	view.Secret = raw
	writeJSON(w, http.StatusCreated, view)
	return nil
}

func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request, p *Principal) error {
	ks, err := s.store.ListAPIKeys(r.Context(), p.TenantID, p.ProjectID)
	if err != nil {
		return err
	}
	views := make([]apiKeyView, 0, len(ks))
	for _, k := range ks {
		views = append(views, renderAPIKey(k))
	}
	writeJSON(w, http.StatusOK, list(views))
	return nil
}

func (s *Server) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request, p *Principal) error {
	keyID := r.PathValue("id")
	if !id.Valid(id.APIKey, keyID) {
		return notFound("API key")
	}
	k, err := s.store.RevokeAPIKey(r.Context(), p.TenantID, p.ProjectID, keyID, s.now().UTC())
	if errors.Is(err, store.ErrNotFound) {
		return notFound("API key")
	}
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, renderAPIKey(k))
	return nil
}

func (s *Server) handleListSigningKeys(w http.ResponseWriter, r *http.Request, p *Principal) error {
	ks, err := s.store.ListSigningKeys(r.Context(), p.TenantID, p.ProjectID)
	if err != nil {
		return err
	}
	views := make([]signingKeyView, 0, len(ks))
	for _, k := range ks {
		views = append(views, renderSigningKey(k))
	}
	writeJSON(w, http.StatusOK, list(views))
	return nil
}

// handleExportSigningKeys returns the public keys in the trusted-keys file
// format used by `delil verify --trusted-keys` and evidence packages.
func (s *Server) handleExportSigningKeys(w http.ResponseWriter, r *http.Request, p *Principal) error {
	keys, err := s.store.PublicKeys(r.Context(), p.TenantID, p.ProjectID)
	if err != nil {
		return err
	}
	if keys == nil {
		keys = []integrity.PublicKey{}
	}
	writeJSON(w, http.StatusOK, evidence.KeysFile{Keys: keys})
	return nil
}

func (s *Server) handleRotateSigningKey(w http.ResponseWriter, r *http.Request, p *Principal) error {
	res, err := s.keys.Rotate(r.Context(), p.TenantID, p.ProjectID)
	if err != nil {
		return err
	}
	s.log.Info("signing key rotated", "project_id", p.ProjectID, "previous", res.Previous.ID, "current", res.Current.ID,
		"by", p.Actor())
	writeJSON(w, http.StatusOK, map[string]any{
		"object":   "key_rotation",
		"previous": renderSigningKey(res.Previous),
		"current":  renderSigningKey(res.Current),
	})
	return nil
}

type revokeKeyRequest struct {
	Reason string `json:"reason"`
}

func (s *Server) handleRevokeSigningKey(w http.ResponseWriter, r *http.Request, p *Principal) error {
	keyID := r.PathValue("id")
	var req revokeKeyRequest
	if err := decodeJSON(w, r, 16<<10, &req); err != nil {
		return err
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" || len(req.Reason) > 500 {
		return badRequest("reason is required (at most 500 characters)")
	}
	replacement, err := s.keys.Revoke(r.Context(), p.TenantID, p.ProjectID, keyID, req.Reason)
	if errors.Is(err, store.ErrNotFound) {
		return notFound("signing key")
	}
	if err != nil {
		return err
	}
	s.log.Warn("signing key revoked", "project_id", p.ProjectID, "key_id", keyID, "by", p.Actor())
	resp := map[string]any{"object": "key_revocation", "revoked": keyID, "replacement": nil}
	if replacement != nil {
		resp["replacement"] = renderSigningKey(*replacement)
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}
