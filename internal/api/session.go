package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/serxan22/delil/internal/auth"
	"github.com/serxan22/delil/internal/id"
	"github.com/serxan22/delil/internal/store"
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type sessionView struct {
	Object    string        `json:"object"`
	Token     string        `json:"token,omitempty"`
	ExpiresAt string        `json:"expiresAt"`
	User      userView      `json:"user"`
	Tenant    tenantView    `json:"tenant"`
	Projects  []projectView `json:"projects"`
}

var errInvalidLogin = unauthorized("invalid email or password")

// handleLogin exchanges credentials for a session token. Responses do not
// reveal whether the email exists, timing is equalised for unknown users,
// and attempts are rate limited per client IP and per email.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := s.login(w, r); err != nil {
		s.writeError(w, r, err)
	}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) error {
	if ok, retry := s.loginByIP.Allow("ip:" + clientIP(r.Context())); !ok {
		e := errorf(http.StatusTooManyRequests, "rate_limited", "too many login attempts; try again later")
		e.RetryAfter = retry
		return e
	}
	var req loginRequest
	if err := decodeJSON(w, r, 8<<10, &req); err != nil {
		return err
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if ok, retry := s.loginByEmail.Allow("email:" + email); !ok {
		e := errorf(http.StatusTooManyRequests, "rate_limited", "too many login attempts; try again later")
		e.RetryAfter = retry
		return e
	}
	if email == "" || req.Password == "" || len(req.Password) > auth.MaxPasswordLength*4 {
		return errInvalidLogin
	}
	user, err := s.store.GetUserByEmail(r.Context(), email)
	if errors.Is(err, store.ErrNotFound) {
		auth.EqualiseTiming(req.Password)
		return errInvalidLogin
	}
	if err != nil {
		return err
	}
	ok, err := auth.VerifyPassword(user.PasswordHash, req.Password)
	if err != nil || !ok || user.DisabledAt != nil {
		s.log.Info("login failed", "user_id", user.ID, "client_ip", clientIP(r.Context()))
		return errInvalidLogin
	}
	token, hash := auth.NewSessionToken()
	now := s.now().UTC()
	sess := store.Session{ID: id.New(id.Session), TokenHash: hash[:], UserID: user.ID, TenantID: user.TenantID,
		CreatedAt: now, ExpiresAt: now.Add(s.cfg.SessionTTL), LastSeenAt: now, IP: clientIP(r.Context()),
		UserAgent: truncate(r.Header.Get("X-Delil-User-Agent"), 512)}
	if err := s.store.CreateSession(r.Context(), sess); err != nil {
		return err
	}
	_ = s.store.TouchUserLogin(r.Context(), user.ID, now)
	view, err := s.sessionView(r, user, sess)
	if err != nil {
		return err
	}
	view.Token = token
	s.log.Info("login succeeded", "user_id", user.ID, "session_id", sess.ID)
	writeJSON(w, http.StatusOK, view)
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (s *Server) sessionView(r *http.Request, user store.User, sess store.Session) (sessionView, error) {
	tenant, err := s.store.GetTenant(r.Context(), user.TenantID)
	if err != nil {
		return sessionView{}, err
	}
	projects, err := s.store.ListProjects(r.Context(), user.TenantID)
	if err != nil {
		return sessionView{}, err
	}
	pv := make([]projectView, 0, len(projects))
	for _, p := range projects {
		pv = append(pv, renderProject(p, nil))
	}
	return sessionView{Object: "session", ExpiresAt: ts(sess.ExpiresAt), User: renderUser(user),
		Tenant: tenantView{ID: tenant.ID, Slug: tenant.Slug, Name: tenant.Name}, Projects: pv}, nil
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, p *Principal) error {
	if err := s.store.RevokeSession(r.Context(), p.SessionID, s.now().UTC()); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request, p *Principal) error {
	token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	h := auth.HashToken(token)
	sess, user, err := s.store.GetActiveSession(r.Context(), h[:], s.now())
	if err != nil {
		return err
	}
	view, err := s.sessionView(r, user, sess)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, view)
	return nil
}

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, p *Principal) error {
	var req changePasswordRequest
	if err := decodeJSON(w, r, 8<<10, &req); err != nil {
		return err
	}
	user, err := s.store.GetUser(r.Context(), p.TenantID, p.UserID)
	if err != nil {
		return err
	}
	if ok, err := auth.VerifyPassword(user.PasswordHash, req.CurrentPassword); err != nil || !ok {
		return errorf(http.StatusForbidden, "invalid_password", "the current password is incorrect")
	}
	if err := auth.CheckPasswordPolicy(req.NewPassword); err != nil {
		return badRequest("%v", err)
	}
	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		return err
	}
	if err := s.store.SetUserPassword(r.Context(), p.TenantID, p.UserID, hash); err != nil {
		return err
	}
	if err := s.store.RevokeOtherSessions(r.Context(), p.UserID, p.SessionID, s.now().UTC()); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
