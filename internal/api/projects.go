package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/serxan22/delil/internal/audit"
	"github.com/serxan22/delil/internal/auth"
	"github.com/serxan22/delil/internal/id"
	"github.com/serxan22/delil/internal/store"
)

var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Slugify derives a slug from a display name.
func Slugify(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > 63 {
		s = strings.Trim(s[:63], "-")
	}
	if s == "" {
		s = "project"
	}
	return s
}

func (s *Server) handleGetProject(w http.ResponseWriter, r *http.Request, p *Principal) error {
	pr, err := s.store.GetProject(r.Context(), p.TenantID, p.ProjectID)
	if err != nil {
		return err
	}
	settings, err := audit.ParseSettings(pr.Settings)
	if err != nil {
		return err
	}
	tenant, err := s.store.GetTenant(r.Context(), p.TenantID)
	if err != nil {
		return err
	}
	v := renderProject(pr, settings)
	v.Tenant = &tenantView{ID: tenant.ID, Slug: tenant.Slug, Name: tenant.Name}
	writeJSON(w, http.StatusOK, v)
	return nil
}

type updateProjectRequest struct {
	Name     *string          `json:"name"`
	Settings *json.RawMessage `json:"settings"`
}

func (s *Server) handleUpdateProject(w http.ResponseWriter, r *http.Request, p *Principal) error {
	var req updateProjectRequest
	if err := decodeJSON(w, r, 64<<10, &req); err != nil {
		return err
	}
	if req.Settings != nil {
		settings, err := audit.ParseSettings(*req.Settings)
		if err != nil {
			return badRequest("%v", err)
		}
		normalized, _ := json.Marshal(settings)
		if err := s.store.UpdateProjectSettings(r.Context(), p.TenantID, p.ProjectID, normalized); err != nil {
			return err
		}
	}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" || len(name) > 200 {
			return badRequest("name must be 1-200 characters")
		}
		if _, err := s.store.Pool.Exec(r.Context(), `UPDATE projects SET name = $3 WHERE tenant_id = $1 AND id = $2`,
			p.TenantID, p.ProjectID, name); err != nil {
			return err
		}
	}
	return s.handleGetProject(w, r, p)
}

func (s *Server) handleListProjects(w http.ResponseWriter, r *http.Request, p *Principal) error {
	projects, err := s.store.ListProjects(r.Context(), p.TenantID)
	if err != nil {
		return err
	}
	views := make([]projectView, 0, len(projects))
	for _, pr := range projects {
		views = append(views, renderProject(pr, nil))
	}
	writeJSON(w, http.StatusOK, list(views))
	return nil
}

type createProjectRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

func (s *Server) handleCreateProject(w http.ResponseWriter, r *http.Request, p *Principal) error {
	var req createProjectRequest
	if err := decodeJSON(w, r, 16<<10, &req); err != nil {
		return err
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 200 {
		return badRequest("name must be 1-200 characters")
	}
	if req.Slug == "" {
		req.Slug = Slugify(req.Name)
	}
	if !slugPattern.MatchString(req.Slug) {
		return badRequest("slug must match %s", slugPattern.String())
	}
	pr := store.Project{ID: id.New(id.Project), TenantID: p.TenantID, Slug: req.Slug, Name: req.Name, CreatedAt: s.now().UTC()}
	err := s.store.InTx(r.Context(), func(tx pgx.Tx) error {
		if err := s.store.CreateProject(r.Context(), tx, pr); err != nil {
			return err
		}
		_, err := s.keys.CreateInitialKey(r.Context(), tx, p.TenantID, pr.ID)
		return err
	})
	if errors.Is(err, store.ErrConflict) {
		return errorf(http.StatusConflict, "conflict", "a project with slug %q already exists", req.Slug)
	}
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, renderProject(pr, audit.DefaultSettings()))
	return nil
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request, p *Principal) error {
	users, err := s.store.ListUsers(r.Context(), p.TenantID)
	if err != nil {
		return err
	}
	views := make([]userView, 0, len(users))
	for _, u := range users {
		views = append(views, renderUser(u))
	}
	writeJSON(w, http.StatusOK, list(views))
	return nil
}

type createUserRequest struct {
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	Role        string `json:"role"`
	Password    string `json:"password"`
}

var emailPattern = regexp.MustCompile(`^[^@\s]{1,64}@[^@\s]{1,255}$`)

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request, p *Principal) error {
	var req createUserRequest
	if err := decodeJSON(w, r, 16<<10, &req); err != nil {
		return err
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !emailPattern.MatchString(email) {
		return badRequest("a valid email is required")
	}
	if !auth.ValidRole(req.Role) {
		return badRequest("role must be admin, auditor or viewer")
	}
	name := strings.TrimSpace(req.DisplayName)
	if name == "" || len(name) > 200 {
		return badRequest("displayName must be 1-200 characters")
	}
	if err := auth.CheckPasswordPolicy(req.Password); err != nil {
		return badRequest("%v", err)
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		return err
	}
	u := store.User{ID: id.New(id.User), TenantID: p.TenantID, Email: email, DisplayName: name, PasswordHash: hash,
		Role: req.Role, CreatedAt: s.now().UTC()}
	if err := s.store.CreateUser(r.Context(), s.store.Pool, u); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return errorf(http.StatusConflict, "conflict", "a user with this email already exists")
		}
		return err
	}
	writeJSON(w, http.StatusCreated, renderUser(u))
	return nil
}
