package store

import (
	"context"
	"encoding/json"
	"time"
)

// Tenant is an organization.
type Tenant struct {
	ID        string
	Slug      string
	Name      string
	CreatedAt time.Time
}

// Project groups streams, API keys and signing keys inside a tenant.
type Project struct {
	ID        string
	TenantID  string
	Slug      string
	Name      string
	Settings  json.RawMessage
	CreatedAt time.Time
}

// CreateTenant inserts a tenant.
func (s *Store) CreateTenant(ctx context.Context, db DBTX, t Tenant) error {
	_, err := db.Exec(ctx, `INSERT INTO tenants (id, slug, name, created_at) VALUES ($1, $2, $3, $4)`,
		t.ID, t.Slug, t.Name, t.CreatedAt)
	return mapErr(err)
}

// GetTenant returns a tenant by id.
func (s *Store) GetTenant(ctx context.Context, tenantID string) (Tenant, error) {
	var t Tenant
	err := s.Pool.QueryRow(ctx, `SELECT id, slug, name, created_at FROM tenants WHERE id = $1`, tenantID).
		Scan(&t.ID, &t.Slug, &t.Name, &t.CreatedAt)
	return t, mapErr(err)
}

// CountTenants returns the number of tenants (used to detect a fresh install).
func (s *Store) CountTenants(ctx context.Context) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM tenants`).Scan(&n)
	return n, err
}

// UpdateTenantName renames a tenant.
func (s *Store) UpdateTenantName(ctx context.Context, tenantID, name string) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE tenants SET name = $2 WHERE id = $1`, tenantID, name)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

const projectColumns = `id, tenant_id, slug, name, settings, created_at`

func scanProject(row interface{ Scan(...any) error }) (Project, error) {
	var p Project
	err := row.Scan(&p.ID, &p.TenantID, &p.Slug, &p.Name, &p.Settings, &p.CreatedAt)
	return p, mapErr(err)
}

// CreateProject inserts a project.
func (s *Store) CreateProject(ctx context.Context, db DBTX, p Project) error {
	settings := p.Settings
	if len(settings) == 0 {
		settings = json.RawMessage(`{}`)
	}
	_, err := db.Exec(ctx, `INSERT INTO projects (id, tenant_id, slug, name, settings, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, p.ID, p.TenantID, p.Slug, p.Name, settings, p.CreatedAt)
	return mapErr(err)
}

// GetProject returns a project of the tenant.
func (s *Store) GetProject(ctx context.Context, tenantID, projectID string) (Project, error) {
	return scanProject(s.Pool.QueryRow(ctx, `SELECT `+projectColumns+` FROM projects WHERE tenant_id = $1 AND id = $2`,
		tenantID, projectID))
}

// GetProjectBySlug returns a project of the tenant by slug.
func (s *Store) GetProjectBySlug(ctx context.Context, tenantID, slug string) (Project, error) {
	return scanProject(s.Pool.QueryRow(ctx, `SELECT `+projectColumns+` FROM projects WHERE tenant_id = $1 AND slug = $2`,
		tenantID, slug))
}

// FindProjectBySlug looks a project up by slug across tenants. It is meant for
// operator commands only, never for request handling.
func (s *Store) FindProjectBySlug(ctx context.Context, slug string) ([]Project, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+projectColumns+` FROM projects WHERE slug = $1 ORDER BY created_at`, slug)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListProjects returns the tenant's projects.
func (s *Store) ListProjects(ctx context.Context, tenantID string) ([]Project, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+projectColumns+` FROM projects WHERE tenant_id = $1 ORDER BY created_at`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListAllProjects returns every project (background jobs only).
func (s *Store) ListAllProjects(ctx context.Context) ([]Project, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+projectColumns+` FROM projects ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpdateProjectSettings replaces a project's settings document.
func (s *Store) UpdateProjectSettings(ctx context.Context, tenantID, projectID string, settings json.RawMessage) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE projects SET settings = $3 WHERE tenant_id = $1 AND id = $2`,
		tenantID, projectID, settings)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
