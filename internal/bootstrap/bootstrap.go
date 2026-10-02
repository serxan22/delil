// Package bootstrap creates the first organization, project, administrator
// and API key of a fresh installation.
package bootstrap

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serxan22/delil/internal/api"
	"github.com/serxan22/delil/internal/app"
	"github.com/serxan22/delil/internal/auth"
	"github.com/serxan22/delil/internal/id"
	"github.com/serxan22/delil/internal/store"
)

// Options configure the bootstrap.
type Options struct {
	OrgName       string
	ProjectName   string
	AdminEmail    string
	AdminPassword string
	// KeyActivation backdates the first signing key (demo data only).
	KeyActivation time.Time
}

// Result describes what was created. Secrets are only populated when they
// were generated during this call and must be shown to the operator once.
type Result struct {
	Created           bool
	TenantID          string
	ProjectID         string
	AdminEmail        string
	AdminPassword     string
	PasswordGenerated bool
	APIKey            string
}

// Run bootstraps an empty installation. If any tenant exists it does nothing.
func Run(ctx context.Context, a *app.App, opts Options) (Result, error) {
	n, err := a.Store.CountTenants(ctx)
	if err != nil || n > 0 {
		return Result{}, err
	}
	now := time.Now().UTC()
	keyAt := now
	if !opts.KeyActivation.IsZero() {
		keyAt = opts.KeyActivation
	}
	res := Result{Created: true, AdminEmail: opts.AdminEmail, AdminPassword: opts.AdminPassword}
	if res.AdminPassword == "" {
		res.AdminPassword = auth.GeneratePassword()
		res.PasswordGenerated = true
	}
	if err := auth.CheckPasswordPolicy(res.AdminPassword); err != nil {
		return Result{}, err
	}
	hash, err := auth.HashPassword(res.AdminPassword)
	if err != nil {
		return Result{}, err
	}
	tenant := store.Tenant{ID: id.New(id.Tenant), Slug: api.Slugify(opts.OrgName), Name: opts.OrgName, CreatedAt: keyAt}
	project := store.Project{ID: id.New(id.Project), TenantID: tenant.ID, Slug: api.Slugify(opts.ProjectName),
		Name: opts.ProjectName, CreatedAt: keyAt}
	raw, lookup, keyHash := auth.NewAPIKey()
	err = a.Store.InTx(ctx, func(tx pgx.Tx) error {
		if err := a.Store.CreateTenant(ctx, tx, tenant); err != nil {
			return err
		}
		if err := a.Store.CreateProject(ctx, tx, project); err != nil {
			return err
		}
		if _, err := a.Keys.CreateInitialKeyAt(ctx, tx, tenant.ID, project.ID, keyAt); err != nil {
			return err
		}
		if err := a.Store.CreateUser(ctx, tx, store.User{ID: id.New(id.User), TenantID: tenant.ID, Email: opts.AdminEmail,
			DisplayName: "Administrator", PasswordHash: hash, Role: auth.RoleAdmin, CreatedAt: now}); err != nil {
			return err
		}
		return a.Store.CreateAPIKey(ctx, tx, store.APIKey{ID: id.New(id.APIKey), TenantID: tenant.ID, ProjectID: project.ID,
			Name: "Bootstrap key", LookupID: lookup, SecretHash: keyHash[:], Scopes: auth.APIKeyScopes,
			CreatedBy: "system:bootstrap", CreatedAt: now})
	})
	if err != nil {
		return Result{}, err
	}
	res.TenantID, res.ProjectID, res.APIKey = tenant.ID, project.ID, raw
	return res, nil
}
