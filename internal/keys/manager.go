package keys

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serxan22/delil/internal/store"
	"github.com/serxan22/delil/pkg/integrity"
)

// ErrNoActiveKey means the project has no active signing key.
var ErrNoActiveKey = errors.New("keys: project has no active signing key")

// Manager creates, rotates and revokes keys and caches signers.
type Manager struct {
	store     *store.Store
	provider  Provider
	providers map[string]Provider
	now       func() time.Time

	mu      sync.Mutex
	signers map[string]integrity.Signer
}

// NewManager uses provider for new keys. Keys created earlier by other
// providers can still be used if those providers are passed in others.
func NewManager(st *store.Store, provider Provider, others ...Provider) *Manager {
	m := &Manager{
		store:     st,
		provider:  provider,
		providers: map[string]Provider{provider.Name(): provider},
		now:       time.Now,
		signers:   make(map[string]integrity.Signer),
	}
	for _, p := range others {
		m.providers[p.Name()] = p
	}
	return m
}

// SetClock overrides the clock (tests and demo data).
func (m *Manager) SetClock(now func() time.Time) { m.now = now }

// ProviderName returns the provider used for new keys.
func (m *Manager) ProviderName() string { return m.provider.Name() }

func (m *Manager) newKeyRecord(ctx context.Context, tenantID, projectID string, at time.Time) (store.SigningKey, error) {
	gen, err := m.provider.Generate(ctx, tenantID, projectID)
	if err != nil {
		return store.SigningKey{}, fmt.Errorf("keys: generate: %w", err)
	}
	return store.SigningKey{
		ID:                integrity.KeyIDFor(gen.PublicKey),
		TenantID:          tenantID,
		ProjectID:         projectID,
		Algorithm:         integrity.AlgorithmEd25519,
		PublicKey:         gen.PublicKey,
		Fingerprint:       integrity.Fingerprint(gen.PublicKey),
		Provider:          m.provider.Name(),
		ProviderRef:       gen.ProviderRef,
		WrappedPrivateKey: gen.WrappedPrivateKey,
		Status:            integrity.KeyStatusActive,
		CreatedAt:         at,
		ActivatedAt:       at,
	}, nil
}

// CreateInitialKey creates the first active key of a new project inside tx.
func (m *Manager) CreateInitialKey(ctx context.Context, tx pgx.Tx, tenantID, projectID string) (store.SigningKey, error) {
	rec, err := m.newKeyRecord(ctx, tenantID, projectID, m.now().UTC().Truncate(time.Microsecond))
	if err != nil {
		return store.SigningKey{}, err
	}
	if err := m.store.InsertSigningKey(ctx, tx, rec); err != nil {
		return store.SigningKey{}, err
	}
	return rec, nil
}

// EnsureActiveKey returns the project's active key, creating one if needed.
func (m *Manager) EnsureActiveKey(ctx context.Context, tenantID, projectID string) (store.SigningKey, error) {
	k, err := m.store.GetActiveSigningKey(ctx, tenantID, projectID)
	if err == nil {
		return k, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.SigningKey{}, err
	}
	err = m.store.InTx(ctx, func(tx pgx.Tx) error {
		_, err := m.CreateInitialKey(ctx, tx, tenantID, projectID)
		return err
	})
	if err != nil && !errors.Is(err, store.ErrConflict) {
		return store.SigningKey{}, err
	}
	// Either we created it or a concurrent caller did.
	return m.store.GetActiveSigningKey(ctx, tenantID, projectID)
}

// Signer returns a cached signer for the key id.
func (m *Manager) Signer(ctx context.Context, keyID string) (integrity.Signer, error) {
	m.mu.Lock()
	s, ok := m.signers[keyID]
	m.mu.Unlock()
	if ok {
		return s, nil
	}
	rec, err := m.store.GetSigningKeyMaterial(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("keys: load %s: %w", keyID, err)
	}
	if rec.Status == integrity.KeyStatusRevoked {
		return nil, fmt.Errorf("keys: key %s is revoked", keyID)
	}
	p, ok := m.providers[rec.Provider]
	if !ok {
		return nil, fmt.Errorf("keys: key %s uses provider %q, which is not configured", keyID, rec.Provider)
	}
	s, err = p.Signer(ctx, rec)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.signers[keyID] = s
	m.mu.Unlock()
	return s, nil
}

func (m *Manager) forget(keyID string) {
	m.mu.Lock()
	delete(m.signers, keyID)
	m.mu.Unlock()
}

// RotationResult describes a completed rotation.
type RotationResult struct {
	Previous store.SigningKey
	Current  store.SigningKey
}

// Rotate replaces the project's active key. It locks the active key FOR
// UPDATE, which waits for in-flight appends (they hold FOR KEY SHARE), so no
// event is signed by the old key after it is retired. The old key's window is
// closed at the later of now and its newest event, and the new key's window
// starts there, so the windows are contiguous.
func (m *Manager) Rotate(ctx context.Context, tenantID, projectID string) (RotationResult, error) {
	var res RotationResult
	err := m.store.InTx(ctx, func(tx pgx.Tx) error {
		old, err := m.store.ActiveSigningKeyForUpdate(ctx, tx, tenantID, projectID)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNoActiveKey
		}
		if err != nil {
			return err
		}
		at := m.now().UTC().Truncate(time.Microsecond)
		latest, err := m.store.LatestRecordedAtForKey(ctx, tx, old.ID)
		if err != nil {
			return err
		}
		if latest != nil && latest.After(at) {
			at = latest.UTC()
		}
		if err := m.store.RetireSigningKey(ctx, tx, old.ID, at); err != nil {
			return err
		}
		rec, err := m.newKeyRecord(ctx, tenantID, projectID, at)
		if err != nil {
			return err
		}
		if err := m.store.InsertSigningKey(ctx, tx, rec); err != nil {
			return err
		}
		old.Status = integrity.KeyStatusRetired
		old.RetiredAt = &at
		res = RotationResult{Previous: old, Current: rec}
		return nil
	})
	if err == nil {
		m.forget(res.Previous.ID)
	}
	return res, err
}

// Revoke marks a key as compromised. If it is the active key a new key is
// created in the same transaction so ingestion can continue.
func (m *Manager) Revoke(ctx context.Context, tenantID, projectID, keyID, reason string) (*store.SigningKey, error) {
	var replacement *store.SigningKey
	err := m.store.InTx(ctx, func(tx pgx.Tx) error {
		active, err := m.store.ActiveSigningKeyForUpdate(ctx, tx, tenantID, projectID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		revokingActive := err == nil && active.ID == keyID
		at := m.now().UTC().Truncate(time.Microsecond)
		if err := m.store.RevokeSigningKey(ctx, tx, tenantID, projectID, keyID, reason, at); err != nil {
			return err
		}
		if revokingActive {
			rec, err := m.newKeyRecord(ctx, tenantID, projectID, at)
			if err != nil {
				return err
			}
			if err := m.store.InsertSigningKey(ctx, tx, rec); err != nil {
				return err
			}
			replacement = &rec
		}
		return nil
	})
	if err == nil {
		m.forget(keyID)
	}
	return replacement, err
}

// KeySet returns every valid key of the project as a verification set, plus
// the key records that failed validation.
func (m *Manager) KeySet(ctx context.Context, tenantID, projectID string) (*integrity.KeySet, []integrity.KeyProblem, error) {
	pks, err := m.store.PublicKeys(ctx, tenantID, projectID)
	if err != nil {
		return nil, nil, err
	}
	set, problems := integrity.NewKeySetLenient(pks...)
	return set, problems, nil
}
