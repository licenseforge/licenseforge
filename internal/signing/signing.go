// Package signing holds tenants' license signing keys (ADR-0026).
//
// Signer is what license issuing depends on. Local, the v0.1 implementation,
// keeps each private key in the database encrypted with the master keyring
// (ADR-0025); KMS/HSM signers (v0.4) implement the same interface, and the
// private key then never exists in LicenseForge memory.
package signing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"licenseforge.io/licenseforge/internal/secrets"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/signingkey"
	"licenseforge.io/licenseforge/internal/store/ids"
)

var (
	// ErrNotActive means the key exists but may not sign: it is pending or
	// retired. After a rotation, read the active kid again and rebuild the
	// message.
	ErrNotActive = errors.New("signing: key is not active")
	// ErrNoActiveKey means the tenant has no active key yet.
	ErrNoActiveKey = errors.New("signing: tenant has no active key")
)

// Signer signs for one tenant's keys. msg is the full signed message,
// "lf1.<kid>.<payload>" (License File Format), so the kid is chosen first.
type Signer interface {
	Sign(ctx context.Context, tenantID, kid string, msg []byte) ([]byte, error)
	Public(ctx context.Context, tenantID, kid string) (PublicKey, error)
}

// PublicKey is a trusted-key entry as vendors embed it in their builds
// (License File Format: kid, alg, key).
type PublicKey struct {
	KID string
	Alg string
	Key []byte
}

// PurposeSigningKey binds private key ciphertexts (ADR-0025).
const PurposeSigningKey secrets.Purpose = "signing_key"

// Local keeps private keys in the database, encrypted with Keys.
type Local struct {
	DB   *store.DB
	Keys *secrets.Keyring
}

var _ Signer = Local{}

func binding(tenantID, kid string) secrets.Binding {
	return secrets.Binding{Purpose: PurposeSigningKey, TenantID: tenantID, RowID: kid}
}

// Create generates a key: active if the tenant has none yet, else pending
// (published for vendors to trust, then Promote). It fails if the tenant
// already has a pending key.
func (l Local) Create(ctx context.Context, tenantID string) (*ent.SigningKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	kid := ids.SigningKey()
	ct, err := l.Keys.Encrypt(priv.Seed(), binding(tenantID, kid))
	if err != nil {
		return nil, err
	}
	var k *ent.SigningKey
	err = l.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		hasActive, err := tx.SigningKey.Query().Where(signingkey.StatusEQ(signingkey.StatusActive)).Exist(ctx)
		if err != nil {
			return err
		}
		c := tx.SigningKey.Create().SetID(kid).SetTenantID(tenantID).SetAlg(signingkey.AlgEd25519).
			SetPublicKey(pub).SetPrivateKeyCiphertext(ct).SetStatus(signingkey.StatusPending)
		if !hasActive {
			c.SetStatus(signingkey.StatusActive).SetActivatedAt(time.Now())
		}
		k, err = c.Save(ctx)
		return err
	})
	return k, err
}

// Promote makes the pending key kid active and retires the active one,
// destroying its private key. Vendor builds that don't trust kid reject
// everything signed afterwards (ADR-0026).
func (l Local) Promote(ctx context.Context, tenantID, kid string) error {
	return l.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		now := time.Now()
		// Lock the tenant's active and pending keys, so concurrent promotions
		// serialize instead of racing on the unique index.
		keys, err := tx.SigningKey.Query().
			Where(signingkey.StatusIn(signingkey.StatusActive, signingkey.StatusPending)).
			ForUpdate().All(ctx)
		if err != nil {
			return err
		}
		var pending, active *ent.SigningKey
		for _, k := range keys {
			if k.Status == signingkey.StatusPending {
				pending = k
			} else {
				active = k
			}
		}
		if pending == nil || pending.ID != kid {
			return fmt.Errorf("signing: %s is not the pending key", kid)
		}
		if active != nil {
			if err := retire(ctx, tx, active.ID, now); err != nil {
				return err
			}
		}
		return tx.SigningKey.UpdateOneID(kid).SetStatus(signingkey.StatusActive).SetActivatedAt(now).Exec(ctx)
	})
}

// Discard retires the pending key kid without it ever signing (rotation
// abandoned, or the pending key leaked).
func (l Local) Discard(ctx context.Context, tenantID, kid string) error {
	return l.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		n, err := tx.SigningKey.Update().
			Where(signingkey.ID(kid), signingkey.StatusEQ(signingkey.StatusPending)).
			SetStatus(signingkey.StatusRetired).SetRetiredAt(time.Now()).ClearPrivateKeyCiphertext().Save(ctx)
		if err == nil && n == 0 {
			err = fmt.Errorf("signing: %s is not the pending key", kid)
		}
		return err
	})
}

func retire(ctx context.Context, tx *ent.Tx, kid string, now time.Time) error {
	return tx.SigningKey.UpdateOneID(kid).SetStatus(signingkey.StatusRetired).SetRetiredAt(now).
		ClearPrivateKeyCiphertext().Exec(ctx)
}

// Active returns the tenant's active kid.
func (l Local) Active(ctx context.Context, tenantID string) (string, error) {
	var kid string
	err := l.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		var err error
		kid, err = tx.SigningKey.Query().Where(signingkey.StatusEQ(signingkey.StatusActive)).OnlyID(ctx)
		if ent.IsNotFound(err) {
			return ErrNoActiveKey
		}
		return err
	})
	return kid, err
}

// Sign signs msg with the tenant's key kid, which must be active.
func (l Local) Sign(ctx context.Context, tenantID, kid string, msg []byte) ([]byte, error) {
	k, err := l.key(ctx, tenantID, kid)
	if err != nil {
		return nil, err
	}
	if k.Status != signingkey.StatusActive || k.PrivateKeyCiphertext == nil {
		return nil, ErrNotActive
	}
	seed, err := l.Keys.Decrypt(*k.PrivateKeyCiphertext, binding(tenantID, kid))
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("signing: bad private key")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	// The stored public key is what vendors trust; refuse a private key that
	// doesn't match it rather than sign files nobody can verify.
	if !priv.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(k.PublicKey)) {
		return nil, errors.New("signing: private key doesn't match public key")
	}
	return ed25519.Sign(priv, msg), nil
}

// Public returns the trusted-key entry for kid (any status), as vendors
// embed it.
func (l Local) Public(ctx context.Context, tenantID, kid string) (PublicKey, error) {
	k, err := l.key(ctx, tenantID, kid)
	if err != nil {
		return PublicKey{}, err
	}
	return PublicKey{KID: k.ID, Alg: string(k.Alg), Key: k.PublicKey}, nil
}

func (l Local) key(ctx context.Context, tenantID, kid string) (*ent.SigningKey, error) {
	var k *ent.SigningKey
	err := l.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		var err error
		k, err = tx.SigningKey.Get(ctx, kid)
		return err
	})
	return k, err
}
