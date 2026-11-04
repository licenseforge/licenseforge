// Package signing holds tenants' license signing keys (ADR-0026).
//
// Signer is what license issuing depends on. Local, the v0.1 implementation,
// keeps each private key in the database encrypted with the master keyring
// (ADR-0025); KMS/HSM signers (v0.4) implement the same interface, and the
// private key then never exists in LicenseForge memory.
package signing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql/sqlgraph"

	"licenseforge.io/licenseforge/internal/authz"
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
	// ErrNoActiveKey means the tenant has no active key.
	ErrNoActiveKey = errors.New("signing: tenant has no active key")
	// ErrPendingExists means the tenant already has a pending key (or a
	// concurrent Create won); promote or discard it first.
	ErrPendingExists = errors.New("signing: tenant already has a pending key")
	// ErrNotPending means the key isn't the tenant's pending key.
	ErrNotPending = errors.New("signing: key is not the pending key")
	// ErrWrongMessage means msg isn't an lf1 message for this kid.
	ErrWrongMessage = errors.New("signing: message is not lf1.<kid>.<payload>")
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

// authorize refuses (authz.ErrDenied) unless ctx's principal may manage the
// signing keys of tenantID: key:write (owners, ADR-0019) on the whole tenant,
// so a product-scoped principal is refused, acting in that same tenant.
func authorize(ctx context.Context, tenantID string) error {
	if err := authz.Require(ctx, authz.KeyWrite, ""); err != nil {
		return err
	}
	if tn, err := authz.TenantID(ctx); err != nil || tn != tenantID {
		return authz.ErrDenied
	}
	return nil
}

func binding(tenantID, kid string) secrets.Binding {
	return secrets.Binding{Purpose: PurposeSigningKey, TenantID: tenantID, RowID: kid}
}

// Create generates a key: active if it is the tenant's first key ever, else
// pending (published for vendors to trust, then Promote). A tenant left
// without an active key still gets a pending one: activating a key no build
// trusts would break every deployed build (ADR-0026). It fails with
// ErrPendingExists if the tenant already has a pending key. ctx's principal
// needs key:write in tenantID (authz.ErrDenied otherwise).
func (l Local) Create(ctx context.Context, tenantID string) (*ent.SigningKey, error) {
	if err := authorize(ctx, tenantID); err != nil {
		return nil, err
	}
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
		hasKeys, err := tx.SigningKey.Query().Exist(ctx)
		if err != nil {
			return err
		}
		c := tx.SigningKey.Create().SetID(kid).SetTenantID(tenantID).SetAlg(signingkey.AlgEd25519).
			SetPublicKey(pub).SetPrivateKeyCiphertext(ct).SetStatus(signingkey.StatusPending)
		if !hasKeys {
			c.SetStatus(signingkey.StatusActive).SetActivatedAt(time.Now())
		}
		k, err = c.Save(ctx)
		// Only the one-active / one-pending index; other violations (unknown
		// tenant, CHECKs) are returned as they are.
		if sqlgraph.IsUniqueConstraintError(err) && strings.Contains(err.Error(), "signingkey_tenant_id_status") {
			return ErrPendingExists
		}
		return err
	})
	return k, err
}

// Promote makes the pending key kid active and retires the active one,
// destroying its private key. Vendor builds that don't trust kid reject
// everything signed afterwards (ADR-0026). Needs key:write, like Create.
func (l Local) Promote(ctx context.Context, tenantID, kid string) error {
	if err := authorize(ctx, tenantID); err != nil {
		return err
	}
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
			return ErrNotPending
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
// abandoned, or the pending key leaked). Needs key:write, like Create.
func (l Local) Discard(ctx context.Context, tenantID, kid string) error {
	if err := authorize(ctx, tenantID); err != nil {
		return err
	}
	return l.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		n, err := tx.SigningKey.Update().
			Where(signingkey.ID(kid), signingkey.StatusEQ(signingkey.StatusPending)).
			SetStatus(signingkey.StatusRetired).SetRetiredAt(time.Now()).ClearPrivateKeyCiphertext().Save(ctx)
		if err == nil && n == 0 {
			err = ErrNotPending
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

// Sign signs msg, which must be "lf1.<kid>.<payload>", with the tenant's
// key kid, which must be active. It signs inside a transaction holding a
// share lock on the key, so a concurrent Promote waits and a key never signs
// after its retirement committed.
func (l Local) Sign(ctx context.Context, tenantID, kid string, msg []byte) ([]byte, error) {
	if !bytes.HasPrefix(msg, []byte("lf1."+kid+".")) {
		return nil, ErrWrongMessage
	}
	var sig []byte
	err := l.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		// ponytail: FOR SHARE writes a row lock per signature on one hot row;
		// check the row version instead if signing throughput ever matters.
		k, err := tx.SigningKey.Query().Where(signingkey.ID(kid)).ForShare().Only(ctx)
		if err != nil {
			return err
		}
		if k.Status != signingkey.StatusActive || k.PrivateKeyCiphertext == nil {
			return ErrNotActive
		}
		seed, err := l.Keys.Decrypt(*k.PrivateKeyCiphertext, binding(tenantID, kid))
		if err != nil {
			return err
		}
		if len(seed) != ed25519.SeedSize {
			return errors.New("signing: bad private key")
		}
		priv := ed25519.NewKeyFromSeed(seed)
		clear(seed)
		// The stored public key is what vendors trust; refuse a private key
		// that doesn't match it rather than sign files nobody can verify.
		if !priv.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(k.PublicKey)) {
			return errors.New("signing: private key doesn't match public key")
		}
		sig = ed25519.Sign(priv, msg)
		return nil
	})
	return sig, err
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
