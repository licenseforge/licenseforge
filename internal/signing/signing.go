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

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/secrets"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
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
	tx   *ent.Tx // WithTx: read keys in this transaction
}

// WithTx returns l reading keys (Active, Public, Sign) in tx, a tenant
// transaction of the caller, instead of transactions of its own: signing
// inside a transaction then needs no second pool connection while that
// transaction holds its locks. The key's share lock is held until tx ends.
func (l Local) WithTx(tx *ent.Tx) Local {
	l.tx = tx
	return l
}

// in runs fn in l's transaction (WithTx) or a new tenant transaction.
func (l Local) in(ctx context.Context, tenantID string, fn func(*ent.Tx) error) error {
	if l.tx != nil {
		return fn(l.tx)
	}
	return l.DB.WithTenant(ctx, tenantID, fn)
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

// begin returns the principal's tenant (where the attempt is recorded) and
// the audit event for action on kid ("" when not known or malformed: hostile
// input isn't stored). Without a well-formed principal there is no one to
// attribute an entry to, so the caller is refused unrecorded.
func begin(ctx context.Context, action, kid string) (string, audit.Event, error) {
	tn, err := authz.TenantID(ctx)
	if err != nil {
		return "", audit.Event{}, err
	}
	p, _ := authz.FromContext(ctx)
	actor := auditevent.ActorTypeUser
	if p.Kind == authz.Token {
		actor = auditevent.ActorTypeToken
	}
	if !ids.Valid("sk", kid) {
		kid = ""
	}
	return tn, audit.Event{ActorType: actor, ActorID: p.ID, Action: action, ObjectType: "signing_key", ObjectID: kid}, nil
}

// refused records a denied or failed attempt in its own transaction, after
// the action rolled back (ADR-0027), in the principal's tenant, and returns
// err. Infrastructure errors aren't attempts and aren't recorded.
func (l Local) refused(ctx context.Context, tenantID string, ev audit.Event, err error) error {
	switch {
	case errors.Is(err, authz.ErrDenied):
		ev.Outcome, ev.Details = auditevent.OutcomeDenied, nil
	case errors.Is(err, ErrPendingExists), errors.Is(err, ErrNotPending):
		ev.Outcome, ev.Details = auditevent.OutcomeFailure, map[string]any{"reason": err.Error()}
	default:
		return err
	}
	if rerr := l.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		_, err := recordAudit(ctx, tx, tenantID, ev)
		return err
	}); rerr != nil {
		return errors.Join(err, rerr)
	}
	return err
}

// record writes the success entry in tx. Lock order: the tenant's audit lock
// before any signing-key row lock, wherever a transaction takes both, so
// every key operation calls audit.Lock first: activation holds the audit
// lock and then share-locks the active key to sign (ActivateTx), and a
// Promote holding the key rows while waiting for the audit lock would
// deadlock with it. details hold the algorithm and states, never key
// material.
func record(ctx context.Context, tx *ent.Tx, tenantID string, ev audit.Event, details map[string]any) error {
	ev.Outcome, ev.Details = auditevent.OutcomeSuccess, details
	_, err := recordAudit(ctx, tx, tenantID, ev)
	return err
}

// recordAudit is audit.Record; tests replace it to check that a failed audit
// write fails the operation (fail closed, ADR-0027).
var recordAudit = audit.Record

// errStateChanged means a key wasn't in the state the operation expected when
// it was written (a concurrent rotation): the write changed nothing.
var errStateChanged = errors.New("signing: key state changed concurrently")

func binding(tenantID, kid string) secrets.Binding {
	return secrets.Binding{Purpose: PurposeSigningKey, TenantID: tenantID, RowID: kid}
}

// Create generates a key: active if it is the tenant's first key ever, else
// pending (published for vendors to trust, then Promote). A tenant left
// without an active key still gets a pending one: activating a key no build
// trusts would break every deployed build (ADR-0026). It fails with
// ErrPendingExists if the tenant already has a pending key. ctx's principal
// needs key:write in tenantID (authz.ErrDenied otherwise). The creation and
// refusals are audited (signing_key.create).
func (l Local) Create(ctx context.Context, tenantID string) (*ent.SigningKey, error) {
	tn, ev, err := begin(ctx, "signing_key.create", "")
	if err != nil {
		return nil, err
	}
	if err := authorize(ctx, tenantID); err != nil {
		return nil, l.refused(ctx, tn, ev, err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	kid := ids.SigningKey()
	ev.ObjectID = kid
	ct, err := l.Keys.Encrypt(priv.Seed(), binding(tenantID, kid))
	if err != nil {
		return nil, err
	}
	var k *ent.SigningKey
	err = l.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		// The audit lock first (see record). It also serializes Creates, so
		// a tenant's first key can't race: the second Create sees it and
		// makes the pending key.
		if err := audit.Lock(ctx, tx, tenantID); err != nil {
			return err
		}
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
		if err != nil {
			return err
		}
		return record(ctx, tx, tenantID, ev, map[string]any{"alg": string(k.Alg), "to": string(k.Status)})
	})
	if err != nil {
		ev.ObjectID = "" // the key doesn't exist
		return nil, l.refused(ctx, tn, ev, err)
	}
	return k, nil
}

// Promote makes the pending key kid active and retires the active one,
// destroying its private key. Vendor builds that don't trust kid reject
// everything signed afterwards (ADR-0026). Needs key:write, like Create;
// audited as signing_key.promote.
func (l Local) Promote(ctx context.Context, tenantID, kid string) error {
	tn, ev, err := begin(ctx, "signing_key.promote", kid)
	if err != nil {
		return err
	}
	if err := authorize(ctx, tenantID); err != nil {
		return l.refused(ctx, tn, ev, err)
	}
	if ev.ObjectID == "" { // malformed kid: refused before any query
		return l.refused(ctx, tn, ev, ErrNotPending)
	}
	err = l.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		if err := audit.Lock(ctx, tx, tenantID); err != nil { // before the key rows (see record)
			return err
		}
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
		details := map[string]any{"alg": string(pending.Alg), "from": string(signingkey.StatusPending), "to": string(signingkey.StatusActive)}
		if active != nil {
			if err := retire(ctx, tx, active.ID, signingkey.StatusActive, now); err != nil {
				return err
			}
			details["retired"] = active.ID
		}
		n, err := tx.SigningKey.Update().Where(signingkey.ID(kid), signingkey.StatusEQ(signingkey.StatusPending)).
			SetStatus(signingkey.StatusActive).SetActivatedAt(now).Save(ctx)
		if err == nil && n != 1 {
			err = errStateChanged
		}
		if err != nil {
			return err
		}
		return record(ctx, tx, tenantID, ev, details)
	})
	if err != nil {
		return l.refused(ctx, tn, ev, err)
	}
	return nil
}

// Discard retires the pending key kid without it ever signing (rotation
// abandoned, or the pending key leaked). Needs key:write, like Create;
// audited as signing_key.discard.
func (l Local) Discard(ctx context.Context, tenantID, kid string) error {
	tn, ev, err := begin(ctx, "signing_key.discard", kid)
	if err != nil {
		return err
	}
	if err := authorize(ctx, tenantID); err != nil {
		return l.refused(ctx, tn, ev, err)
	}
	if ev.ObjectID == "" { // malformed kid: refused before any query
		return l.refused(ctx, tn, ev, ErrNotPending)
	}
	err = l.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		if err := audit.Lock(ctx, tx, tenantID); err != nil { // before the key row (see record)
			return err
		}
		// The write itself requires the key to be pending, so a concurrent
		// Promote either commits first (nothing is retired: ErrNotPending) or
		// waits for this transaction.
		if err := retire(ctx, tx, kid, signingkey.StatusPending, time.Now()); errors.Is(err, errStateChanged) {
			return ErrNotPending
		} else if err != nil {
			return err
		}
		alg, err := tx.SigningKey.Query().Where(signingkey.ID(kid)).Select(signingkey.FieldAlg).String(ctx)
		if err != nil {
			return err
		}
		return record(ctx, tx, tenantID, ev, map[string]any{"alg": alg, "from": string(signingkey.StatusPending), "to": string(signingkey.StatusRetired)})
	})
	if err != nil {
		return l.refused(ctx, tn, ev, err)
	}
	return nil
}

// retire retires kid and erases its private key, only if it is still in
// state from (errStateChanged otherwise, and nothing changes).
func retire(ctx context.Context, tx *ent.Tx, kid string, from signingkey.Status, now time.Time) error {
	n, err := tx.SigningKey.Update().Where(signingkey.ID(kid), signingkey.StatusEQ(from)).
		SetStatus(signingkey.StatusRetired).SetRetiredAt(now).ClearPrivateKeyCiphertext().Save(ctx)
	if err == nil && n != 1 {
		err = errStateChanged
	}
	return err
}

// Active returns the tenant's active kid.
func (l Local) Active(ctx context.Context, tenantID string) (string, error) {
	var kid string
	err := l.in(ctx, tenantID, func(tx *ent.Tx) error {
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
	err := l.in(ctx, tenantID, func(tx *ent.Tx) error {
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
	err := l.in(ctx, tenantID, func(tx *ent.Tx) error {
		var err error
		k, err = tx.SigningKey.Get(ctx, kid)
		return err
	})
	return k, err
}
