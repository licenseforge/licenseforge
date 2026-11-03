package signing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"licenseforge.io/licenseforge/internal/secrets"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/signingkey"
	"licenseforge.io/licenseforge/internal/store/storetest"
)

var env storetest.Env

func TestMain(m *testing.M) { os.Exit(storetest.Main(m, &env, store.Migrate)) }

// setup returns the signer, a platform-pool connection and an owner
// connection (bypasses grants, not CHECKs: a database attacker's view).
func setup(t *testing.T) (Local, *sql.DB, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	d, err := store.Open(ctx, env.TenantURL, env.PlatformURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	kr, err := secrets.ParseKeyring("k1=" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, secrets.KeySize)))
	if err != nil {
		t.Fatal(err)
	}
	platform, err := sql.Open("pgx", env.PlatformURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = platform.Close() })
	owner, err := sql.Open("pgx", env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	return Local{DB: d, Keys: kr}, platform, owner
}

func newTenant(t *testing.T, l Local) string {
	t.Helper()
	var id string
	err := l.DB.WithPlatform(context.Background(), func(tx *ent.Tx) error {
		tn, err := tx.Tenant.Create().SetSlug("t-" + storetest.Suffix()).SetName("T").Save(context.Background())
		if err == nil {
			id = tn.ID
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func msgFor(kid string) []byte { return []byte("lf1." + kid + ".eyJ9") }

// signVerify signs with kid and verifies against its published public key.
func signVerify(t *testing.T, l Local, tenantID, kid string) error {
	t.Helper()
	ctx := context.Background()
	msg := msgFor(kid)
	sig, err := l.Sign(ctx, tenantID, kid, msg)
	if err != nil {
		return err
	}
	pub, err := l.Public(ctx, tenantID, kid)
	if err != nil {
		t.Fatal(err)
	}
	if pub.KID != kid || pub.Alg != "ed25519" || !ed25519.Verify(pub.Key, msg, sig) {
		t.Fatalf("signature from %s doesn't verify with its public key %+v", kid, pub)
	}
	return nil
}

func TestLifecycle(t *testing.T) {
	ctx := context.Background()
	l, _, _ := setup(t)
	tn := newTenant(t, l)

	if _, err := l.Active(ctx, tn); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("new tenant: %v, want ErrNoActiveKey", err)
	}
	first, err := l.Create(ctx, tn)
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != signingkey.StatusActive {
		t.Fatalf("first key is %s, want active", first.Status)
	}
	if kid, err := l.Active(ctx, tn); err != nil || kid != first.ID {
		t.Fatalf("Active = %q, %v", kid, err)
	}
	if err := signVerify(t, l, tn, first.ID); err != nil {
		t.Fatal(err)
	}

	next, err := l.Create(ctx, tn)
	if err != nil {
		t.Fatal(err)
	}
	if next.Status != signingkey.StatusPending {
		t.Fatalf("second key is %s, want pending", next.Status)
	}
	if err := signVerify(t, l, tn, next.ID); !errors.Is(err, ErrNotActive) {
		t.Fatalf("pending key signed: %v", err)
	}
	if pub, err := l.Public(ctx, tn, next.ID); err != nil || len(pub.Key) != ed25519.PublicKeySize {
		t.Fatalf("pending key not published: %v", err)
	}
	if _, err := l.Create(ctx, tn); !errors.Is(err, ErrPendingExists) {
		t.Fatalf("second pending key: %v", err)
	}
	if err := l.Promote(ctx, tn, first.ID); !errors.Is(err, ErrNotPending) {
		t.Fatalf("promoted the active key: %v", err)
	}
	if _, err := l.Sign(ctx, tn, first.ID, []byte("lf1."+next.ID+".eyJ9")); !errors.Is(err, ErrWrongMessage) {
		t.Fatalf("signed a message naming another kid: %v", err)
	}
	if _, err := l.Sign(ctx, tn, first.ID, []byte("anything")); !errors.Is(err, ErrWrongMessage) {
		t.Fatalf("signed a non-lf1 message: %v", err)
	}

	if err := l.Promote(ctx, tn, next.ID); err != nil {
		t.Fatal(err)
	}
	if kid, _ := l.Active(ctx, tn); kid != next.ID {
		t.Fatalf("after promote, active = %s", kid)
	}
	if err := signVerify(t, l, tn, next.ID); err != nil {
		t.Fatal(err)
	}
	if err := signVerify(t, l, tn, first.ID); !errors.Is(err, ErrNotActive) {
		t.Fatalf("retired key signed: %v", err)
	}
	var old *ent.SigningKey
	if err := l.DB.WithTenant(ctx, tn, func(tx *ent.Tx) error {
		old, err = tx.SigningKey.Get(ctx, first.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if old.Status != signingkey.StatusRetired || old.PrivateKeyCiphertext != nil || old.RetiredAt == nil {
		t.Fatalf("retired key not destroyed: %+v", old)
	}

	// Abandoned rotation: discard the pending key, then a new one can be made.
	abandoned, err := l.Create(ctx, tn)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Discard(ctx, tn, next.ID); !errors.Is(err, ErrNotPending) {
		t.Fatalf("discarded the active key: %v", err)
	}
	if err := l.Discard(ctx, tn, abandoned.ID); err != nil {
		t.Fatal(err)
	}
	if err := l.Promote(ctx, tn, abandoned.ID); !errors.Is(err, ErrNotPending) {
		t.Fatalf("promoted a discarded key: %v", err)
	}
	if _, err := l.Create(ctx, tn); err != nil {
		t.Fatalf("new pending key after discard: %v", err)
	}
}

func TestKeysStayInTenant(t *testing.T) {
	ctx := context.Background()
	l, platform, _ := setup(t)
	a, b := newTenant(t, l), newTenant(t, l)
	ka, err := l.Create(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := l.Create(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Sign(ctx, b, ka.ID, msgFor(ka.ID)); !ent.IsNotFound(err) {
		t.Fatalf("tenant b signed with a's key: %v", err)
	}
	if _, err := l.Public(ctx, b, ka.ID); !ent.IsNotFound(err) {
		t.Fatalf("tenant b read a's key: %v", err)
	}
	// A ciphertext copied to another tenant's row doesn't decrypt (binding),
	// even with a matching public key: copy both, as a database attacker could.
	if _, err := platform.Exec(`UPDATE signing_keys SET private_key_ciphertext = (SELECT private_key_ciphertext FROM signing_keys WHERE id = $1) WHERE id = $2`, ka.ID, kb.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Sign(ctx, b, kb.ID, msgFor(kb.ID)); !errors.Is(err, secrets.ErrDecrypt) {
		t.Fatalf("copied ciphertext: %v, want ErrDecrypt", err)
	}
	// Within a tenant too: the pending key's ciphertext copied to the active row.
	pending, err := l.Create(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := platform.Exec(`UPDATE signing_keys SET private_key_ciphertext = (SELECT private_key_ciphertext FROM signing_keys WHERE id = $1) WHERE id = $2`, pending.ID, ka.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Sign(ctx, a, ka.ID, msgFor(ka.ID)); !errors.Is(err, secrets.ErrDecrypt) {
		t.Fatalf("ciphertext copied within tenant: %v, want ErrDecrypt", err)
	}
}

func TestSigningKeysInDatabase(t *testing.T) {
	ctx := context.Background()
	l, platform, owner := setup(t)
	tn := newTenant(t, l)
	k, err := l.Create(ctx, tn)
	if err != nil {
		t.Fatal(err)
	}
	next, err := l.Create(ctx, tn)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Promote(ctx, tn, next.ID); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"retired regains key": "signing_keys_retired_destroyed", "active loses key": "signing_keys_retired_destroyed",
		"second active key": "signingkey_tenant_id_status", "active without activated": "signing_keys_activated_at",
		"pending with activated_at": "signing_keys_activated_at", "retired without retired_at": "signing_keys_retired_at",
		"malformed ciphertext": "signing_keys_ciphertext", "bad id": "signing_keys_id_format",
		"short public key": "signing_keys_ed25519_len", "unknown alg": "signing_keys_alg_valid",
	}
	for name, q := range map[string][]any{
		"retired regains key":        {`UPDATE signing_keys SET private_key_ciphertext = (SELECT private_key_ciphertext FROM signing_keys WHERE id = $2) WHERE id = $1`, k.ID, next.ID},
		"active loses key":           {`UPDATE signing_keys SET private_key_ciphertext = NULL WHERE id = $1`, next.ID},
		"second active key":          {`UPDATE signing_keys SET status = 'active', retired_at = NULL, private_key_ciphertext = (SELECT private_key_ciphertext FROM signing_keys WHERE id = $2) WHERE id = $1`, k.ID, next.ID},
		"active without activated":   {`UPDATE signing_keys SET activated_at = NULL WHERE id = $1`, next.ID},
		"short public key":           {`INSERT INTO signing_keys (id, tenant_id, created_at, updated_at, alg, public_key, status, retired_at) VALUES ('sk_aaaaaaaaaaaaaaaaaaaaaaaaaa', $1, now(), now(), 'ed25519', '\x00', 'retired', now())`, tn},
		"pending with activated_at":  {`INSERT INTO signing_keys (id, tenant_id, created_at, updated_at, alg, public_key, status, activated_at, private_key_ciphertext) SELECT 'sk_aaaaaaaaaaaaaaaaaaaaaaaaad', tenant_id, now(), now(), alg, public_key, 'pending', now(), private_key_ciphertext FROM signing_keys WHERE id = $1`, next.ID},
		"retired without retired_at": {`UPDATE signing_keys SET retired_at = NULL WHERE id = $1`, k.ID},
		"malformed ciphertext":       {`UPDATE signing_keys SET private_key_ciphertext = 'v1.k1.short' WHERE id = $1`, next.ID},
		"bad id":                     {`INSERT INTO signing_keys (id, tenant_id, created_at, updated_at, alg, public_key, status, retired_at) VALUES ('sk_BAD', $1, now(), now(), 'ed25519', decode(repeat('00', 32), 'hex'), 'retired', now())`, tn},
		"unknown alg":                {`INSERT INTO signing_keys (id, tenant_id, created_at, updated_at, alg, public_key, status, retired_at) VALUES ('sk_aaaaaaaaaaaaaaaaaaaaaaaaab', $1, now(), now(), 'rsa', decode(repeat('00', 32), 'hex'), 'retired', now())`, tn},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := owner.ExecContext(ctx, q[0].(string), q[1:]...)
			if err == nil || !strings.Contains(err.Error(), want[name]) {
				t.Fatalf("%s: %v, want violation of %s", name, err, want[name])
			}
		})
	}
	// The same row shape is accepted when valid, so the cases above fail for
	// their own reason.
	if _, err := owner.ExecContext(ctx, `INSERT INTO signing_keys (id, tenant_id, created_at, updated_at, alg, public_key, status, retired_at) VALUES ('sk_aaaaaaaaaaaaaaaaaaaaaaaaac', $1, now(), now(), 'ed25519', decode(repeat('00', 32), 'hex'), 'retired', now())`, tn); err != nil {
		t.Fatalf("valid retired key refused: %v", err)
	}
	// Grants: no DELETE, immutable identity, and the platform pool may only
	// rewrap private keys.
	for _, q := range []struct {
		db  *sql.DB
		sql string
	}{
		{platform, `DELETE FROM signing_keys WHERE id = $1`},
		{platform, `UPDATE signing_keys SET status = 'retired' WHERE id = $1`},
		{platform, `INSERT INTO signing_keys (id) VALUES ($1)`},
	} {
		if _, err := q.db.ExecContext(ctx, q.sql, k.ID); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("platform %s: %v, want permission denied", q.sql, err)
		}
	}
	if err := l.DB.WithTenant(ctx, tn, func(tx *ent.Tx) error {
		for _, q := range []string{
			`DELETE FROM signing_keys WHERE id = $1`,
			`UPDATE signing_keys SET public_key = public_key WHERE id = $1`,
			`UPDATE signing_keys SET alg = alg WHERE id = $1`,
			`UPDATE signing_keys SET tenant_id = tenant_id WHERE id = $1`,
		} {
			if _, err := tx.ExecContext(ctx, `SAVEPOINT s`); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, q, k.ID); err == nil || !strings.Contains(err.Error(), "permission denied") {
				t.Errorf("tenant %s: %v, want permission denied", q, err)
			}
			if _, err := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT s`); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A tenant whose only key was retired (compromise) gets a pending key, not an
// active one no vendor build trusts.
func TestCreateAfterRetirementIsPending(t *testing.T) {
	ctx := context.Background()
	l, _, owner := setup(t)
	tn := newTenant(t, l)
	k, err := l.Create(ctx, tn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ExecContext(ctx, `UPDATE signing_keys SET status = 'retired', retired_at = now(), private_key_ciphertext = NULL WHERE id = $1`, k.ID); err != nil {
		t.Fatal(err)
	}
	next, err := l.Create(ctx, tn)
	if err != nil {
		t.Fatal(err)
	}
	if next.Status != signingkey.StatusPending {
		t.Fatalf("key after retirement is %s, want pending", next.Status)
	}
}

// A private key that decrypts but doesn't match the published public key is
// never used (it would sign files nobody can verify).
func TestSignRefusesMismatchedKey(t *testing.T) {
	ctx := context.Background()
	l, _, owner := setup(t)
	tn := newTenant(t, l)
	k, err := l.Create(ctx, tn)
	if err != nil {
		t.Fatal(err)
	}
	_, other, _ := ed25519.GenerateKey(nil)
	ct, err := l.Keys.Encrypt(other.Seed(), binding(tn, k.ID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ExecContext(ctx, `UPDATE signing_keys SET private_key_ciphertext = $1 WHERE id = $2`, ct, k.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Sign(ctx, tn, k.ID, msgFor(k.ID)); err == nil || !strings.Contains(err.Error(), "doesn't match") {
		t.Fatalf("signed with a mismatched private key: %v", err)
	}
}

func TestConcurrentCreateMakesOneActiveKey(t *testing.T) {
	ctx := context.Background()
	l, _, _ := setup(t)
	tn := newTenant(t, l)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if _, err := l.Create(ctx, tn); err != nil && !errors.Is(err, ErrPendingExists) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	var active, pending int
	if err := l.DB.WithTenant(ctx, tn, func(tx *ent.Tx) error {
		ks, err := tx.SigningKey.Query().All(ctx)
		for _, k := range ks {
			switch k.Status {
			case signingkey.StatusActive:
				active++
			case signingkey.StatusPending:
				pending++
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if active != 1 || pending > 1 {
		t.Fatalf("%d active, %d pending keys", active, pending)
	}
}

func TestCreateReportsOtherErrorsAsIs(t *testing.T) {
	l, _, _ := setup(t)
	_, err := l.Create(context.Background(), "tnt_aaaaaaaaaaaaaaaaaaaaaaaaaa") // no such tenant
	if err == nil || errors.Is(err, ErrPendingExists) {
		t.Fatalf("unknown tenant: %v", err)
	}
}
