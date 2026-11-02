package signing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"errors"
	"os"
	"testing"

	"licenseforge.io/licenseforge/internal/secrets"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/signingkey"
	"licenseforge.io/licenseforge/internal/store/storetest"
)

var env storetest.Env

func TestMain(m *testing.M) { os.Exit(storetest.Main(m, &env, store.Migrate)) }

func setup(t *testing.T) (Local, *sql.DB) {
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
	return Local{DB: d, Keys: kr}, platform
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

// signVerify signs with kid and verifies against its published public key.
func signVerify(t *testing.T, l Local, tenantID, kid string) error {
	t.Helper()
	ctx := context.Background()
	msg := []byte("lf1." + kid + ".eyJ9")
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
	l, _ := setup(t)
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
	if _, err := l.Create(ctx, tn); err == nil {
		t.Fatal("second pending key created")
	}
	if err := l.Promote(ctx, tn, first.ID); err == nil {
		t.Fatal("promoted the active key")
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
	if err := l.Discard(ctx, tn, next.ID); err == nil {
		t.Fatal("discarded the active key")
	}
	if err := l.Discard(ctx, tn, abandoned.ID); err != nil {
		t.Fatal(err)
	}
	if err := l.Promote(ctx, tn, abandoned.ID); err == nil {
		t.Fatal("promoted a discarded key")
	}
	if _, err := l.Create(ctx, tn); err != nil {
		t.Fatalf("new pending key after discard: %v", err)
	}
}

func TestKeysStayInTenant(t *testing.T) {
	ctx := context.Background()
	l, platform := setup(t)
	a, b := newTenant(t, l), newTenant(t, l)
	ka, err := l.Create(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := l.Create(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Sign(ctx, b, ka.ID, []byte("m")); !ent.IsNotFound(err) {
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
	if _, err := l.Sign(ctx, b, kb.ID, []byte("m")); !errors.Is(err, secrets.ErrDecrypt) {
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
	if _, err := l.Sign(ctx, a, ka.ID, []byte("m")); !errors.Is(err, secrets.ErrDecrypt) {
		t.Fatalf("ciphertext copied within tenant: %v, want ErrDecrypt", err)
	}
}

func TestSigningKeysInDatabase(t *testing.T) {
	ctx := context.Background()
	l, platform := setup(t)
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
	for name, q := range map[string][]any{
		"delete":                   {`DELETE FROM signing_keys WHERE id = $1`, k.ID},
		"change public key":        {`UPDATE signing_keys SET public_key = public_key WHERE id = $1`, k.ID},
		"change alg":               {`UPDATE signing_keys SET alg = alg WHERE id = $1`, k.ID},
		"move tenant":              {`UPDATE signing_keys SET tenant_id = tenant_id WHERE id = $1`, k.ID},
		"retired regains key":      {`UPDATE signing_keys SET private_key_ciphertext = (SELECT private_key_ciphertext FROM signing_keys WHERE id = $2) WHERE id = $1`, k.ID, next.ID},
		"active loses key":         {`UPDATE signing_keys SET private_key_ciphertext = NULL WHERE id = $1`, next.ID},
		"second active key":        {`UPDATE signing_keys SET status = 'active', retired_at = NULL, private_key_ciphertext = (SELECT private_key_ciphertext FROM signing_keys WHERE id = $2) WHERE id = $1`, k.ID, next.ID},
		"active without activated": {`UPDATE signing_keys SET activated_at = NULL WHERE id = $1`, next.ID},
		"short public key":         {`INSERT INTO signing_keys (id, tenant_id, created_at, updated_at, alg, public_key, status, retired_at) VALUES ('sk_aaaaaaaaaaaaaaaaaaaaaaaaaa', $1, now(), now(), 'ed25519', '\x00', 'retired', now())`, tn},
		"unknown alg":              {`INSERT INTO signing_keys (id, tenant_id, created_at, updated_at, alg, public_key, status, retired_at) VALUES ('sk_aaaaaaaaaaaaaaaaaaaaaaaaab', $1, now(), now(), 'rsa', decode(repeat('00', 32), 'hex'), 'retired', now())`, tn},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := platform.ExecContext(ctx, q[0].(string), q[1:]...); err == nil {
				t.Fatalf("%s accepted", name)
			}
		})
	}
	// The same row shape is accepted when valid, so the cases above fail for
	// their own reason.
	if _, err := platform.ExecContext(ctx, `INSERT INTO signing_keys (id, tenant_id, created_at, updated_at, alg, public_key, status, retired_at) VALUES ('sk_aaaaaaaaaaaaaaaaaaaaaaaaac', $1, now(), now(), 'ed25519', decode(repeat('00', 32), 'hex'), 'retired', now())`, tn); err != nil {
		t.Fatalf("valid retired key refused: %v", err)
	}
}
