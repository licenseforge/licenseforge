package api

import (
	"context"
	"encoding/base64"
	"reflect"
	"slices"
	"strings"
	"testing"

	"licenseforge.io/licenseforge/internal/api/apigen"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/signingkey"
)

func TestSigningKeyEndpoints(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	owner, viewer, admin := f.session(t, f.ownerA, true), f.session(t, f.viewerA, true), f.session(t, f.adminA, true)
	p := Prefix + "/tenants/" + f.a.Slug + "/signing-keys"
	create := func(o opt) resp { return f.do(t, "POST", p, "", o) }

	// The first key is active, the next pending; a second pending is 409.
	first := create(owner)
	if first.code != 201 || first.body["status"] != "active" || first.body["activated_at"] == nil {
		t.Fatalf("first: %d %s", first.code, first.raw)
	}
	create(admin).problem(t, 403, "forbidden")
	pending := create(owner)
	if pending.code != 201 || pending.body["status"] != "pending" {
		t.Fatalf("pending: %d %s", pending.code, pending.raw)
	}
	create(owner).problem(t, 409, "pending_key_exists")
	kid := pending.body["kid"].(string)

	// Every member reads the public part only, newest first.
	l := f.do(t, "GET", p+"?limit=1", "", viewer)
	items, _ := l.body["items"].([]any)
	if l.code != 200 || len(items) != 1 || items[0].(map[string]any)["kid"] != kid || l.body["next_cursor"] == nil {
		t.Fatalf("list: %d %s", l.code, l.raw)
	}
	next := f.do(t, "GET", p+"?cursor="+l.body["next_cursor"].(string), "", viewer)
	if it, _ := next.body["items"].([]any); len(it) != 1 || it[0].(map[string]any)["kid"] != first.body["kid"] {
		t.Errorf("page 2: %s", next.raw)
	}
	var stored *ent.SigningKey
	if err := f.db.WithTenant(ctx, f.a.ID, func(tx *ent.Tx) (err error) {
		stored, err = tx.SigningKey.Get(ctx, kid)
		return
	}); err != nil {
		t.Fatal(err)
	}
	item := items[0].(map[string]any)
	pub, err := base64.RawURLEncoding.Strict().DecodeString(item["public_key"].(string))
	if err != nil || !slices.Equal(pub, stored.PublicKey) || item["alg"] != "ed25519" ||
		stored.PrivateKeyCiphertext == nil || strings.Contains(l.raw, *stored.PrivateKeyCiphertext) {
		t.Errorf("item %v", item)
	}
	var want, got []string
	for _, fl := range reflect.VisibleFields(reflect.TypeFor[apigen.SigningKey]()) {
		name, _, _ := strings.Cut(fl.Tag.Get("json"), ",")
		want = append(want, name)
	}
	for k := range item {
		got = append(got, k)
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("fields %v, spec %v", got, want)
	}

	// Missing, malformed and another tenant's keys are 404 alike; seen but
	// not owner: 403, recorded as denied, and nothing changes.
	bKey, err := f.srv.SigningKeys.Create(authz.WithPrincipal(ctx, authz.Principal{Kind: authz.User, ID: f.ownerB, TenantID: f.b.ID, Role: authz.Owner, Scope: authz.Scope{All: true}}), f.b.ID)
	if err != nil {
		t.Fatal(err)
	}
	missing := f.do(t, "POST", p+"/sk_aaaaaaaaaaaaaaaaaaaaaaaaaa/promote", "", owner).problem(t, 404, "not_found")
	for name, path := range map[string]string{"malformed": p + "/x/promote", "another tenant's": p + "/" + bKey.ID + "/promote",
		"another tenant's discard": p + "/" + bKey.ID + "/discard", "missing discard": p + "/sk_aaaaaaaaaaaaaaaaaaaaaaaaaa/discard"} {
		if got := f.do(t, "POST", path, "", owner).problem(t, 404, "not_found"); !reflect.DeepEqual(got, missing) {
			t.Errorf("%s: %v, missing %v", name, got, missing)
		}
	}
	f.do(t, "POST", p+"/"+kid+"/promote", "", admin).problem(t, 403, "forbidden")
	if e := f.lastEvent(t, f.a.ID); e.Action != "signing_key.promote" || e.Outcome != auditevent.OutcomeDenied || *e.ActorID != f.adminA {
		t.Errorf("denied promote entry %+v", e)
	}
	f.do(t, "POST", p+"/"+kid+"/discard", "", viewer).problem(t, 403, "forbidden")
	if e := f.lastEvent(t, f.a.ID); e.Action != "signing_key.discard" || e.Outcome != auditevent.OutcomeDenied || *e.ActorID != f.viewerA {
		t.Errorf("denied discard entry %+v", e)
	}
	if err := f.db.WithTenant(ctx, f.a.ID, func(tx *ent.Tx) (err error) {
		stored, err = tx.SigningKey.Get(ctx, kid)
		return
	}); err != nil || stored.Status != signingkey.StatusPending {
		t.Errorf("refusals changed the key: %v %v", stored, err)
	}
	// Product-scoped principals read no keys; non-members get 404.
	f.do(t, "GET", p, "", f.session(t, f.scoped, true)).problem(t, 403, "forbidden")
	f.do(t, "GET", p, "", f.session(t, f.ownerB, true)).problem(t, 404, "not_found")

	// Promote: the pending key signs, the old one is retired; audited.
	r := f.do(t, "POST", p+"/"+kid+"/promote", "", owner)
	if r.code != 200 || r.body["kid"] != kid || r.body["status"] != "active" {
		t.Fatalf("promote: %d %s", r.code, r.raw)
	}
	if e := f.lastEvent(t, f.a.ID); e.Action != "signing_key.promote" || e.Outcome != auditevent.OutcomeSuccess || *e.ActorID != f.ownerA || *e.ObjectID != kid {
		t.Errorf("promote entry %+v", e)
	}
	old := first.body["kid"].(string)
	f.do(t, "POST", p+"/"+old+"/promote", "", owner).problem(t, 409, "invalid_state")
	f.do(t, "POST", p+"/"+kid+"/discard", "", owner).problem(t, 409, "invalid_state")

	// Discard a new pending key, with an owner token: retired, never active.
	tok := bearer(f.token(t, f.a.ID, f.ownerA, authz.Owner).Token)
	again := create(tok)
	d := f.do(t, "POST", p+"/"+again.body["kid"].(string)+"/discard", "", tok)
	if d.code != 200 || d.body["status"] != "retired" || d.body["activated_at"] != nil || d.body["retired_at"] == nil {
		t.Fatalf("discard: %d %s", d.code, d.raw)
	}
	if e := f.lastEvent(t, f.a.ID); e.Action != "signing_key.discard" || e.ActorType != auditevent.ActorTypeToken || e.Outcome != auditevent.OutcomeSuccess {
		t.Errorf("discard entry %+v", e)
	}
	// Retired keys keep no private key.
	if err := f.db.WithTenant(ctx, f.a.ID, func(tx *ent.Tx) error {
		ks, err := tx.SigningKey.Query().Where(signingkey.StatusEQ(signingkey.StatusRetired)).All(ctx)
		if err == nil && (len(ks) != 2 || ks[0].PrivateKeyCiphertext != nil || ks[1].PrivateKeyCiphertext != nil) {
			t.Errorf("retired keys %v", ks)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f.do(t, "GET", p+"?cursor=x", "", viewer).problem(t, 400, "invalid_cursor")
	f.do(t, "GET", p+"?status=active", "", viewer).problem(t, 400, "invalid_request")
}
