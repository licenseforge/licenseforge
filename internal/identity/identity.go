// Package identity is the login path (ADR-0003, ADR-0029): it turns verified
// OIDC claims into a LicenseForge user and lists the tenants they belong to.
// It runs on the identity pool, which can touch identity tables only.
// Verifying the ID token (issuer, audience, signature, expiry, nonce) is the
// OIDC client's job and happens before Login.
package identity

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/membership"
	"licenseforge.io/licenseforge/internal/store/ent/tenant"
	"licenseforge.io/licenseforge/internal/store/ent/user"
)

var (
	// ErrDisabled means the user is suspended (disabled_at): login refused.
	ErrDisabled = errors.New("identity: user is disabled")
	// ErrInvalidClaims means required claims are missing or malformed.
	ErrInvalidClaims = errors.New("identity: invalid claims")
)

// Claims are the verified ID token claims LicenseForge uses. A user is
// (Issuer, Subject), never the email (ADR-0003).
type Claims struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

// Service runs on the identity pool.
type Service struct{ DB *store.DB }

// Login creates or refreshes the user for c and returns them. The name is
// refreshed every login; the email only from a verified email claim, so an
// unverified claim can't make a member list show a colleague's address
// (ADR-0029); an unverified claim clears the verified flag. Disabled users
// get ErrDisabled.
func (s Service) Login(ctx context.Context, c Claims) (*ent.User, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	u, err := s.login(ctx, c)
	if ent.IsConstraintError(err) {
		// Two first logins raced (two tabs, a double redirect): the other one
		// created the user; this attempt now takes the refresh path.
		u, err = s.login(ctx, c)
	}
	return u, err
}

func (s Service) login(ctx context.Context, c Claims) (*ent.User, error) {
	name := clean(c.Name, 200)
	var u *ent.User
	err := s.DB.WithIdentity(ctx, "", func(tx *ent.Tx) error {
		var err error
		u, err = tx.User.Query().Where(user.Issuer(c.Issuer), user.Subject(c.Subject)).Only(ctx)
		switch {
		case ent.IsNotFound(err):
			cr := tx.User.Create().SetIssuer(c.Issuer).SetSubject(c.Subject).SetLastLoginAt(time.Now())
			if name != "" {
				cr.SetName(name)
			}
			if c.EmailVerified {
				cr.SetEmail(c.Email).SetEmailVerified(true)
			}
			u, err = cr.Save(ctx)
			return err
		case err != nil:
			return err
		case u.DisabledAt != nil:
			return ErrDisabled
		}
		up := tx.User.UpdateOne(u).SetLastLoginAt(time.Now())
		if name != "" {
			up.SetName(name)
		}
		if c.EmailVerified {
			up.SetEmail(c.Email).SetEmailVerified(true)
		} else {
			up.SetEmailVerified(false) // the IdP no longer vouches for it: fail safe for invitations
		}
		u, err = up.Save(ctx)
		return err
	})
	if err != nil {
		return nil, err
	}
	return u, nil
}

// TenantMembership is one entry of the tenant switcher.
type TenantMembership struct {
	TenantID, TenantSlug, TenantName string
	Role                             membership.Role
	ScopeAll                         bool
}

// Memberships lists the tenants userID belongs to, sorted by slug. Call it
// after Login, which refuses disabled users.
func (s Service) Memberships(ctx context.Context, userID string) ([]TenantMembership, error) {
	var out []TenantMembership
	err := s.DB.WithIdentity(ctx, "", func(tx *ent.Tx) error {
		ms, err := tx.Membership.Query().Where(membership.UserID(userID)).
			Order(membership.ByTenantField(tenant.FieldSlug)).
			WithTenant(func(q *ent.TenantQuery) { q.Select(tenant.FieldID, tenant.FieldSlug, tenant.FieldName) }).All(ctx)
		if err != nil {
			return err
		}
		for _, m := range ms {
			out = append(out, TenantMembership{TenantID: m.TenantID, TenantSlug: m.Edges.Tenant.Slug,
				TenantName: m.Edges.Tenant.Name, Role: m.Role, ScopeAll: m.ScopeAll})
		}
		return nil
	})
	return out, err
}

// BootstrapMatches reports whether u is LICENSEFORGE_BOOTSTRAP_ADMIN
// (ADR-0003): "issuer|subject" (recommended; the issuer exactly as in the ID
// token's iss, trailing slash included; the subject may itself contain '|',
// as Auth0's do), or an email that the IdP verified, compared
// case-insensitively in ASCII only (no Unicode look-alike folding, such as
// the long s or the Kelvin sign, for the highest-privilege grant). An empty
// setting matches nobody.
func BootstrapMatches(setting string, u *ent.User) bool {
	setting = strings.TrimSpace(setting)
	if setting == "" || u == nil {
		return false
	}
	if iss, sub, ok := strings.Cut(setting, "|"); ok {
		return iss == u.Issuer && sub == u.Subject
	}
	return u.EmailVerified && u.Email != nil && isASCII(*u.Email) && isASCII(setting) && strings.EqualFold(*u.Email, setting)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func (c Claims) check() error {
	ok := func(s string, n int) bool {
		return s != "" && len(s) <= n && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
	}
	if !ok(c.Issuer, 500) || !ok(c.Subject, 255) || strings.TrimSpace(c.Issuer) == "" || strings.TrimSpace(c.Subject) == "" {
		return ErrInvalidClaims
	}
	if c.EmailVerified && (!ok(c.Email, 320) || !strings.Contains(c.Email, "@") || !graphic(c.Email)) {
		return ErrInvalidClaims // a verified email is shown in member lists: no invisible or spoofing characters
	}
	return nil
}

func graphic(s string) bool {
	for _, r := range s {
		if !unicode.IsGraphic(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// clean keeps a display name storable: valid UTF-8, graphic characters only,
// trimmed, at most n bytes. A hostile claim must not make login fail.
func clean(s string, n int) string {
	var b strings.Builder
	for _, r := range strings.ToValidUTF8(s, "") {
		if unicode.IsGraphic(r) {
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	for len(out) > n {
		_, size := utf8.DecodeLastRuneInString(out)
		out = out[:len(out)-size]
	}
	return out
}
