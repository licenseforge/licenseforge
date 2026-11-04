// Package apitokens creates, authenticates and revokes a tenant's API tokens
// (ADR-0019, ADR-0029). The format is internal/apitoken; the database enforces
// expiry, scope, role cap and one-way revocation (api_tokens policies). Every
// change is written to the audit log in the same transaction (ADR-0027).
package apitokens

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"entgo.io/ent/dialect/sql"
	"github.com/jackc/pgx/v5/pgconn"

	"licenseforge.io/licenseforge/internal/apitoken"
	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	entapitoken "licenseforge.io/licenseforge/internal/store/ent/apitoken"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// Lifetimes (ADR-0029): required, default 90 days, at most a year.
const (
	DefaultTTL = 90 * 24 * time.Hour
	MaxTTL     = 365 * 24 * time.Hour
	MinTTL     = time.Minute
	// skew keeps the longest token inside the database's "at most a year from
	// its clock" rule when this host's clock runs a little ahead.
	skew = 5 * time.Minute
)

var (
	// ErrUnauthenticated means the token isn't valid for this tenant: unknown,
	// malformed, another tenant's, revoked or expired. Callers answer the same
	// way for all of them.
	ErrUnauthenticated = errors.New("apitokens: invalid API token")
	// ErrNotFound means there is no active token with that ID in the tenant.
	ErrNotFound = errors.New("apitokens: no such active token")
	// ErrInvalid means the request is malformed (name, lifetime).
	ErrInvalid = errors.New("apitokens: invalid request")
)

// Service works on the tenant pool.
type Service struct{ DB *store.DB }

// Created is a new token. Token is shown once and never stored.
type Created struct {
	Token string
	Row   *ent.APIToken
}

// Create issues a token for ctx's tenant with role and scope, for ttl (0:
// DefaultTTL). The caller needs token:write and may only give what it holds
// (authz.CanAssign); API tokens can't create tokens.
func (s Service) Create(ctx context.Context, name string, role authz.Role, scope authz.Scope, ttl time.Duration) (Created, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return Created{}, err
	}
	p, _ := authz.FromContext(ctx)
	ev := event(p, "api_token.create", "")
	// Authorization first: a caller who may not create tokens learns nothing
	// about its input.
	if err := authz.CanAssign(ctx, authz.Token, nil, &authz.Grant{Role: role, Scope: scope}); err != nil {
		return Created{}, s.refused(ctx, tenantID, ev, err)
	}
	if ttl == 0 {
		ttl = DefaultTTL
	}
	if err := validName(name); err != nil || ttl < MinTTL || ttl > MaxTTL || !validProducts(scope.Products) {
		return Created{}, s.refused(ctx, tenantID, ev, fmt.Errorf("%w: name of 1-200 printable characters, lifetime 1 minute to a year, distinct product IDs", ErrInvalid))
	}
	expires := time.Now().Add(min(ttl, MaxTTL-skew))
	tok := apitoken.New()
	var row *ent.APIToken
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		var err error
		row, err = tx.APIToken.Create().SetTenantID(tenantID).SetName(name).SetRole(entapitoken.Role(role)).
			SetScopeAll(scope.All).SetTokenHash(apitoken.Hash(tok)).SetDisplay(apitoken.Display(tok)).
			SetCreatedBy(p.ID).SetExpiresAt(expires).Save(ctx)
		if err != nil {
			return dbRefusal(err)
		}
		for _, product := range scope.Products {
			if _, err := tx.APITokenProduct.Create().SetTenantID(tenantID).SetAPITokenID(row.ID).SetProductID(product).Save(ctx); err != nil {
				return dbRefusal(err)
			}
		}
		ev.ObjectID = row.ID
		ev.Outcome = auditevent.OutcomeSuccess
		ev.Details = map[string]any{"role": string(role), "scope_all": scope.All, "products": len(scope.Products), "expires_at": row.ExpiresAt.UTC().Format(time.RFC3339)}
		_, err = audit.Record(ctx, tx, tenantID, ev)
		return err
	})
	if err != nil {
		ev.ObjectID, ev.Details = "", nil
		return Created{}, s.refused(ctx, tenantID, ev, err)
	}
	return Created{Token: tok, Row: row}, nil
}

// validName: 1-200 printable characters (no control characters), not blank.
func validName(name string) error {
	if strings.TrimSpace(name) == "" || len(name) > 200 || !utf8.ValidString(name) {
		return ErrInvalid
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return ErrInvalid
		}
	}
	return nil
}

// validProducts: well-formed, distinct product IDs (whether they exist in
// the tenant is checked by the database: same-tenant key).
func validProducts(products []string) bool {
	seen := map[string]bool{}
	for _, p := range products {
		if !ids.Valid("prd", p) || seen[p] {
			return false
		}
		seen[p] = true
	}
	return true
}

// dbRefusal maps the database's refusals of a client request to the
// service's errors: row-level security (the creator isn't, or is no longer,
// allowed: a stale principal) to authz.ErrDenied, a missing referenced row
// (an unknown or another tenant's product) to ErrInvalid. Others stay.
func dbRefusal(err error) error {
	var pe *pgconn.PgError
	switch {
	case !errors.As(err, &pe):
		return err
	case pe.Code == "42501" && strings.Contains(pe.Message, "row-level security"):
		return fmt.Errorf("%w (database refused: %s)", authz.ErrDenied, pe.ConstraintName)
	case pe.Code == "23503":
		return fmt.Errorf("%w: unknown product", ErrInvalid)
	}
	return err
}

// Authenticate returns the principal for token in tenantID (the tenant from
// the request URL). Unknown, malformed, wrong-tenant, revoked and expired
// tokens all give ErrUnauthenticated. It records the use (at most once a
// minute per token); failing to record never fails authentication.
func (s Service) Authenticate(ctx context.Context, tenantID, token string) (authz.Principal, error) {
	// Malformed input is refused before any query (cheap; same answer anyway).
	if apitoken.Check(token) != nil || !ids.Valid("tnt", tenantID) {
		return authz.Principal{}, ErrUnauthenticated
	}
	var row *ent.APIToken
	var products []string
	err := s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		var err error
		row, err = tx.APIToken.Query().Where(entapitoken.TokenHash(apitoken.Hash(token)), entapitoken.RevokedAtIsNil(),
			notExpired).WithProducts().Only(ctx)
		if err != nil {
			return err
		}
		for _, p := range row.Edges.Products {
			products = append(products, p.ProductID)
		}
		return nil
	})
	if ent.IsNotFound(err) {
		return authz.Principal{}, ErrUnauthenticated
	}
	if err != nil {
		return authz.Principal{}, err
	}
	if row.LastUsedAt == nil || time.Since(*row.LastUsedAt) > time.Minute { // skip the write when clearly throttled
		err := s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
			// One DB-side statement: the database clock, never moving the value
			// back, throttled; the api_tokens policies refuse anything else.
			_, err := tx.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = GREATEST(coalesce(last_used_at, '-infinity'), clock_timestamp()), updated_at = clock_timestamp()
				WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < clock_timestamp() - interval '1 minute')`, row.ID)
			return err
		})
		if err != nil && !errors.Is(dbRefusal(err), authz.ErrDenied) { // a policy refusal (e.g. at expiry) is expected
			slog.WarnContext(ctx, "api token use not recorded", "token", row.ID, "err", err)
		}
	}
	return authz.Principal{Kind: authz.Token, ID: row.ID, TenantID: tenantID, Role: authz.Role(row.Role),
		Scope: authz.Scope{All: row.ScopeAll, Products: products}}, nil
}

// Revoke revokes an active token of ctx's tenant. The caller needs
// token:write and may only revoke a token whose role it could have given.
func (s Service) Revoke(ctx context.Context, tokenID string) error {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return err
	}
	p, _ := authz.FromContext(ctx)
	ev := event(p, "api_token.revoke", "")
	// Authorization first (token:write, as a user with every product), so a
	// caller who may not revoke can't probe which IDs exist.
	if err := authz.CanAssign(ctx, authz.Token, &authz.Grant{Role: authz.SDK, Scope: authz.Scope{All: true}}, nil); err != nil {
		return s.refused(ctx, tenantID, ev, err)
	}
	if !ids.Valid("tok", tokenID) {
		return s.refused(ctx, tenantID, ev, ErrNotFound)
	}
	ev.ObjectID = tokenID
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		row, err := tx.APIToken.Query().Where(entapitoken.ID(tokenID), entapitoken.RevokedAtIsNil()).WithProducts().Only(ctx)
		if ent.IsNotFound(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		var products []string
		for _, p := range row.Edges.Products {
			products = append(products, p.ProductID)
		}
		from := &authz.Grant{Role: authz.Role(row.Role), Scope: authz.Scope{All: row.ScopeAll, Products: products}}
		if err := authz.CanAssign(ctx, authz.Token, from, nil); err != nil {
			return err
		}
		// The database clock (the policies bound revoked_at to it), and count
		// the row: ent's UpdateOneID would hide a zero-row update.
		res, err := tx.ExecContext(ctx, `UPDATE api_tokens SET revoked_at = clock_timestamp(), updated_at = clock_timestamp()
			WHERE id = $1 AND revoked_at IS NULL`, tokenID)
		if err != nil {
			return dbRefusal(err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 { // revoked concurrently since the query: not ours to record
			return errors.Join(ErrNotFound, err)
		}
		ev.Outcome = auditevent.OutcomeSuccess
		_, err = audit.Record(ctx, tx, tenantID, ev)
		return err
	})
	if err != nil {
		return s.refused(ctx, tenantID, ev, err)
	}
	return nil
}

// notExpired compares with the database clock, as the api_tokens policies do.
func notExpired(s *sql.Selector) { s.Where(sql.ExprP(s.C(entapitoken.FieldExpiresAt) + " > now()")) }

func event(p authz.Principal, action, objectID string) audit.Event {
	actor := auditevent.ActorTypeUser
	if p.Kind == authz.Token {
		actor = auditevent.ActorTypeToken
	}
	return audit.Event{ActorType: actor, ActorID: p.ID, Action: action, ObjectType: "api_token", ObjectID: objectID}
}

// refused records a denied or failed attempt in its own transaction
// (ADR-0027) and returns err. Infrastructure errors aren't attempts.
func (s Service) refused(ctx context.Context, tenantID string, ev audit.Event, err error) error {
	switch {
	case errors.Is(err, authz.ErrDenied):
		ev.Outcome = auditevent.OutcomeDenied
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrNotFound):
		ev.Outcome = auditevent.OutcomeFailure
	default:
		return err
	}
	if rerr := s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		_, err := audit.Record(ctx, tx, tenantID, ev)
		return err
	}); rerr != nil {
		return errors.Join(err, rerr)
	}
	return err
}
