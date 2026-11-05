package weblogin

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/identity"
	"licenseforge.io/licenseforge/internal/store/ent"
)

// CSRFHeader carries the session's CSRF token on every unsafe request
// (ADR-0020). The dashboard reads the token from GET /auth/session.
const CSRFHeader = "X-CSRF-Token"

// CSRFToken is the CSRF token of the session cookie: derived from the session secret, so it needs no storage and
// can't be computed by anyone who doesn't hold the cookie.
func CSRFToken(cookie string) string {
	h := sha256.Sum256([]byte("licenseforge csrf\x00" + cookie))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

type userKey struct{}

// User returns the signed-in user of a request that passed RequireSession.
func User(ctx context.Context) *ent.User {
	u, _ := ctx.Value(userKey{}).(*ent.User)
	return u
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// Sessions checks dashboard sessions: RequireSession here and the
// management API (internal/api) share it.
type Sessions struct {
	id    identity.Service
	cross *http.CrossOriginProtection // trusts the redirect URL's origin
}

// NewSessions checks sessions of id, trusting redirectURL's origin as same-origin.
func NewSessions(id identity.Service, redirectURL string) (*Sessions, error) {
	own, err := origin(redirectURL)
	if err != nil {
		return nil, err
	}
	cross := http.NewCrossOriginProtection()
	if err := cross.AddTrustedOrigin(own); err != nil {
		return nil, fmt.Errorf("weblogin: redirect URL: %w", err)
	}
	return &Sessions{id: id, cross: cross}, nil
}

// Check returns the user of r's live session. Unsafe methods must also not
// be cross-origin (Fetch metadata / Origin, net/http.CrossOriginProtection)
// and carry the CSRF token: two independent defences, either of which stops
// a forged form post. The redirect URL's origin is trusted, so a proxy that
// rewrites Host doesn't break browsers that send only Origin. On failure it
// returns the status to answer (401, 403, or 500) and why; it writes
// nothing except clearing a dead session cookie. It also returns the
// assurance the session's login proved (ADR-0038).
func (s *Sessions) Check(w http.ResponseWriter, r *http.Request) (*ent.User, authz.Assurance, int, error) {
	if err := s.cross.Check(r); err != nil {
		return nil, "", http.StatusForbidden, err
	}
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return nil, "", http.StatusUnauthorized, err
	}
	if !safeMethod(r.Method) && !equal(r.Header.Get(CSRFHeader), CSRFToken(c.Value)) {
		return nil, "", http.StatusForbidden, errors.New("missing or wrong " + CSRFHeader)
	}
	u, level, err := s.id.Session(r.Context(), c.Value)
	if errors.Is(err, identity.ErrNoSession) {
		setCookie(w, SessionCookie, "", -1)
		return nil, "", http.StatusUnauthorized, err
	}
	if err != nil {
		return nil, "", http.StatusInternalServerError, err
	}
	return u, level, 0, nil
}

// Sessions returns h's session checker.
func (h *Handler) Sessions() *Sessions { return h.sessions }

// RequireSession serves next only for a session that passes Sessions.Check.
func (h *Handler) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		u, _, code, err := h.sessions.Check(w, r)
		switch code {
		case 0:
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, u)))
		case http.StatusForbidden: // our own or net/http's message
			http.Error(w, err.Error(), code)
		default:
			if code == http.StatusInternalServerError {
				h.log.Error("session lookup", "err", err)
			}
			http.Error(w, http.StatusText(code), code)
		}
	})
}

// session tells the dashboard who is signed in and its CSRF token.
func (h *Handler) session(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie(SessionCookie) // present: RequireSession passed
	u := User(r.Context())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff") // holds the CSRF token
	_ = json.NewEncoder(w).Encode(map[string]any{
		"user":       map[string]any{"id": u.ID, "email": u.Email, "name": u.Name},
		"csrf_token": CSRFToken(c.Value),
	})
}

// logout ends the session (needs the CSRF token like any unsafe request).
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie(SessionCookie)
	if err := h.id.EndSession(r.Context(), c.Value); err != nil {
		h.log.Error("logout", "err", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	setCookie(w, SessionCookie, "", -1)
	w.WriteHeader(http.StatusNoContent)
}
