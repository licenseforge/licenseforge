package weblogin

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"licenseforge.io/licenseforge/internal/identity"
	"licenseforge.io/licenseforge/internal/store/ent"
)

// CSRFHeader carries the session's CSRF token on every unsafe request
// (ADR-0020). The dashboard reads the token from GET /auth/session.
const CSRFHeader = "X-CSRF-Token"

// csrfToken is derived from the session secret, so it needs no storage and
// can't be computed by anyone who doesn't hold the cookie.
func csrfToken(cookie string) string {
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

// RequireSession serves next only for a live session (else 401). Unsafe
// methods also need the CSRF token and must not be cross-origin (Fetch
// metadata / Origin, net/http.CrossOriginProtection): two independent
// defences, either of which stops a forged form post. The redirect URL's
// origin is trusted, so a proxy that rewrites Host doesn't break browsers
// that send only Origin.
func (h *Handler) RequireSession(next http.Handler) http.Handler {
	cross := http.NewCrossOriginProtection()
	if u, err := url.Parse(h.oauth.RedirectURL); err == nil {
		if err := cross.AddTrustedOrigin(u.Scheme + "://" + u.Host); err != nil {
			panic(err) // New checked the URL
		}
	}
	return cross.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		c, err := r.Cookie(SessionCookie)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		if !safeMethod(r.Method) && !equal(r.Header.Get(CSRFHeader), csrfToken(c.Value)) {
			http.Error(w, "missing or wrong "+CSRFHeader, http.StatusForbidden)
			return
		}
		u, err := h.id.Session(r.Context(), c.Value)
		if errors.Is(err, identity.ErrNoSession) {
			setCookie(w, SessionCookie, "", -1)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		if err != nil {
			h.log.Error("session lookup", "err", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, u)))
	}))
}

// session tells the dashboard who is signed in and its CSRF token.
func (h *Handler) session(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie(SessionCookie) // present: RequireSession passed
	u := User(r.Context())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff") // holds the CSRF token
	_ = json.NewEncoder(w).Encode(map[string]any{
		"user":       map[string]any{"id": u.ID, "email": u.Email, "name": u.Name},
		"csrf_token": csrfToken(c.Value),
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
