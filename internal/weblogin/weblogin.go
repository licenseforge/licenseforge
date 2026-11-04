// Package weblogin is the dashboard's OIDC login (ADR-0003, ADR-0020): the
// server is the relying party (Authorization Code + PKCE), verifies the ID
// token, and gives the browser only an opaque session cookie.
package weblogin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"licenseforge.io/licenseforge/internal/identity"
)

// Cookie names. The __Host- prefix makes the browser refuse them unless
// Secure, Path=/ and without Domain, so a sibling subdomain can't plant them.
const (
	SessionCookie = "__Host-lf_session"
	flowCookie    = "__Host-lf_login" // state, nonce and PKCE verifier of one login
	flowTTL       = 10 * time.Minute
)

// httpTimeout bounds every call to the provider (discovery, keys, token):
// go-oidc fetches keys in the background, and a hung fetch would otherwise
// block every login until a restart.
var httpTimeout = 10 * time.Second

// Config is the OIDC client registration.
type Config struct {
	Issuer       string // exactly as in the ID token's iss
	ClientID     string
	ClientSecret string // empty for a public client (PKCE only)
	RedirectURL  string // https://<host>/auth/callback
	Banner       string // system use notification (AC-8), plain text; empty = none
}

// MaxBannerLen bounds the login banner (bytes).
const MaxBannerLen = 4096

// checkBanner refuses a banner that isn't printable text: it is shown as
// text (never HTML), but control characters have no place in a notice or
// in the logs.
func checkBanner(b string) error {
	if len(b) > MaxBannerLen {
		return fmt.Errorf("weblogin: login banner is %d bytes, at most %d", len(b), MaxBannerLen)
	}
	if !utf8.ValidString(b) {
		return errors.New("weblogin: login banner is not UTF-8")
	}
	for _, r := range b {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return fmt.Errorf("weblogin: login banner has control character %U", r)
		}
	}
	return nil
}

// Handler serves GET /auth/login and GET /auth/callback.
type Handler struct {
	client           *http.Client
	oauth            oauth2.Config
	verify           *oidc.IDTokenVerifier
	id               identity.Service
	log              *slog.Logger
	cross            *http.CrossOriginProtection // trusts the redirect URL's origin
	banner, bannerID string                      // bannerID: hash the login page sends back as acknowledgement
}

// origin is the browser's Origin for u: lowercase host, no default port.
func origin(u string) (string, error) {
	p, err := url.Parse(u)
	if err != nil {
		return "", err
	}
	host, port := strings.ToLower(p.Hostname()), p.Port()
	if p.User != nil || strings.Contains(host, "%") {
		return "", fmt.Errorf("weblogin: %q: no userinfo or IPv6 zone", u)
	}
	if port == "" || p.Scheme == "https" && port == "443" || p.Scheme == "http" && port == "80" {
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		return p.Scheme + "://" + host, nil
	}
	return p.Scheme + "://" + net.JoinHostPort(host, port), nil
}

// secureURL reports whether u is https, or http on a loopback host (browsers
// keep Secure cookies only there).
func secureURL(u string) bool {
	p, err := url.Parse(u)
	if err != nil || p.Hostname() == "" {
		return false
	}
	if p.Scheme == "https" {
		return true
	}
	ip := net.ParseIP(p.Hostname())
	return p.Scheme == "http" && (p.Hostname() == "localhost" || ip != nil && ip.IsLoopback())
}

// New discovers the provider (fails if it is unreachable, like the database
// at start). Issuer and redirect URL must be https, or http on localhost for
// development.
func New(ctx context.Context, c Config, id identity.Service, log *slog.Logger) (*Handler, error) {
	c.Banner = strings.TrimSpace(strings.ReplaceAll(c.Banner, "\r\n", "\n"))
	if err := checkBanner(c.Banner); err != nil {
		return nil, err
	}
	var bannerID string
	if c.Banner != "" {
		sum := sha256.Sum256([]byte(c.Banner))
		bannerID = base64.RawURLEncoding.EncodeToString(sum[:16])
	}
	if c.Issuer == "" || c.ClientID == "" || c.RedirectURL == "" {
		return nil, errors.New("weblogin: issuer, client ID and redirect URL are required")
	}
	if !secureURL(c.Issuer) || !secureURL(c.RedirectURL) {
		return nil, errors.New("weblogin: issuer and redirect URL must be https (http only on localhost)")
	}
	own, err := origin(c.RedirectURL)
	if err != nil {
		return nil, err
	}
	cross := http.NewCrossOriginProtection()
	if err := cross.AddTrustedOrigin(own); err != nil {
		return nil, fmt.Errorf("weblogin: redirect URL: %w", err)
	}
	client := &http.Client{Timeout: httpTimeout}
	p, err := oidc.NewProvider(oidc.ClientContext(ctx, client), c.Issuer) // the provider keeps the client for key fetches
	if err != nil {
		return nil, fmt.Errorf("weblogin: discovery: %w", err)
	}
	return &Handler{
		client: client,
		oauth: oauth2.Config{
			ClientID: c.ClientID, ClientSecret: c.ClientSecret, RedirectURL: c.RedirectURL,
			Endpoint: p.Endpoint(), Scopes: []string{oidc.ScopeOpenID, "email", "profile"},
		},
		verify:   p.Verifier(&oidc.Config{ClientID: c.ClientID}),
		id:       id,
		log:      log,
		cross:    cross,
		banner:   c.Banner,
		bannerID: bannerID,
	}, nil
}

// Register adds the login routes to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/config", h.config)
	mux.HandleFunc("GET /auth/login", h.login)
	mux.HandleFunc("GET /auth/callback", h.callback)
	mux.Handle("GET /auth/session", h.RequireSession(http.HandlerFunc(h.session)))
	mux.Handle("POST /auth/logout", h.RequireSession(http.HandlerFunc(h.logout)))
}

func setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: maxAge,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

// config is what the login page needs before anyone signs in: the banner
// (AC-8) and its ID, which /auth/login wants back as the acknowledgement.
func (h *Handler) config(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_ = json.NewEncoder(w).Encode(map[string]string{"banner": h.banner, "banner_id": h.bannerID})
}

// login starts a login. With a banner configured it needs the banner's ID
// (?banner=, sent once the user agreed on /login), so no login skips the
// notice; anything else goes back to /login.
func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	if h.bannerID != "" && !equal(r.URL.Query().Get("banner"), h.bannerID) {
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	state, nonce, verifier := rand.Text(), rand.Text(), oauth2.GenerateVerifier()
	setCookie(w, flowCookie, state+"."+nonce+"."+verifier, int(flowTTL.Seconds()))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, h.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// fail logs the reason and shows the user only a status.
func (h *Handler) fail(w http.ResponseWriter, code int, reason string, err error) {
	h.log.Warn("login failed", "reason", reason, "err", err)
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, http.StatusText(code), code)
}

// callback finishes the login whose state matches the flow cookie. A request
// without that state (a stray or cross-site link) leaves the login in
// progress alone. ponytail: one login per browser at a time; a second tab's
// login replaces the first one's cookie, key the cookie by state if that
// bothers people.
func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c, err := r.Cookie(flowCookie)
	if err != nil {
		h.fail(w, http.StatusBadRequest, "no login in progress", err)
		return
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 3 || !equal(parts[0], q.Get("state")) {
		h.fail(w, http.StatusBadRequest, "state mismatch", nil)
		return
	}
	setCookie(w, flowCookie, "", -1) // one use, whatever happens next
	if e := q.Get("error"); e != "" {
		h.fail(w, http.StatusUnauthorized, "provider error", errors.New(e))
		return
	}
	nonce, verifier := parts[1], parts[2]

	ctx, cancel := context.WithTimeout(context.WithValue(r.Context(), oauth2.HTTPClient, h.client), 15*time.Second)
	defer cancel()
	tok, err := h.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		h.fail(w, http.StatusUnauthorized, "code exchange", err)
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := h.verify.Verify(ctx, raw) // signature, iss, aud, exp
	if err != nil {
		h.fail(w, http.StatusUnauthorized, "id token", err)
		return
	}
	if !equal(idt.Nonce, nonce) {
		h.fail(w, http.StatusUnauthorized, "nonce mismatch", nil)
		return
	}
	var claims struct {
		AuthorizedParty string   `json:"azp"`
		Email           string   `json:"email"`
		EmailVerified   flexBool `json:"email_verified"`
		Name            string   `json:"name"`
	}
	if err := idt.Claims(&claims); err != nil {
		h.fail(w, http.StatusUnauthorized, "id token claims", err)
		return
	}
	if claims.AuthorizedParty != "" && claims.AuthorizedParty != h.oauth.ClientID { // OIDC Core 3.1.3.7
		h.fail(w, http.StatusUnauthorized, "id token for another client (azp)", nil)
		return
	}
	u, err := h.id.Login(ctx, identity.Claims{
		Issuer: idt.Issuer, Subject: idt.Subject,
		Email: claims.Email, EmailVerified: bool(claims.EmailVerified), Name: claims.Name,
	})
	switch {
	case errors.Is(err, identity.ErrDisabled):
		h.fail(w, http.StatusForbidden, "user disabled", err)
		return
	case errors.Is(err, identity.ErrInvalidClaims):
		h.fail(w, http.StatusUnauthorized, "invalid claims", err)
		return
	case err != nil:
		h.fail(w, http.StatusInternalServerError, "login", err)
		return
	}
	// A fresh session on every login (no fixation); end the one presented.
	if old, err := r.Cookie(SessionCookie); err == nil {
		if err := h.id.EndSession(ctx, old.Value); err != nil {
			h.fail(w, http.StatusInternalServerError, "end old session", err)
			return
		}
	}
	cookie, err := h.id.NewSession(ctx, u.ID)
	if errors.Is(err, identity.ErrDisabled) { // disabled since Login
		h.fail(w, http.StatusForbidden, "user disabled", err)
		return
	}
	if err != nil {
		h.fail(w, http.StatusInternalServerError, "new session", err)
		return
	}
	// AC-8 evidence: this login started from an acknowledged banner (the
	// flow cookie exists only if /auth/login checked it).
	if h.bannerID != "" {
		h.log.Info("login banner acknowledged", "user", u.ID, "banner_id", h.bannerID)
	}
	setCookie(w, SessionCookie, cookie, int(h.id.SessionMaxAge().Seconds()))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// flexBool accepts true/false and "true"/"false": some providers (AWS
// Cognito among them) send email_verified as a string.
type flexBool bool

func (b *flexBool) UnmarshalJSON(data []byte) error {
	switch string(data) {
	case `true`, `"true"`:
		*b = true
	case `false`, `"false"`, `null`:
		*b = false
	default:
		var v bool
		return json.Unmarshal(data, &v) // reports the type error
	}
	return nil
}
