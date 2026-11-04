// Package weblogin is the dashboard's OIDC login (ADR-0003, ADR-0020): the
// server is the relying party (Authorization Code + PKCE), verifies the ID
// token, and gives the browser only an opaque session cookie.
package weblogin

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

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

// Config is the OIDC client registration.
type Config struct {
	Issuer       string // exactly as in the ID token's iss
	ClientID     string
	ClientSecret string // empty for a public client (PKCE only)
	RedirectURL  string // https://<host>/auth/callback
}

// Handler serves GET /auth/login and GET /auth/callback.
type Handler struct {
	oauth  oauth2.Config
	verify *oidc.IDTokenVerifier
	id     identity.Service
	log    *slog.Logger
}

// New discovers the provider (fails if it is unreachable, like the database
// at start).
func New(ctx context.Context, c Config, id identity.Service, log *slog.Logger) (*Handler, error) {
	if c.Issuer == "" || c.ClientID == "" || c.RedirectURL == "" {
		return nil, errors.New("weblogin: issuer, client ID and redirect URL are required")
	}
	p, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		return nil, fmt.Errorf("weblogin: discovery: %w", err)
	}
	return &Handler{
		oauth: oauth2.Config{
			ClientID: c.ClientID, ClientSecret: c.ClientSecret, RedirectURL: c.RedirectURL,
			Endpoint: p.Endpoint(), Scopes: []string{oidc.ScopeOpenID, "email", "profile"},
		},
		verify: p.Verifier(&oidc.Config{ClientID: c.ClientID}),
		id:     id,
		log:    log,
	}, nil
}

// Register adds the login routes to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/login", h.login)
	mux.HandleFunc("GET /auth/callback", h.callback)
}

func setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: maxAge,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
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

func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	setCookie(w, flowCookie, "", -1) // one use, whatever happens
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		h.fail(w, http.StatusUnauthorized, "provider error", errors.New(e))
		return
	}
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
	nonce, verifier := parts[1], parts[2]

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
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
		Email         string   `json:"email"`
		EmailVerified flexBool `json:"email_verified"`
		Name          string   `json:"name"`
	}
	if err := idt.Claims(&claims); err != nil {
		h.fail(w, http.StatusUnauthorized, "id token claims", err)
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
	if err != nil {
		h.fail(w, http.StatusInternalServerError, "new session", err)
		return
	}
	setCookie(w, SessionCookie, cookie, int(identity.AbsoluteTimeout.Seconds()))
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
