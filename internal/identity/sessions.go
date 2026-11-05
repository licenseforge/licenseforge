package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/user"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// Session lifetimes (ADR-0020, ADR-0024 AC-12): a session ends after the idle
// timeout without a request, and at most its max age after login. Service
// uses these defaults for zero values.
const (
	DefaultIdleTimeout = time.Hour
	DefaultMaxAge      = 12 * time.Hour
	seenEvery          = time.Minute // last_seen_at is written at most this often
)

// Bounds for configured timeouts. The database caps a session at a day
// (CHECK and insert policy on sessions).
const (
	MinIdleTimeout = 5 * time.Minute
	MinMaxAge      = time.Hour
	MaxMaxAge      = 24 * time.Hour
)

// CheckSessionTimeouts reports whether idle and maxAge are within bounds:
// idle from MinIdleTimeout up to maxAge, maxAge from MinMaxAge to MaxMaxAge
// (so idle is at most a day too).
func CheckSessionTimeouts(idle, maxAge time.Duration) error {
	switch {
	case idle < MinIdleTimeout:
		return fmt.Errorf("identity: idle timeout %v: want at least %v", idle, MinIdleTimeout)
	case maxAge < MinMaxAge || maxAge > MaxMaxAge:
		return fmt.Errorf("identity: session max age %v: want %v to %v", maxAge, MinMaxAge, MaxMaxAge)
	case maxAge < idle:
		return fmt.Errorf("identity: session max age %v is below the idle timeout %v", maxAge, idle)
	}
	return nil
}

func (s Service) idleTimeout() time.Duration {
	if s.IdleTimeout == 0 {
		return DefaultIdleTimeout
	}
	return s.IdleTimeout
}

// SessionMaxAge is the lifetime of new sessions (the cookie's Max-Age).
func (s Service) SessionMaxAge() time.Duration {
	if s.MaxAge == 0 {
		return DefaultMaxAge
	}
	return s.MaxAge
}

// ErrNoSession means the cookie names no live session: unknown, malformed,
// ended, idle too long, expired, or its user is disabled. Callers send the
// user to log in again.
var ErrNoSession = errors.New("identity: no session")

// cookieLen is the base64url length of a 256-bit session secret.
const cookieLen = 43

func sessionHash(cookie string) []byte {
	h := sha256.Sum256([]byte(cookie))
	return h[:]
}

// NewSession starts a session for userID, authenticated as auth says
// (ADR-0038; stored with it, never changed), and returns the cookie value
// (the HTTP layer sets it HttpOnly, Secure, SameSite=Lax). Only its SHA-256
// is stored. Times come from the database clock. A disabled user gets
// ErrDisabled; the user row is share-locked so a concurrent DisableUser
// either sees this session (and deletes it) or is seen first.
func (s Service) NewSession(ctx context.Context, userID string, auth SessionAuth) (string, error) {
	if !auth.Assurance.Valid() {
		return "", fmt.Errorf("identity: session assurance %q", auth.Assurance)
	}
	var acr *string
	if auth.ACR != "" {
		acr = &auth.ACR
	}
	var b [32]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails (Go 1.24+)
	cookie := base64.RawURLEncoding.EncodeToString(b[:])
	err := s.DB.WithIdentity(ctx, "", func(tx *ent.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT 1 FROM users WHERE id = $1 AND disabled_at IS NULL FOR SHARE`, userID)
		if err != nil {
			return err
		}
		enabled := rows.Next()
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return err
		}
		if !enabled {
			return ErrDisabled
		}
		// One clock reading for all three times: a full-day session must not
		// end a microsecond past the database's one-day CHECK.
		_, err = tx.ExecContext(ctx, `INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, last_seen_at, assurance, amr, acr, acrs, auth_time)
			SELECT $1, $2, $3, n, n + make_interval(secs => $4), n, $5, $6, $7, $8, $9 FROM clock_timestamp() n`,
			ids.Session(), userID, sessionHash(cookie), s.SessionMaxAge().Seconds(),
			string(auth.Assurance), strings.Join(auth.AMR, " "), acr, strings.Join(auth.ACRs, " "), auth.AuthTime)
		return err
	})
	if err != nil {
		return "", err
	}
	return cookie, nil
}

// Session returns the user of a live session and the assurance its login
// proved (ADR-0038), and records the activity (at most once a minute).
func (s Service) Session(ctx context.Context, cookie string) (*ent.User, authz.Assurance, error) {
	if len(cookie) != cookieLen {
		return nil, "", ErrNoSession
	}
	var u *ent.User
	var level authz.Assurance
	err := s.DB.WithIdentity(ctx, "", func(tx *ent.Tx) error {
		var id, userID string
		rows, err := tx.QueryContext(ctx, `SELECT s.id, s.user_id, s.assurance FROM sessions s JOIN users u ON u.id = s.user_id
			WHERE s.token_hash = $1 AND s.expires_at > clock_timestamp()
			  AND s.last_seen_at > clock_timestamp() - make_interval(secs => $2) AND u.disabled_at IS NULL`,
			sessionHash(cookie), s.idleTimeout().Seconds())
		if err != nil {
			return err
		}
		if !rows.Next() {
			_ = rows.Close()
			return errors.Join(sql.ErrNoRows, rows.Err())
		}
		err = rows.Scan(&id, &userID, &level)
		if cerr := rows.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		// Checked again: the user may have been disabled since the join.
		if u, err = tx.User.Query().Where(user.ID(userID), user.DisabledAtIsNil()).Only(ctx); ent.IsNotFound(err) {
			return sql.ErrNoRows
		} else if err != nil {
			return err
		}
		// Decided by the database clock: touches no row until it is due.
		_, err = tx.ExecContext(ctx, `UPDATE sessions SET last_seen_at = clock_timestamp()
			WHERE id = $1 AND last_seen_at < clock_timestamp() - make_interval(secs => $2)`, id, seenEvery.Seconds())
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", ErrNoSession
	}
	if err != nil {
		return nil, "", err
	}
	return u, level, nil
}

// EndSession ends the session (logout). Ending an unknown session is not an
// error.
func (s Service) EndSession(ctx context.Context, cookie string) error {
	return s.DB.WithIdentity(ctx, "", func(tx *ent.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = $1`, sessionHash(cookie))
		return err
	})
}
