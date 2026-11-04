package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"

	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/user"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// Session lifetimes (ADR-0020): a session ends after IdleTimeout without a
// request, and at most AbsoluteTimeout after login.
const (
	IdleTimeout     = time.Hour
	AbsoluteTimeout = 12 * time.Hour
	seenEvery       = time.Minute // last_seen_at is written at most this often
)

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

// NewSession starts a session for userID and returns the cookie value (the
// HTTP layer sets it HttpOnly, Secure, SameSite=Lax). Only its SHA-256 is
// stored. Times come from the database clock; the database refuses a
// session for a disabled user.
func (s Service) NewSession(ctx context.Context, userID string) (string, error) {
	var b [32]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails (Go 1.24+)
	cookie := base64.RawURLEncoding.EncodeToString(b[:])
	err := s.DB.WithIdentity(ctx, "", func(tx *ent.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, last_seen_at)
			VALUES ($1, $2, $3, clock_timestamp(), clock_timestamp() + $4::interval, clock_timestamp())`,
			ids.Session(), userID, sessionHash(cookie), AbsoluteTimeout.String())
		return err
	})
	if err != nil {
		return "", err
	}
	return cookie, nil
}

// Session returns the user of a live session and records the activity (at
// most once a minute).
func (s Service) Session(ctx context.Context, cookie string) (*ent.User, error) {
	if len(cookie) != cookieLen {
		return nil, ErrNoSession
	}
	var u *ent.User
	err := s.DB.WithIdentity(ctx, "", func(tx *ent.Tx) error {
		var id, userID string
		var lastSeen time.Time
		rows, err := tx.QueryContext(ctx, `SELECT s.id, s.user_id, s.last_seen_at FROM sessions s JOIN users u ON u.id = s.user_id
			WHERE s.token_hash = $1 AND s.expires_at > clock_timestamp()
			  AND s.last_seen_at > clock_timestamp() - $2::interval AND u.disabled_at IS NULL`,
			sessionHash(cookie), IdleTimeout.String())
		if err != nil {
			return err
		}
		if !rows.Next() {
			_ = rows.Close()
			return errors.Join(sql.ErrNoRows, rows.Err())
		}
		err = rows.Scan(&id, &userID, &lastSeen)
		if cerr := rows.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		if u, err = tx.User.Query().Where(user.ID(userID)).Only(ctx); err != nil {
			return err
		}
		if time.Since(lastSeen) > seenEvery {
			_, err = tx.ExecContext(ctx, `UPDATE sessions SET last_seen_at = clock_timestamp()
				WHERE id = $1 AND last_seen_at < clock_timestamp() - $2::interval`, id, seenEvery.String())
		}
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// EndSession ends the session (logout). Ending an unknown session is not an
// error.
func (s Service) EndSession(ctx context.Context, cookie string) error {
	return s.DB.WithIdentity(ctx, "", func(tx *ent.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = $1`, sessionHash(cookie))
		return err
	})
}
