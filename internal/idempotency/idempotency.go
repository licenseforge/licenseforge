// Package idempotency implements Idempotency-Key (ADR-0032, "Writes"): a POST
// that carries a key runs at most once per (tenant, credential, key) within
// 24 hours, and a retry gets the first outcome back.
//
// Do claims the key by inserting its row in the operation's own transaction,
// before the operation runs. A concurrent request with the same key waits on
// that row (the unique index) for at most Store.Wait, then gets
// ErrInProgress. The outcome is stored in the same transaction, so a crashed
// or failed request leaves no key, and a 5xx outcome is rolled back with the
// operation (it can be retried); 2xx and 4xx outcomes are stored.
//
// How the API layer uses it (one wrapper per idempotent operation): after
// authentication and tenant resolution (ADR-0032 steps 1-3), build a Request
// from the resolved tenant ID, the credential (token ID or user ID), the
// header, the operation ID, the resolved path parameter IDs and the raw
// body, and call Do with
//   - recheck: the operation's object lookup and permission checks (steps
//     4-5) for a replay. If they now refuse, that refusal is the answer and
//     the stored outcome isn't sent;
//   - op: the operation itself, in the transaction Do passes, returning the
//     status and response body it answers with. It must not write anything
//     it wouldn't keep when it answers 4xx (the transaction commits), and
//     records its refusal audit entries in that same transaction rather
//     than on a second pool connection.
//
// Errors map to 400 invalid_request (ErrInvalidKey), 422
// idempotency_key_reused (ErrKeyReused) and 409 idempotency_in_progress
// (ErrInProgress).
package idempotency

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"licenseforge.io/licenseforge/internal/secrets"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// DefaultWait bounds how long a request waits for a concurrent one with the
// same key. TTL is how long keys are kept.
const (
	DefaultWait = 5 * time.Second
	TTL         = 24 * time.Hour
)

var (
	// ErrInvalidKey means the key isn't 1-255 printable ASCII characters (or
	// the request has no valid tenant or credential).
	ErrInvalidKey = errors.New("idempotency: invalid Idempotency-Key")
	// ErrKeyReused means the key was used with a different request.
	ErrKeyReused = errors.New("idempotency: key reused with a different request")
	// ErrInProgress means a request with the same key is still running.
	ErrInProgress = errors.New("idempotency: a request with this key is in progress")

	errNotStored = errors.New("idempotency: outcome not stored") // rolls back a 5xx

	keyRE = regexp.MustCompile(`^[ -~]{1,255}$`)
)

// Store keeps idempotency keys in the tenant pool. Response bodies are
// stored encrypted with Keys, bound to their key row (they can carry
// secrets, such as a new license key). A replay reveals them again only to
// the same credential: the same API token, or the same user in any session.
//
// Master key rotation: keep a retired key in the keyring for at least TTL
// (24 hours) after it stops being active, or replays of rows encrypted under
// it fail with secrets.ErrUnknownKey (answered as a server error, so the
// client retries and, once the row expires, runs the request anew).
type Store struct {
	DB   *store.DB
	Keys *secrets.Keyring
	Wait time.Duration // 0: DefaultWait
}

// Request identifies a request. TenantID is the resolved tenant ID (not the
// slug from the path), Credential the API token or user ID, Operation the
// OpenAPI operation ID, Params the resolved path parameter IDs in route
// order (e.g. the license ID of POST …/licenses/{id}/activations).
type Request struct {
	TenantID, Credential, Key, Operation string
	Params                               []string
	Body                                 []byte
}

// Outcome is an operation's answer.
type Outcome struct {
	Status int
	Body   []byte
}

// Hash is the request hash: SHA-256 over the tenant ID, the operation, each
// path parameter and the body, each field length-prefixed so no two
// requests encode alike.
func (r Request) Hash() []byte {
	h := sha256.New()
	fields := [][]byte{[]byte(r.TenantID), []byte(r.Operation)}
	for _, p := range r.Params {
		fields = append(fields, []byte(p))
	}
	for _, f := range append(fields, r.Body) {
		h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(f))))
		h.Write(f)
	}
	return h.Sum(nil)
}

func (r Request) binding(rowID string) secrets.Binding {
	return secrets.Binding{Purpose: secrets.PurposeIdempotencyResponse, TenantID: r.TenantID, RowID: rowID}
}

// Do runs op at most once for r's key and returns its outcome; replayed is
// true when the outcome is the stored one of an earlier request (after
// recheck passed). See the package documentation.
func (s Store) Do(ctx context.Context, r Request, recheck func(context.Context, *ent.Tx) error,
	op func(context.Context, *ent.Tx) (Outcome, error)) (out Outcome, replayed bool, err error) {
	credential := ids.Valid("tok", r.Credential) || ids.Valid("usr", r.Credential)
	if !keyRE.MatchString(r.Key) || !ids.Valid("tnt", r.TenantID) || !credential || r.Operation == "" {
		return Outcome{}, false, ErrInvalidKey
	}
	wait := s.Wait
	if wait <= 0 {
		wait = DefaultWait
	}
	hash := r.Hash()
	err = s.DB.WithTenant(ctx, r.TenantID, func(tx *ent.Tx) error {
		claimed, id, err := claim(ctx, tx, r, hash, wait)
		if err != nil {
			return err
		}
		if !claimed {
			out, err = s.stored(ctx, tx, r, hash)
			if err != nil {
				return err
			}
			if err := recheck(ctx, tx); err != nil {
				return err
			}
			replayed = true
			return nil
		}
		if out, err = op(ctx, tx); err != nil {
			return err
		}
		switch {
		case out.Status >= 500 && out.Status <= 599:
			return errNotStored
		case out.Status/100 != 2 && out.Status/100 != 4:
			return fmt.Errorf("idempotency: status %d can't be stored", out.Status)
		}
		body, err := s.Keys.Encrypt(out.Body, r.binding(id))
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE idempotency_keys SET status = $2, body = $3 WHERE id = $1 AND status IS NULL`, id, out.Status, []byte(body))
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return errors.Join(errors.New("idempotency: claim lost"), err)
		}
		return nil
	})
	if errors.Is(err, errNotStored) {
		return out, false, nil
	}
	if err != nil {
		return Outcome{}, false, err
	}
	return out, replayed, nil
}

// claim inserts r's key, waiting at most wait for a concurrent claim of it
// to commit or roll back. It reports false if the key is already stored. An
// expired key (not yet cleaned up) is deleted first, so it is claimed anew.
func claim(ctx context.Context, tx *ent.Tx, r Request, hash []byte, wait time.Duration) (bool, string, error) {
	if _, err := tx.ExecContext(ctx, `SELECT set_config('lock_timeout', $1, true)`, strconv.FormatInt(wait.Milliseconds(), 10)+"ms"); err != nil {
		return false, "", err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM idempotency_keys WHERE tenant_id = $1 AND credential = $2 AND key = $3
		AND created_at < clock_timestamp() - interval '24 hours'`, r.TenantID, r.Credential, r.Key); err != nil {
		return false, "", inProgress(err)
	}
	id := ids.IdempotencyKey()
	rows, err := tx.QueryContext(ctx, `INSERT INTO idempotency_keys (id, tenant_id, credential, key, request_hash, created_at)
		VALUES ($1, $2, $3, $4, $5, clock_timestamp()) ON CONFLICT (tenant_id, credential, key) DO NOTHING RETURNING id`,
		id, r.TenantID, r.Credential, r.Key, hash)
	if err != nil {
		return false, "", inProgress(err)
	}
	claimed := rows.Next()
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return false, "", inProgress(err)
	}
	// The operation runs without the bound.
	if _, err := tx.ExecContext(ctx, `SET LOCAL lock_timeout TO DEFAULT`); err != nil {
		return false, "", err
	}
	return claimed, id, nil
}

// inProgress maps a lock timeout (waiting for a concurrent claim) to ErrInProgress.
func inProgress(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "55P03" {
		return ErrInProgress
	}
	return err
}

// stored returns the outcome stored for r's key, if r is the same request.
func (s Store) stored(ctx context.Context, tx *ent.Tx, r Request, hash []byte) (Outcome, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, request_hash, status, body FROM idempotency_keys WHERE tenant_id = $1 AND credential = $2 AND key = $3`,
		r.TenantID, r.Credential, r.Key)
	if err != nil {
		return Outcome{}, err
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return Outcome{}, errors.Join(ErrInProgress, rows.Err()) // removed meanwhile; the client retries
	}
	var id string
	var got []byte
	var status sql.NullInt64
	var body []byte
	if err := rows.Scan(&id, &got, &status, &body); err != nil {
		return Outcome{}, err
	}
	switch {
	case subtle.ConstantTimeCompare(got, hash) != 1:
		return Outcome{}, ErrKeyReused
	case !status.Valid:
		return Outcome{}, errors.New("idempotency: committed key without an outcome")
	}
	pt, err := s.Keys.Decrypt(string(body), r.binding(id))
	if err != nil {
		return Outcome{}, fmt.Errorf("idempotency: stored response: %w", err)
	}
	return Outcome{Status: int(status.Int64), Body: pt}, nil
}

// Cleanup deletes keys older than TTL in every tenant, on the platform pool,
// in batches, and returns how many it deleted. It is meant for a periodic
// job (the server's maintenance loop or a Kubernetes CronJob running
// `licenseforge maintenance`), hourly is enough: Do already ignores expired
// keys, so cleanup only bounds the table's size.
func Cleanup(ctx context.Context, db *store.DB) (int64, error) {
	var total int64
	for {
		var n int64
		err := db.WithPlatform(ctx, func(tx *ent.Tx) error {
			res, err := tx.ExecContext(ctx, `DELETE FROM idempotency_keys WHERE id IN (
				SELECT id FROM idempotency_keys WHERE created_at < clock_timestamp() - interval '24 hours' LIMIT 1000)`)
			if err != nil {
				return err
			}
			n, err = res.RowsAffected()
			return err
		})
		if err != nil {
			return total, err
		}
		total += n
		if n < 1000 {
			return total, nil
		}
	}
}
