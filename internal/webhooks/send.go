package webhooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Signature is the Standard Webhooks v1 webhook-signature header value:
// "v1," + base64 HMAC-SHA256 over "id.timestamp.body", one per secret,
// space-separated (current and, during a rotation, previous).
func Signature(id string, ts int64, body []byte, secrets ...string) (string, error) {
	sigs := make([]string, 0, len(secrets))
	for _, s := range secrets {
		key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, "whsec_"))
		if err != nil || !strings.HasPrefix(s, "whsec_") || len(key) == 0 {
			return "", errors.New("webhooks: malformed signing secret")
		}
		m := hmac.New(sha256.New, key)
		m.Write([]byte(id + "." + strconv.FormatInt(ts, 10) + "."))
		m.Write(body)
		sigs = append(sigs, "v1,"+base64.StdEncoding.EncodeToString(m.Sum(nil)))
	}
	if len(sigs) == 0 {
		return "", errors.New("webhooks: no signing secret")
	}
	return strings.Join(sigs, " "), nil
}

// Attempt is how one delivery went, in the delivery log's words (ADR-0044):
// category http (with Status), timeout, connection (a blocked address
// reads the same), tls or redirect. Never an address or a response body.
type Attempt struct {
	Category   string
	Status     int // http only
	Duration   time.Duration
	RetryAfter time.Duration // from a 429 or 503, capped at MaxRetryAfter
}

// OK reports a success: any 2xx.
func (a Attempt) OK() bool { return a.Category == "http" && a.Status >= 200 && a.Status <= 299 }

// MaxRetryAfter caps a receiver's Retry-After.
const MaxRetryAfter = 10 * time.Hour

// maxResponse is how much of a response is read (and discarded).
const maxResponse = 64 << 10

// Send POSTs one event: body, signed with secrets for webhook-id id at
// time now. It never follows redirects (c from Guard.Client).
func Send(ctx context.Context, c *http.Client, url, id string, now time.Time, body []byte, secrets ...string) (Attempt, error) {
	sig, err := Signature(id, now.Unix(), body, secrets...)
	if err != nil {
		return Attempt{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Attempt{}, err
	}
	if req.URL.Scheme != "https" {
		return Attempt{}, errors.New("webhooks: endpoint URL must be https")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "LicenseForge-Webhooks/1")
	req.Header.Set("webhook-id", id)
	req.Header.Set("webhook-timestamp", strconv.FormatInt(now.Unix(), 10))
	req.Header.Set("webhook-signature", sig)
	start := time.Now()
	resp, err := c.Do(req)
	a := Attempt{}
	if err != nil {
		// The caller stopped (shutting down): no attempt to record. A
		// deadline that passed is a timeout like any other.
		if errors.Is(ctx.Err(), context.Canceled) {
			return Attempt{}, ctx.Err()
		}
		a.Category = classify(err)
		if a.Category != "connection" { // a blocked destination fails at once: its duration would tell
			a.Duration = time.Since(start)
		}
		return a, nil
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
	_ = resp.Body.Close()
	a.Duration = time.Since(start)
	switch {
	case resp.StatusCode < 100 || resp.StatusCode > 599: // not HTTP as the delivery log records it
		a.Category, a.Duration = "connection", 0
	case resp.StatusCode >= 300 && resp.StatusCode <= 399:
		a.Category = "redirect"
	default:
		a.Category, a.Status = "http", resp.StatusCode
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			a.RetryAfter = retryAfter(resp.Header.Get("Retry-After"), time.Now())
		}
	}
	return a, nil
}

// classify names a transport failure.
func classify(err error) string {
	var ne net.Error
	var cv *tls.CertificateVerificationError
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ci x509.CertificateInvalidError
	var rh tls.RecordHeaderError
	var al tls.AlertError
	switch {
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		return "timeout"
	case errors.As(err, &cv), errors.As(err, &ua), errors.As(err, &hn), errors.As(err, &ci), errors.As(err, &rh), errors.As(err, &al),
		tlsText(err): // e.g. a protocol version below the minimum (untyped)
		return "tls"
	}
	return "connection"
}

// retryAfter parses a Retry-After header: seconds or an HTTP date.
func retryAfter(v string, now time.Time) time.Duration {
	var d time.Duration
	v = strings.TrimSpace(v)
	if v != "" && strings.Trim(v, "0123456789") == "" { // delay-seconds: 1*DIGIT
		s, err := strconv.ParseUint(v, 10, 64)
		if err != nil || s > uint64(MaxRetryAfter/time.Second) {
			return MaxRetryAfter
		}
		d = time.Duration(s) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
	}
	return max(0, min(d, MaxRetryAfter))
}

// tlsText reports an untyped crypto/tls error: the transport's own message,
// not the URL error around it (which can quote what the server sent).
func tlsText(err error) bool {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	m := err.Error()
	return strings.HasPrefix(m, "tls: ") || strings.HasPrefix(m, "remote error: tls: ")
}
