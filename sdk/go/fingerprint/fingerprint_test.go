package fingerprint

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func fakeEnv(vars map[string]string) env {
	return env{
		getenv:    func(k string) string { return vars[k] },
		k8s:       func(context.Context) (string, error) { return "kube-uid-1", nil },
		machineID: func() (string, error) { return "0123456789abcdef0123456789abcdef", nil },
	}
}

func TestComputeSourceOrder(t *testing.T) {
	override := func() (string, error) { return " serial-42\n", nil }
	k8sAndEnv := map[string]string{EnvOverride: " my-id ", "KUBERNETES_SERVICE_HOST": "10.0.0.1"}
	for _, tc := range []struct {
		name   string
		opts   Options
		vars   map[string]string
		source Source
		raw    string
		bind   string
	}{
		{"vendor override wins over everything", Options{Override: override, AllowEnvOverride: true}, k8sAndEnv, SourceOverride, "serial-42", "machine"},
		{"env override only when vendor allows it", Options{AllowEnvOverride: true}, k8sAndEnv, SourceEnv, "my-id", "machine"},
		{"env override ignored by default", Options{}, k8sAndEnv, SourceKubernetes, "kube-uid-1", "cluster"},
		{"machine id", Options{}, nil, SourceMachineID, "0123456789abcdef0123456789abcdef", "machine"},
		{"env trims ASCII whitespace only", Options{AllowEnvOverride: true}, map[string]string{EnvOverride: " x\t"}, SourceEnv, " x", "machine"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := compute(context.Background(), "tnt_acme", "acme-db", tc.opts, fakeEnv(tc.vars))
			if err != nil {
				t.Fatal(err)
			}
			want, _ := Hash("tnt_acme", "acme-db", tc.raw)
			if r.Source != tc.source || r.Fingerprint != want || r.Binding != tc.bind {
				t.Fatalf("got %+v, want source %s raw %q", r, tc.source, tc.raw)
			}
		})
	}
}

func TestComputeErrors(t *testing.T) {
	e := fakeEnv(map[string]string{"KUBERNETES_SERVICE_HOST": "10.0.0.1"})
	e.k8s = func(context.Context) (string, error) { return "", errors.New("forbidden") }
	if _, err := compute(context.Background(), "tnt_acme", "acme-db", Options{}, e); err == nil {
		t.Error("kubernetes failure must be an error, not a fallback to the node machine-id")
	}
	e = fakeEnv(nil)
	e.machineID = func() (string, error) { return "", ErrNoFingerprint }
	if _, err := compute(context.Background(), "tnt_acme", "acme-db", Options{}, e); !errors.Is(err, ErrNoFingerprint) {
		t.Errorf("got %v, want ErrNoFingerprint", err)
	}
	if _, err := compute(context.Background(), "tnt_acme", "acme-db", Options{Override: func() (string, error) { return " ", nil }}, fakeEnv(nil)); err == nil {
		t.Error("empty override must be an error")
	}
	for _, ids := range [][2]string{{"tnt_acme", ""}, {"", "acme-db"}, {"t\x00x", "p"}} {
		if _, err := compute(context.Background(), ids[0], ids[1], Options{}, fakeEnv(nil)); err == nil {
			t.Errorf("IDs %q must be an error", ids)
		}
	}
}

func mustHash(t *testing.T, tenant, product, raw string) string {
	t.Helper()
	h, err := Hash(tenant, product, raw)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestHash(t *testing.T) {
	if mustHash(t, "t1", "p", "id") == mustHash(t, "t2", "p", "id") || mustHash(t, "t", "p1", "id") == mustHash(t, "t", "p2", "id") {
		t.Fatal("different tenants or products must give different fingerprints")
	}
	// NUL in tenant or product would make the input ambiguous; it is rejected.
	for _, ids := range [][2]string{{"a\x00b", "c"}, {"a", "b\x00c"}, {"", "p"}, {"t", ""}, {"t\xff", "p"}} {
		if _, err := Hash(ids[0], ids[1], "id"); err == nil {
			t.Errorf("Hash(%q, %q) accepted", ids[0], ids[1])
		}
	}
	if _, err := Hash("t", "p", "bad\xffutf8"); err == nil {
		t.Error("invalid UTF-8 raw ID accepted")
	}
}

func TestNamespaceUID(t *testing.T) {
	var calls atomic.Int32
	failFirst := int32(0)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		switch {
		case n <= failFirst:
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		case r.Header.Get("Authorization") != "Bearer tok":
			http.Error(w, "forbidden", http.StatusForbidden)
		default:
			_, _ = w.Write([]byte(`{"metadata":{"name":"kube-system","uid":"5f0c-uid"}}`))
		}
	}))
	defer srv.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	backoff := []time.Duration{time.Millisecond, time.Millisecond}

	reset := func(fail int32) { calls.Store(0); failFirst = fail }

	reset(0)
	if uid, err := namespaceUID(context.Background(), srv.URL, "tok", ca, backoff); err != nil || uid != "5f0c-uid" {
		t.Fatalf("ok: %q, %v", uid, err)
	}
	reset(2)
	if uid, err := namespaceUID(context.Background(), srv.URL, "tok", ca, backoff); err != nil || uid != "5f0c-uid" || calls.Load() != 3 {
		t.Fatalf("retry: %q, %v after %d calls", uid, err, calls.Load())
	}
	reset(5)
	if _, err := namespaceUID(context.Background(), srv.URL, "tok", ca, backoff); !errors.Is(err, ErrTransient) || calls.Load() != 3 {
		t.Fatalf("persistent 503: %v after %d calls, want ErrTransient after 3", err, calls.Load())
	}
	reset(0)
	if _, err := namespaceUID(context.Background(), srv.URL, "wrong", ca, backoff); err == nil || errors.Is(err, ErrTransient) || calls.Load() != 1 {
		t.Fatalf("403 must fail at once and not be transient: %v after %d calls", err, calls.Load())
	}
	if _, err := namespaceUID(context.Background(), srv.URL, "tok", []byte("not a cert"), backoff); err == nil {
		t.Fatal("bad CA must fail")
	}
	// A CA that doesn't match the server is a permanent error, not retried.
	otherCA := selfSignedCA(t)
	reset(0)
	if _, err := namespaceUID(context.Background(), srv.URL, "tok", otherCA, backoff); err == nil || errors.Is(err, ErrTransient) || calls.Load() != 0 {
		t.Fatalf("wrong CA: %v after %d calls, want a permanent error", err, calls.Load())
	}
	// Cancellation stops the retries.
	reset(5)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := namespaceUID(ctx, srv.URL, "tok", ca, []time.Duration{time.Hour}); !errors.Is(err, ErrTransient) {
		t.Fatalf("canceled: %v", err)
	}
}

// selfSignedCA returns an unrelated CA certificate (httptest servers all share one).
func selfSignedCA(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "other-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
