package webhooks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The Standard Webhooks reference vector (standard-webhooks libraries' tests).
func TestSignatureVector(t *testing.T) {
	got, err := Signature("msg_p5jXN8AQM9LWM0D4loKWxJek", 1614265330, []byte(`{"test": 2432232314}`), "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")
	if err != nil || got != "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=" {
		t.Errorf("Signature = %q, %v", got, err)
	}
	two, err := Signature("msg_p5jXN8AQM9LWM0D4loKWxJek", 1614265330, []byte(`{"test": 2432232314}`), "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw", "whsec_"+strings.Repeat("A", 44))
	if err != nil || !strings.HasPrefix(two, got+" v1,") || strings.Count(two, "v1,") != 2 {
		t.Errorf("two secrets = %q, %v", two, err)
	}
	for _, bad := range [][]string{nil, {"MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"}, {"whsec_not base64!"}, {"whsec_"}} {
		if _, err := Signature("m", 1, nil, bad...); err == nil {
			t.Errorf("secret %q accepted", bad)
		}
	}
}

func TestGuardAllowed(t *testing.T) {
	g, err := ParseGuard("10.20.0.0/16, fd00:ec2::/32, 100.64.0.0/10", "203.0.114.0/24,2001:67c::/32", "")
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]bool{
		"93.184.216.34": true, "2606:2800:220:1::1": true, // public
		"10.0.0.5": false, "172.16.1.1": false, "192.168.1.1": false, // private
		"10.20.3.4":       true,  // allowlisted
		"127.0.0.1":       false, // loopback
		"0.0.0.0":         false,
		"169.254.169.254": false, // metadata (link-local, always)
		"100.64.1.1":      true,  // CGNAT, allowlisted ...
		"100.100.100.200": false, // ... but Alibaba metadata stays refused
		"fd00:ec2::254":   false, // AWS IPv6 metadata stays refused in an allowlisted range
		"fd00:ec2::5":     true,
		"168.63.129.16":   false, // Azure, globally routable
		"192.0.0.192":     false, "198.18.0.1": false, "240.0.0.1": false, "224.0.0.1": false, "255.255.255.255": false,
		"203.0.114.9":          false, // operator deny
		"::1":                  false,
		"::":                   false,
		"::ffff:10.0.0.5":      false, // IPv4-mapped, checked as IPv4
		"::ffff:93.184.216.34": true,
		"::10.0.0.5":           false, // IPv4-compatible
		"64:ff9b::a00:5":       false, // NAT64 of 10.0.0.5
		"64:ff9b::5db8:d822":   true,  // NAT64 of 93.184.216.34
		"64:ff9b::7f00:1":      false, // NAT64 of 127.0.0.1
		"64:ff9b:1::5db8:d822": false, // local-use NAT64: refused
		"2002:a00:5::1":        false, // 6to4
		"2001:0:4136:e378::1":  false, // Teredo
		"2001:db8::1":          false,
		"fc00::1":              false, "fe80::1": false, "ff02::1": false, "fec0::1": false,
		"2001:67c:2e8::1": false, // operator deny (IPv6)
		"fe80::1%eth0":    false,
	} {
		if got := g.Allowed(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: %v, want %v", addr, got, want)
		}
	}
	// The dialer's Control sees addresses and ports.
	for address, ok := range map[string]bool{"93.184.216.34:443": true, "93.184.216.34:8443": false, "10.0.0.5:443": false, "[2606:2800:220:1::1]:443": true} {
		if err := g.control("tcp", address, nil); (err == nil) != ok {
			t.Errorf("control %s: %v", address, err)
		}
	}
	if g8, _ := ParseGuard("", "", "443,8443"); g8.control("tcp", "93.184.216.34:8443", nil) != nil {
		t.Error("allowed port refused")
	}
	for _, bad := range [][3]string{{"10.0.0.0/33", "", ""}, {"", "nope", ""}, {"", "", "0"}, {"", "", "70000"}, {"", "", "x"}} {
		if _, err := ParseGuard(bad[0], bad[1], bad[2]); err == nil {
			t.Errorf("ParseGuard%q accepted", bad)
		}
	}
}

// A client that may reach the test server (loopback is always refused by
// the guard) and trusts its certificate.
func testClient(srv *httptest.Server, timeout time.Duration) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	allow := func(string, string, syscall.RawConn) error { return nil }
	return client(allow, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, timeout)
}

func TestSend(t *testing.T) {
	var hits atomic.Int32
	var got http.Header
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/fail", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
	mux.HandleFunc("/gone", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusGone) })
	mux.HandleFunc("/busy", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	mux.HandleFunc("/moved", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/target", http.StatusFound) })
	mux.HandleFunc("/target", func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) })
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(make([]byte, 1<<20)) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	c := testClient(srv, time.Second)
	ctx := context.Background()
	now := time.Unix(1614265330, 0)
	secret := "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
	body := []byte(`{"test": 2432232314}`)
	a, err := Send(ctx, c, srv.URL+"/ok", "msg_p5jXN8AQM9LWM0D4loKWxJek", now, body, secret)
	if err != nil || !a.OK() || a.Status != 204 {
		t.Fatalf("ok: %+v, %v", a, err)
	}
	if got.Get("webhook-id") != "msg_p5jXN8AQM9LWM0D4loKWxJek" || got.Get("webhook-timestamp") != "1614265330" ||
		got.Get("webhook-signature") != "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=" || got.Get("Content-Type") != "application/json" {
		t.Errorf("headers %v", got)
	}
	for path, want := range map[string]Attempt{
		"/fail":  {Category: "http", Status: 500},
		"/gone":  {Category: "http", Status: 410},
		"/busy":  {Category: "http", Status: 429, RetryAfter: 2 * time.Minute},
		"/moved": {Category: "redirect"},
		"/slow":  {Category: "timeout"},
		"/big":   {Category: "http", Status: 200},
	} {
		a, err := Send(ctx, c, srv.URL+path, "msg_1", now, body, secret)
		if err != nil || a.Category != want.Category || a.Status != want.Status || a.RetryAfter != want.RetryAfter || (a.OK() != (want.Status == 200)) {
			t.Errorf("%s: %+v, %v", path, a, err)
		}
	}
	if hits.Load() != 0 {
		t.Error("a redirect was followed")
	}
	// An untrusted certificate is tls; the real guard refuses loopback.
	if a, _ := Send(ctx, client(func(string, string, syscall.RawConn) error { return nil }, nil, time.Second), srv.URL+"/ok", "m", now, body, secret); a.Category != "tls" {
		t.Errorf("untrusted certificate: %+v", a)
	}
	if a, _ := Send(ctx, Guard{}.Client(), srv.URL+"/ok", "m", now, body, secret); a.Category != "connection" {
		t.Errorf("loopback through the guard: %+v", a)
	}
	if _, err := Send(ctx, c, srv.URL+"/ok", "m", now, body, "bad"); err == nil {
		t.Error("bad secret sent")
	}
}

func TestRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	for v, want := range map[string]time.Duration{
		"120": 2 * time.Minute, "0": 0, "-5": 0, "": 0, "soon": 0,
		"99999999":                      MaxRetryAfter,
		"Tue, 10 Nov 2026 12:05:00 GMT": 5 * time.Minute,
		"Tue, 10 Nov 2026 11:00:00 GMT": 0,
		"Wed, 11 Nov 2026 12:00:00 GMT": MaxRetryAfter,
	} {
		if got := retryAfter(v, now); got != want {
			t.Errorf("%q: %v, want %v", v, got, want)
		}
	}
}
