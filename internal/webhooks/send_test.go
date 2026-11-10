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
		"fd00:ec2::5":     false, // AWS service range, always
		"fd00:ec2::23":    false, // EKS Pod Identity
		"fd20:ce::254":    false, // Google Cloud metadata
		"fd00:1::1":       false, // other ULA, not allowlisted here
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
		"100:0:0:1::1":    false, // dummy IPv6 prefix (outside 2000::/3)
		"::ffff:0:a00:5":  false, // SIIT translated form
		"64:ff9b:2::1":    false,
		"4000::1":         false, // unallocated
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
	mux.HandleFunc("/down", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	mux.HandleFunc("/down-bare", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	mux.HandleFunc("/err-after", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/choices", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusMultipleChoices) })
	mux.HandleFunc("/headers", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Big", strings.Repeat("a", 100<<10))
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/odd", func(w http.ResponseWriter, _ *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		_, _ = buf.WriteString("HTTP/1.1 999 Odd\r\nContent-Length: 0\r\n\r\n")
		_ = buf.Flush()
		_ = conn.Close()
	})
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
		"/fail":      {Category: "http", Status: 500},
		"/gone":      {Category: "http", Status: 410},
		"/busy":      {Category: "http", Status: 429, RetryAfter: 2 * time.Minute},
		"/moved":     {Category: "redirect"},
		"/slow":      {Category: "timeout"},
		"/big":       {Category: "http", Status: 200},
		"/down":      {Category: "http", Status: 503, RetryAfter: 30 * time.Second},
		"/down-bare": {Category: "http", Status: 503},
		"/err-after": {Category: "http", Status: 500},
		"/choices":   {Category: "redirect"},
		"/headers":   {Category: "connection"},
		"/odd":       {Category: "connection"},
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
	if a, _ := Send(ctx, Guard{}.Client(), srv.URL+"/ok", "m", now, body, secret); a.Duration != 0 {
		t.Errorf("a refused connection reports its duration: %v", a.Duration)
	}
	if _, err := Send(ctx, c, strings.Replace(srv.URL, "https://", "http://", 1)+"/ok", "m", now, body, secret); err == nil {
		t.Error("plain http sent")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := Send(cancelled, c, srv.URL+"/ok", "m", now, body, secret); err == nil {
		t.Error("a cancelled send reported as an attempt")
	}
	short, stop := context.WithTimeout(ctx, 200*time.Millisecond)
	defer stop()
	if a, err := Send(short, testClient(srv, 5*time.Second), srv.URL+"/slow", "m", now, body, secret); err != nil || a.Category != "timeout" {
		t.Errorf("the caller's deadline: %+v, %v", a, err)
	}
	// No proxy from the environment.
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	if a, err := Send(ctx, testClient(srv, time.Second), srv.URL+"/ok", "m", now, body, secret); err != nil || !a.OK() {
		t.Errorf("went through the environment's proxy: %+v, %v", a, err)
	}
}

// The delivery client's settings that a loopback test server can't show:
// no proxy from the environment (Go never proxies loopback), TLS 1.2+.
func TestClientSettings(t *testing.T) {
	tr := Guard{}.Client().Transport.(*http.Transport)
	if tr.Proxy != nil || tr.TLSClientConfig.MinVersion < tls.VersionTLS12 || tr.DialContext == nil {
		t.Errorf("transport: proxy set %v, TLS min %x", tr.Proxy != nil, tr.TLSClientConfig.MinVersion)
	}
}

// Servers below TLS 1.2 are refused.
func TestSendOldTLS(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	srv.TLS = &tls.Config{MaxVersion: tls.VersionTLS11}
	srv.StartTLS()
	defer srv.Close()
	if a, err := Send(context.Background(), testClient(srv, time.Second), srv.URL, "m", time.Now(), nil, "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"); err != nil || a.Category != "tls" {
		t.Errorf("TLS 1.1 server: %+v, %v", a, err)
	}
}

func TestRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	for v, want := range map[string]time.Duration{
		"120": 2 * time.Minute, "0": 0, "-5": 0, "": 0, "soon": 0,
		"99999999":                      MaxRetryAfter,
		"99999999999999999999999":       MaxRetryAfter,
		"+60":                           0,
		"Tue, 10 Nov 2026 12:05:00 GMT": 5 * time.Minute,
		"Tue, 10 Nov 2026 11:00:00 GMT": 0,
		"Wed, 11 Nov 2026 12:00:00 GMT": MaxRetryAfter,
	} {
		if got := retryAfter(v, now); got != want {
			t.Errorf("%q: %v, want %v", v, got, want)
		}
	}
}

// One address per special range is refused by default; this host, link-local
// and metadata stay refused when everything is allowlisted; the deny list
// holds for NAT64 and IPv4-mapped forms; configured ports and prefixes.
func TestGuardRules(t *testing.T) {
	for _, a := range []string{"0.1.2.3", "10.1.1.1", "100.64.0.1", "127.0.0.2", "169.254.1.1", "172.31.1.1", "192.0.0.8", "192.0.2.1",
		"192.88.99.1", "192.168.0.1", "198.19.0.1", "198.51.100.1", "203.0.113.1", "239.1.1.1", "250.0.0.1",
		"::2", "::ffff:10.0.0.1", "64:ff9b:1::1", "100::1", "2001:2::1", "2001:db8::1", "2002::1", "3fff::1", "5f00::1", "fd12::1", "fe80::2", "fec0::1", "ff05::1"} {
		if (Guard{}).Allowed(netip.MustParseAddr(a)) {
			t.Errorf("%s allowed by default", a)
		}
	}
	all, err := ParseGuard("0.0.0.0/0,::/0", "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"0.0.0.0", "127.0.0.1", "169.254.169.254", "169.254.170.23", "::", "::1", "fe80::1", "fd00:ec2::254", "fd20:ce::254",
		"100.100.100.200", "192.0.0.192", "168.63.129.16", "64:ff9b::7f00:1", "::ffff:127.0.0.1"} {
		if all.Allowed(netip.MustParseAddr(a)) {
			t.Errorf("%s allowed with everything allowlisted", a)
		}
	}
	if !all.Allowed(netip.MustParseAddr("10.0.0.1")) || !all.Allowed(netip.MustParseAddr("fd12::1")) {
		t.Error("allowlist doesn't lift special ranges")
	}
	deny, err := ParseGuard("", "64:ff9b::/96, ::ffff:93.184.216.0/120", "8443")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"64:ff9b::808:808", "93.184.216.34", "::ffff:93.184.216.34"} { // 8.8.8.8 via NAT64: only the NAT64 deny matches
		if deny.Allowed(netip.MustParseAddr(a)) {
			t.Errorf("%s allowed past the deny list", a)
		}
	}
	if !deny.Allowed(netip.MustParseAddr("8.8.8.8")) {
		t.Error("8.8.8.8 refused")
	}
	if deny.control("tcp", "93.184.217.1:443", nil) == nil || deny.control("tcp", "93.184.217.1:8443", nil) != nil {
		t.Error("configured ports not applied")
	}
	if g, _ := ParseGuard("10.20.3.4/16", "", ""); g.Allow[0].String() != "10.20.0.0/16" {
		t.Errorf("prefix stored as %s", g.Allow[0])
	}
}
