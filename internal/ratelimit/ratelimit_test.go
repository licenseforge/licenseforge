package ratelimit

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func mustTrusted(t *testing.T, s string) []netip.Prefix {
	t.Helper()
	p, err := ParseTrusted(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func request(remote string, xff ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	r.RemoteAddr = remote
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

func TestClientAddr(t *testing.T) {
	proxies := mustTrusted(t, "10.0.0.0/8, 2001:db8:ffff::/48, 192.0.2.7")
	for name, c := range map[string]struct {
		remote string
		xff    []string
		want   string
	}{
		"no proxy header":                  {"203.0.113.9:4000", nil, "203.0.113.9"},
		"untrusted peer, spoofed header":   {"203.0.113.9:4000", []string{"198.51.100.1"}, "203.0.113.9"},
		"trusted peer":                     {"10.1.2.3:4000", []string{"203.0.113.9"}, "203.0.113.9"},
		"client's own claim is ignored":    {"10.1.2.3:4000", []string{"198.51.100.1, 203.0.113.9"}, "203.0.113.9"},
		"claims to be a trusted proxy":     {"10.1.2.3:4000", []string{"10.9.9.9, 203.0.113.9"}, "203.0.113.9"},
		"two trusted proxies":              {"10.1.2.3:4000", []string{"198.51.100.1, 203.0.113.9, 192.0.2.7"}, "203.0.113.9"},
		"header lines in order":            {"10.1.2.3:4000", []string{"198.51.100.1", "203.0.113.9"}, "203.0.113.9"},
		"malformed hop stops at the proxy": {"10.1.2.3:4000", []string{"203.0.113.9, garbage"}, "10.1.2.3"},
		"empty header":                     {"10.1.2.3:4000", []string{""}, "10.1.2.3"},
		"only trusted hops":                {"10.1.2.3:4000", []string{"10.5.5.5"}, "10.5.5.5"},
		"hop with port":                    {"10.1.2.3:4000", []string{"[2001:db8::1]:443"}, "2001:db8::1"},
		"IPv6 peer":                        {"[2001:db8::5]:4000", []string{"203.0.113.9"}, "2001:db8::5"},
		"trusted IPv6 proxy":               {"[2001:db8:ffff::1]:4000", []string{"2001:db8::5"}, "2001:db8::5"},
		"IPv4-mapped peer":                 {"[::ffff:10.1.2.3]:4000", []string{"203.0.113.9"}, "203.0.113.9"},
		"zone dropped":                     {"[fe80::1%eth0]:4000", nil, "fe80::1"},
	} {
		got, ok := ClientAddr(request(c.remote, c.xff...), proxies)
		if !ok || got.String() != c.want {
			t.Errorf("%s: %v %v, want %s", name, got, ok, c.want)
		}
	}
	if _, ok := ClientAddr(request("pipe"), proxies); ok {
		t.Error("a RemoteAddr that isn't an address resolved")
	}
	if got, _ := ClientAddr(request("10.1.2.3:4000", "203.0.113.9"), nil); got.String() != "10.1.2.3" {
		t.Errorf("no trusted proxies: %v", got)
	}
}

func TestParseTrusted(t *testing.T) {
	got, err := ParseTrusted(" 10.1.2.3/8 ,192.0.2.7, ::ffff:192.0.2.8, 2001:db8::/32, ::ffff:172.16.0.0/108,")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/8", "192.0.2.7/32", "192.0.2.8/32", "2001:db8::/32", "172.16.0.0/12"}
	if len(got) != len(want) {
		t.Fatalf("%v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("%d: %v, want %s", i, got[i], want[i])
		}
	}
	if p, err := ParseTrusted(""); err != nil || len(p) != 0 {
		t.Errorf("empty: %v %v", p, err)
	}
	for _, bad := range []string{"10.0.0.0/33", "proxy.local", "fe80::1%eth0", "10.0.0.1-10.0.0.9",
		"0.0.0.0/0", "::/0", "10.0.0.0/7", "2001:db8::/31", "::ffff:0.0.0.0/96", "::ffff:0.0.0.0/95", "10.0.0.0/8, 0.0.0.0/0"} {
		if _, err := ParseTrusted(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSurfaceOf(t *testing.T) {
	for p, want := range map[string]Surface{
		"/api/v1/activation/tenants/t/activate": Activation,
		"/api/v1/tenants/t/licenses":            Management,
		"/api/v1":                               Management,
		"/api/v1/activationx":                   Management,
		"/auth/login":                           Login,
		"/auth/callback":                        Login,
		"/auth/session":                         Management,
		"/auth/config":                          Management,
		"/healthz":                              None,
		"/readyz":                               None,
		"/":                                     None,
		"/assets/app.js":                        None,
		"/apix":                                 None,
		"/api/v1/../healthz":                    Management, // decoded %2e%2e: ServeMux routes it to /api/v1/
		"/api/v1/activation/../../x":            Activation,
	} {
		if got := SurfaceOf(p); got != want {
			t.Errorf("%s: %q, want %q", p, got, want)
		}
	}
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTest(c Config, at time.Time) (*Limiter, *clock, *int) {
	l := New(c)
	ck := &clock{at}
	l.now = ck.now
	calls := new(int)
	return l, ck, calls
}

func serve(l *Limiter, calls *int, remote, path string) *httptest.ResponseRecorder {
	h := l.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { *calls++ }))
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.RemoteAddr = remote
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

var start = time.Date(2026, 11, 5, 10, 0, 45, 0, time.UTC) // 15 s before the window ends

func TestLimitThen429(t *testing.T) {
	l, _, calls := newTest(Config{Quotas: map[Surface]int{Login: 3, Management: 5}}, start)
	refused := testutil.ToFloat64(Refused.WithLabelValues("login"))
	for i := range 3 {
		w := serve(l, calls, "203.0.113.9:1", "/auth/login")
		if w.Code != http.StatusOK || w.Header().Get("RateLimit") != `"address-login";r=`+strconv.Itoa(2-i)+`;t=15` ||
			w.Header().Get("RateLimit-Policy") != `"address-login";q=3;w=60` {
			t.Fatalf("request %d: %d %v", i, w.Code, w.Header())
		}
	}
	w := serve(l, calls, "203.0.113.9:2", "/auth/callback") // another port, same client and surface
	if w.Code != http.StatusTooManyRequests || *calls != 3 {
		t.Fatalf("4th: %d, handler ran %d times", w.Code, *calls)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if w.Header().Get("Retry-After") != "15" || w.Header().Get("Content-Type") != "application/problem+json" ||
		w.Header().Get("RateLimit") != `"address-login";r=0;t=15` || body["code"] != "rate_limited" || body["status"] != 429.0 ||
		w.Header().Get("X-Request-Id") == "" || body["request_id"] != w.Header().Get("X-Request-Id") {
		t.Errorf("429: %v %s", w.Header(), w.Body)
	}
	if got := testutil.ToFloat64(Refused.WithLabelValues("login")); got != refused+1 {
		t.Errorf("refused counter %v, want %v", got, refused+1)
	}
	// Other addresses, other surfaces and unlimited paths are unaffected.
	if w := serve(l, calls, "203.0.113.10:1", "/auth/login"); w.Code != http.StatusOK {
		t.Errorf("other address: %d", w.Code)
	}
	if w := serve(l, calls, "203.0.113.9:1", "/api/v1/tenants/t/licenses"); w.Code != http.StatusOK {
		t.Errorf("other surface: %d", w.Code)
	}
	if w := serve(l, calls, "203.0.113.9:1", "/healthz"); w.Code != http.StatusOK || w.Header().Get("RateLimit") != "" {
		t.Errorf("health check: %d %v", w.Code, w.Header())
	}
	// Activation's quota is unset: off.
	for range 10 {
		if w := serve(l, calls, "203.0.113.9:1", "/api/v1/activation/x"); w.Code != http.StatusOK || w.Header().Get("RateLimit") != "" {
			t.Fatalf("disabled surface: %d %v", w.Code, w.Header())
		}
	}
}

func TestSpoofedForwardedForDoesNotEscape(t *testing.T) {
	l, _, calls := newTest(Config{Quotas: map[Surface]int{Login: 2}, Trusted: mustTrusted(t, "10.0.0.0/8")}, start)
	h := l.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { *calls++ }))
	codes := []int{}
	for i := range 4 {
		r := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
		r.RemoteAddr = "203.0.113.9:1" // not a proxy: its header is the client's claim
		r.Header.Set("X-Forwarded-For", "198.51.100."+strconv.Itoa(1+i))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		codes = append(codes, w.Code)
	}
	if codes[2] != http.StatusTooManyRequests || codes[3] != http.StatusTooManyRequests {
		t.Errorf("rotating X-Forwarded-For from an untrusted peer: %v", codes)
	}
	// Behind the trusted proxy, clients are counted apart.
	for _, client := range []string{"198.51.100.1", "198.51.100.2"} {
		r := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
		r.RemoteAddr = "10.0.0.1:1"
		r.Header.Set("X-Forwarded-For", client)
		w := httptest.NewRecorder()
		var seen netip.Addr
		l.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seen, _ = Addr(r.Context()) })).ServeHTTP(w, r)
		if w.Code != http.StatusOK || seen.String() != client {
			t.Errorf("%s behind the proxy: %d, context address %v", client, w.Code, seen)
		}
	}
}

func TestWindowReset(t *testing.T) {
	l, ck, calls := newTest(Config{Quotas: map[Surface]int{Management: 1}}, start)
	serve(l, calls, "203.0.113.9:1", "/api/v1/x")
	if w := serve(l, calls, "203.0.113.9:1", "/api/v1/x"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("over quota: %d", w.Code)
	}
	ck.t = start.Add(14 * time.Second) // same window
	if w := serve(l, calls, "203.0.113.9:1", "/api/v1/x"); w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "1" {
		t.Fatalf("end of window: %d %v", w.Code, w.Header())
	}
	ck.t = start.Add(15 * time.Second) // next minute
	if w := serve(l, calls, "203.0.113.9:1", "/api/v1/x"); w.Code != http.StatusOK || w.Header().Get("RateLimit") != `"address-management";r=0;t=60` {
		t.Fatalf("new window: %d %v", w.Code, w.Header())
	}
}

func TestIPv6CountedPer64(t *testing.T) {
	l, _, calls := newTest(Config{Quotas: map[Surface]int{Login: 2}}, start)
	serve(l, calls, "[2001:db8:1:2::1]:1", "/auth/login")
	serve(l, calls, "[2001:db8:1:2::ffff]:1", "/auth/login")
	if w := serve(l, calls, "[2001:db8:1:2:aaaa::1]:1", "/auth/login"); w.Code != http.StatusTooManyRequests {
		t.Errorf("same /64: %d", w.Code)
	}
	if w := serve(l, calls, "[2001:db8:1:3::1]:1", "/auth/login"); w.Code != http.StatusOK {
		t.Errorf("other /64: %d", w.Code)
	}
}

// Past MaxAddresses, new addresses pass untracked (fail open) while tracked
// ones stay limited, and the table never grows past the bound.
func TestMemoryBound(t *testing.T) {
	l, ck, calls := newTest(Config{Quotas: map[Surface]int{Login: 1}, MaxAddresses: 2}, start)
	untracked := testutil.ToFloat64(Untracked.WithLabelValues("login"))
	serve(l, calls, "203.0.113.1:1", "/auth/login")
	serve(l, calls, "203.0.113.2:1", "/auth/login")
	for range 3 {
		if w := serve(l, calls, "203.0.113.3:1", "/auth/login"); w.Code != http.StatusOK || w.Header().Get("RateLimit") != "" {
			t.Fatalf("untracked address: %d %v", w.Code, w.Header())
		}
	}
	if w := serve(l, calls, "203.0.113.1:1", "/auth/login"); w.Code != http.StatusTooManyRequests {
		t.Errorf("tracked address after the bound: %d", w.Code)
	}
	if n := len(l.counts); n != 2 {
		t.Errorf("%d tracked, want 2", n)
	}
	if got := testutil.ToFloat64(Untracked.WithLabelValues("login")); got != untracked+3 {
		t.Errorf("untracked counter %v, want %v", got, untracked+3)
	}
	ck.t = start.Add(time.Minute) // a new window starts empty
	if w := serve(l, calls, "203.0.113.3:1", "/auth/login"); w.Code != http.StatusOK || !strings.Contains(w.Header().Get("RateLimit"), "r=0") {
		t.Errorf("new window: %d %v", w.Code, w.Header())
	}
	if n := len(l.counts); n != 1 {
		t.Errorf("new window tracks %d", n)
	}
}

// An encoded dot segment reaches the handler of the prefix it is under
// (ServeMux routes "/api/v1/%2e%2e/healthz" to "/api/v1/"), so it is limited
// as that surface, not as the path it would clean to.
func TestEncodedDotSegmentsAreLimited(t *testing.T) {
	l, _, _ := newTest(Config{Quotas: map[Surface]int{Management: 1}}, start)
	mux := http.NewServeMux()
	api := 0
	mux.HandleFunc("/api/v1/", func(http.ResponseWriter, *http.Request) { api++ })
	mux.HandleFunc("GET /healthz", func(http.ResponseWriter, *http.Request) {})
	h := l.Wrap(mux)
	var codes []int
	for range 2 {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/%2e%2e/healthz", nil)
		r.RemoteAddr = "203.0.113.9:1"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		codes = append(codes, w.Code)
	}
	if api != 1 || codes[1] != http.StatusTooManyRequests {
		t.Errorf("encoded dot segments: codes %v, API handler ran %d times", codes, api)
	}
}

// X-Forwarded-For from a peer that isn't trusted is ignored, counted each
// time and logged once, naming the peer and the setting.
func TestIgnoredForwardedForIsReported(t *testing.T) {
	var logs strings.Builder
	l := New(Config{Trusted: mustTrusted(t, "10.0.0.0/8"), Log: slog.New(slog.NewTextHandler(&logs, nil))})
	ignored := testutil.ToFloat64(IgnoredForwarded)
	for _, c := range []struct {
		remote, xff string
	}{
		{"203.0.113.9:1", "198.51.100.1"}, // untrusted: counted, logged
		{"203.0.113.9:1", "198.51.100.2"}, // counted, not logged again
		{"10.0.0.1:1", "198.51.100.3"},    // a trusted proxy: not counted
		{"203.0.113.9:1", ""},             // no header: not counted
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		l.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), r)
	}
	if got := testutil.ToFloat64(IgnoredForwarded); got != ignored+2 {
		t.Errorf("ignored counter %v, want %v", got, ignored+2)
	}
	if n := strings.Count(logs.String(), "LICENSEFORGE_TRUSTED_PROXIES"); n != 1 || !strings.Contains(logs.String(), "peer=203.0.113.9") {
		t.Errorf("want one warning naming the peer, got %q", logs.String())
	}
}
