package metrics

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func scrape(t *testing.T) string {
	t.Helper()
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape: %d", rec.Code)
	}
	return rec.Body.String()
}

// Requests are labelled by the pattern that matched, never the raw path, and
// by status class.
func TestInstrumentLabelsByRoutePattern(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /t/{tenant}/licenses/{id}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	mux.HandleFunc("GET /ok", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("GET /hints", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusEarlyHints) // informational: the final status follows
		w.WriteHeader(http.StatusNotFound)
	})
	h := Instrument(mux)
	for _, p := range []string{"/t/acme/licenses/lic_secret1", "/t/other/licenses/lic_secret2", "/ok", "/LF-KEY-in-a-path", "/hints"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, p, nil))
	}
	if n := testutil.ToFloat64(requests.WithLabelValues("GET /t/{tenant}/licenses/{id}", "4xx")); n != 2 {
		t.Errorf("pattern count = %v, want 2", n)
	}
	if n := testutil.ToFloat64(requests.WithLabelValues("GET /ok", "2xx")); n != 1 {
		t.Errorf("implicit 200 = %v", n)
	}
	if n := testutil.ToFloat64(requests.WithLabelValues("GET /hints", "4xx")); n != 1 {
		t.Errorf("1xx then 404 = %v, want one 4xx", n)
	}
	if n := testutil.ToFloat64(requests.WithLabelValues("unmatched", "4xx")); n != 1 {
		t.Errorf("unmatched = %v", n)
	}
	body := scrape(t)
	for _, leak := range []string{"acme", "lic_secret", "LF-KEY"} {
		if strings.Contains(body, leak) {
			t.Errorf("raw path value %q in metrics", leak)
		}
	}
	if !strings.Contains(body, `licenseforge_http_request_duration_seconds_count{route="GET /ok"} 1`) {
		t.Error("no duration for GET /ok")
	}
}

func TestCounters(t *testing.T) {
	before := testutil.ToFloat64(Logins.v.WithLabelValues("denied"))
	Logins.Inc(Denied)
	Activations.Inc(Success)
	UnknownLicenseKeys.Inc()
	if got := testutil.ToFloat64(Logins.v.WithLabelValues("denied")); got != before+1 {
		t.Errorf("logins denied = %v, want %v", got, before+1)
	}
	body := scrape(t)
	for _, want := range []string{`licenseforge_activations_total{outcome="success"} 1`, `licenseforge_activations_total{outcome="denied"} 0`,
		`licenseforge_lease_refreshes_total{outcome="failure"} 0`, "licenseforge_unknown_license_keys_total 1"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
}

func TestPools(t *testing.T) {
	SetPools(func() map[string]sql.DBStats {
		return map[string]sql.DBStats{"tenant": {OpenConnections: 3, InUse: 1, Idle: 2, WaitCount: 7}}
	})
	t.Cleanup(func() { pools.Store(nil) })
	body := scrape(t)
	for _, want := range []string{`licenseforge_db_pool_open_connections{pool="tenant"} 3`, `licenseforge_db_pool_in_use_connections{pool="tenant"} 1`,
		`licenseforge_db_pool_waits_total{pool="tenant"} 7`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
}
