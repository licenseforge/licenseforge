package weblogin

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"

	"licenseforge.io/licenseforge/internal/metrics"
	"licenseforge.io/licenseforge/internal/store/ids"
)

func logins(t *testing.T, outcome string) float64 {
	t.Helper()
	rec := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	m := regexp.MustCompile(`(?m)^licenseforge_logins_total\{outcome="` + outcome + `"\} (\S+)$`).FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("no logins_total{outcome=%q}", outcome)
	}
	v, _ := strconv.ParseFloat(m[1], 64)
	return v
}

func TestLoginMetrics(t *testing.T) {
	f := setup(t)
	ok, failed := logins(t, "success"), logins(t, "failure")
	q := f.start(t)
	if code := f.finish(t, q, q.Get("state"), map[string]any{"sub": ids.New("sub")}); code != http.StatusSeeOther {
		t.Fatalf("login: %d", code)
	}
	q = f.start(t)
	if code := f.finish(t, q, "wrong-state", nil); code != http.StatusBadRequest {
		t.Fatalf("bad login: %d", code)
	}
	if logins(t, "success") != ok+1 || logins(t, "failure") != failed+1 {
		t.Errorf("logins: success %v→%v, failure %v→%v", ok, logins(t, "success"), failed, logins(t, "failure"))
	}
}
