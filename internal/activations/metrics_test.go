package activations

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"

	"licenseforge.io/licenseforge/internal/licensekey"
	"licenseforge.io/licenseforge/internal/metrics"
)

func metric(t *testing.T, series string) float64 {
	t.Helper()
	rec := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	m := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(series) + ` (\S+)$`).FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("no series %s", series)
	}
	v, _ := strconv.ParseFloat(m[1], 64)
	return v
}

// Outcomes are counted (ADR-0027: high volume, not audited); unknown keys on their own (ADR-0034).
func TestOutcomeMetrics(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	series := []string{`licenseforge_activations_total{outcome="success"}`, `licenseforge_activations_total{outcome="denied"}`,
		`licenseforge_activations_total{outcome="failure"}`, `licenseforge_lease_refreshes_total{outcome="success"}`,
		`licenseforge_lease_refreshes_total{outcome="denied"}`, "licenseforge_unknown_license_keys_total"}
	before := map[string]float64{}
	for _, s := range series {
		before[s] = metric(t, s)
	}
	is := f.issue(t, "pro")
	machine := fp()
	if _, err := f.s.Activate(ctx, f.req(is.Key, machine)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Refresh(ctx, f.req(is.Key, machine)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Refresh(ctx, f.req(is.Key, fp())); err == nil { // not activated: a valid key refused
		t.Fatal("refresh of an unknown machine")
	}
	if _, err := f.s.Activate(ctx, f.req(licensekey.New(), fp())); err == nil {
		t.Fatal("unknown key activated")
	}
	want := map[string]float64{series[0]: 1, series[1]: 0, series[2]: 1, series[3]: 1, series[4]: 1, series[5]: 1}
	for _, s := range series {
		if got := metric(t, s) - before[s]; got != want[s] {
			t.Errorf("%s moved by %v, want %v", s, got, want[s])
		}
	}
}
