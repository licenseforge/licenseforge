package weblogin

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/identity"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// The session records how the login authenticated (ADR-0038), from the ID
// token's amr/acr/acrs/auth_time; malformed claims mean none, never a
// refused login. The login's audit entry carries the same.
func TestLoginRecordsAssurance(t *testing.T) {
	okta := identity.DefaultAssurancePolicy()
	okta.PhishingResistantACR = []string{"phr"}
	f := setupWith(t, func(c *Config, _ *identity.Service) { c.Assurance = &okta })
	authAt := time.Now().Add(-time.Minute).Truncate(time.Second)
	for _, tc := range []struct {
		name   string
		claims map[string]any
		want   authz.Assurance
		amr    string
	}{
		{"no amr", nil, authz.AssuranceNone, ""},
		{"password", map[string]any{"amr": []string{"pwd"}}, authz.AssuranceNone, "pwd"},
		{"otp", map[string]any{"amr": []string{"pwd", "otp"}}, authz.AssuranceMFA, "pwd otp"},
		{"security key", map[string]any{"amr": []string{"hwk"}, "auth_time": authAt.Unix()}, authz.AssurancePhishingResistant, "hwk"},
		{"okta phr", map[string]any{"amr": []string{"pwd"}, "acr": "phr"}, authz.AssurancePhishingResistant, "pwd"},
		{"amr as one string", map[string]any{"amr": "mfa"}, authz.AssuranceMFA, "mfa"},
		{"amr malformed", map[string]any{"amr": map[string]any{"x": 1}, "acr": 3, "auth_time": "soon"}, authz.AssuranceNone, ""},
		{"amr values not tokens", map[string]any{"amr": []any{"hw k", 7, "<script>"}}, authz.AssuranceNone, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := f.head(t)
			q := f.start(t)
			claims := map[string]any{"sub": ids.New("sub")}
			for k, v := range tc.claims {
				claims[k] = v
			}
			if code := f.finish(t, q, q.Get("state"), claims); code != http.StatusSeeOther {
				t.Fatalf("callback: %d", code)
			}
			_, level, err := f.ids.Session(context.Background(), f.session(t))
			if err != nil || level.Assurance != tc.want || level.ID == "" {
				t.Fatalf("session assurance %q, %v", level, err)
			}
			var s *ent.Session
			if err := f.db.WithPlatform(context.Background(), func(tx *ent.Tx) (err error) {
				s, err = tx.Session.Query().Order(ent.Desc("created_at")).First(context.Background())
				return
			}); err != nil {
				t.Fatal(err)
			}
			if string(s.Assurance) != string(tc.want) || s.Amr != tc.amr {
				t.Errorf("session row %+v", s)
			}
			if tc.name == "security key" && (s.AuthTime == nil || !s.AuthTime.Equal(authAt)) {
				t.Errorf("auth_time %v", s.AuthTime)
			}
			var login *ent.AuditEvent
			for _, e := range f.entries(t, before) {
				if e.Action == "user.login" {
					login = e
				}
			}
			if login == nil || !strings.Contains(login.Details, `"assurance":"`+string(tc.want)+`"`) {
				t.Errorf("login entry %+v", login)
			}
		})
	}
}
