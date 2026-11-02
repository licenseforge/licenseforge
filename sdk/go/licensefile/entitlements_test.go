package licensefile

import "testing"

func TestEntitlements(t *testing.T) {
	c, err := ParseClaims([]byte(`{"v":1,"lid":"l","product":"p","iat":"2026-11-01T00:00:00Z",
		"entitlements":{"features":["sso","export"],"limits":{"max_users":50,"nodes":-1,"seats":0}}}`))
	if err != nil {
		t.Fatal(err)
	}
	e := c.Entitlements
	for key, want := range map[string]bool{"sso": true, "export": true, "audit": false, "SSO": false, "": false} {
		if got := e.HasFeature(key); got != want {
			t.Errorf("HasFeature(%q) = %v, want %v", key, got, want)
		}
	}
	for key, want := range map[string]int64{"max_users": 50, "nodes": Unlimited, "seats": 0, "unknown": 0} {
		if got := e.Limit(key); got != want {
			t.Errorf("Limit(%q) = %d, want %d", key, got, want)
		}
	}
	for _, tc := range []struct {
		key  string
		n    int64
		want bool
	}{
		{"max_users", 50, true}, {"max_users", 51, false}, {"nodes", 1 << 40, true},
		{"seats", 0, true}, {"seats", 1, false}, {"unknown", 1, false}, {"unknown", 0, true},
		{"max_users", -1, false}, {"nodes", -1, false}, {"unknown", -3, false},
	} {
		if got := e.Allows(tc.key, tc.n); got != tc.want {
			t.Errorf("Allows(%q, %d) = %v, want %v", tc.key, tc.n, got, tc.want)
		}
	}
	// Features and limits are separate namespaces.
	if e.HasFeature("max_users") {
		t.Error("HasFeature must not look at limits")
	}
	// The 51st user on a 50-user license: callers pass the resulting total.
	users := make([]string, 50)
	if e.Allows("max_users", int64(len(users)+1)) {
		t.Error("adding a 51st user must not be allowed")
	}
	// A license with no entitlements at all.
	var none Entitlements
	if none.HasFeature("sso") || none.Limit("max_users") != 0 || none.Allows("max_users", 1) {
		t.Error("empty entitlements must grant nothing")
	}
}
