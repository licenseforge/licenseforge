package storetest

import "testing"

// Unset database URL: fail where skipping would hide tests that never ran.
func TestWithoutDatabase(t *testing.T) {
	for _, c := range []struct {
		env  map[string]string
		code int
	}{
		{nil, 0},
		{map[string]string{"CI": "true"}, 1},
		{map[string]string{"LICENSEFORGE_REQUIRE_TEST_DB": "1"}, 1},
	} {
		if code, _ := withoutDatabase(func(k string) string { return c.env[k] }); code != c.code {
			t.Errorf("%v: code %d, want %d", c.env, code, c.code)
		}
	}
}
