package fingerprint

import "testing"

func TestParseMachineID(t *testing.T) {
	if id, err := parseMachineID("0123456789abcdef0123456789abcdef\n"); err != nil || id != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("valid: %q %v", id, err)
	}
	for _, bad := range []string{"", "uninitialized\n", "0123456789ABCDEF0123456789ABCDEF", "short"} {
		if _, err := parseMachineID(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
