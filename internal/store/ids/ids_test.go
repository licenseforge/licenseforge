package ids

import "testing"

func TestValid(t *testing.T) {
	if id := License(); !Valid("lic", id) || Valid("cus", id) {
		t.Errorf("Valid(%q)", id)
	}
	for _, s := range []string{"", "lic_", "lic_aaaaaaaaaaaaaaaaaaaaaaaaa", "lic_aaaaaaaaaaaaaaaaaaaaaaaaaaa", "lic_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		"lic_aaaaaaaaaaaaaaaaaaaaaaaaa1", "lic-aaaaaaaaaaaaaaaaaaaaaaaaaa", "lic_aaaaaaaaaaaaaaaaaaaaaaaaa\x00", "lic_aaaaaaaaaaaaaaaaaaaaaaaaa\xff"} {
		if Valid("lic", s) {
			t.Errorf("Valid(%q) = true", s)
		}
	}
}
