//go:build windows || darwin

package fingerprint

import "testing"

// Runs on the Windows CI runner (macOS: on a Mac or a self-hosted runner;
// CI only compile-checks it): the OS source must return an ID.
func TestOSMachineIDSmoke(t *testing.T) {
	id, err := osMachineID()
	if err != nil || id == "" {
		t.Fatalf("osMachineID() = %q, %v", id, err)
	}
}
