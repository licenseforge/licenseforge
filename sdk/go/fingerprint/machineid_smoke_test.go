//go:build windows || darwin

package fingerprint

import "testing"

// Runs on the Windows and macOS CI runners: the OS source must return an ID.
func TestOSMachineIDSmoke(t *testing.T) {
	id, err := osMachineID()
	if err != nil || id == "" {
		t.Fatalf("osMachineID() = %q, %v", id, err)
	}
}
