package fingerprint

import (
	"errors"
	"os"
	"strings"
)

func osMachineID() (string, error) {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			return parseMachineID(string(b))
		}
	}
	return "", errors.New("no /etc/machine-id")
}

// parseMachineID validates the systemd format: 32 lowercase hex characters.
// An empty or "uninitialized" file (fresh images) is not a usable ID.
func parseMachineID(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) != 32 || strings.Trim(s, "0123456789abcdef") != "" {
		return "", errors.New("machine-id missing or uninitialized")
	}
	return s, nil
}
