//go:build !linux && !windows && !darwin

package fingerprint

import "errors"

func osMachineID() (string, error) {
	return "", errors.New("no default machine ID on this OS")
}
