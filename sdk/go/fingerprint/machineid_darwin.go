package fingerprint

import (
	"errors"
	"os/exec"
	"regexp"
)

var ioPlatformUUID = regexp.MustCompile(`"IOPlatformUUID" = "([0-9A-Fa-f-]{36})"`)

func osMachineID() (string, error) {
	out, err := exec.Command("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return "", err
	}
	m := ioPlatformUUID.FindSubmatch(out)
	if m == nil {
		return "", errors.New("IOPlatformUUID not found")
	}
	return string(m[1]), nil
}
