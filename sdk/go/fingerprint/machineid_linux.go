package fingerprint

import (
	"bytes"
	"errors"
	"os"
	"strings"
)

type linuxFS struct {
	readFile func(string) ([]byte, error)
	exists   func(string) bool
}

func osMachineID() (string, error) {
	return linuxMachineID(linuxFS{
		readFile: os.ReadFile,
		exists:   func(p string) bool { _, err := os.Stat(p); return err == nil },
	})
}

// linuxMachineID returns a stable, unique machine ID or ErrNoFingerprint:
//   - a machine-id on tmpfs is regenerated every boot (systemd on read-only /etc): refused
//   - inside a container, only a host /etc/machine-id bind-mounted in is trusted;
//     an image's own machine-id is shared by every container started from it
//   - otherwise /etc/machine-id, falling back to /var/lib/dbus/machine-id
func linuxMachineID(fs linuxFS) (string, error) {
	mountinfo, _ := fs.readFile("/proc/self/mountinfo")
	fstype, mounted := mountFSType(mountinfo, "/etc/machine-id")
	if mounted && fstype == "tmpfs" {
		return "", ErrNoFingerprint
	}
	if inContainer(fs) {
		if !mounted {
			return "", ErrNoFingerprint
		}
		b, err := fs.readFile("/etc/machine-id")
		if err != nil {
			return "", ErrNoFingerprint
		}
		return parseMachineID(string(b))
	}
	var lastErr error = ErrNoFingerprint
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		b, err := fs.readFile(p)
		if err != nil {
			continue
		}
		id, err := parseMachineID(string(b))
		if err == nil {
			return id, nil
		}
		lastErr = err
	}
	return "", lastErr
}

// inContainer reports the common container markers (Docker, Podman, systemd
// containers incl. nspawn/LXC). Unreadable /proc/1/environ is ignored.
func inContainer(fs linuxFS) bool {
	if fs.exists("/.dockerenv") || fs.exists("/run/.containerenv") || fs.exists("/run/systemd/container") {
		return true
	}
	environ, err := fs.readFile("/proc/1/environ")
	if err != nil {
		return false
	}
	for _, kv := range bytes.Split(environ, []byte{0}) {
		if bytes.HasPrefix(kv, []byte("container=")) {
			return true
		}
	}
	return false
}

// mountFSType finds target in /proc/self/mountinfo and returns its filesystem type.
func mountFSType(mountinfo []byte, target string) (string, bool) {
	for _, line := range strings.Split(string(mountinfo), "\n") {
		pre, post, ok := strings.Cut(line, " - ")
		f := strings.Fields(pre)
		if !ok || len(f) < 5 || f[4] != target {
			continue
		}
		if g := strings.Fields(post); len(g) > 0 {
			return g[0], true
		}
	}
	return "", false
}

// parseMachineID validates the systemd format: 32 lowercase hex characters.
// An empty or "uninitialized" file (fresh images) is not a usable ID.
func parseMachineID(s string) (string, error) {
	s = trimASCII(s)
	if len(s) != 32 || strings.Trim(s, "0123456789abcdef") != "" {
		return "", errors.New("machine-id missing or uninitialized")
	}
	return s, nil
}
