package fingerprint

import (
	"bytes"
	"errors"
	"os"
	"strconv"
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
//   - a machine-id on tmpfs/ramfs (the file itself, /etc or /) is regenerated
//     every boot: refused
//   - in an application container (Docker, Podman, OCI) only the host's
//     /etc/machine-id bind-mounted in is trusted; an image's own machine-id is
//     shared by every container started from it
//   - otherwise (hosts, VMs, LXC/nspawn system containers) /etc/machine-id,
//     falling back to /var/lib/dbus/machine-id
func linuxMachineID(fs linuxFS) (string, error) {
	mountinfo, _ := fs.readFile("/proc/self/mountinfo")
	m, found := containingMount(mountinfo, "/etc/machine-id")
	if found && (m.fstype == "tmpfs" || m.fstype == "ramfs") {
		return "", ErrNoFingerprint
	}
	if appContainer(fs) {
		// Trust only a bind mount of a file that is itself a machine-id
		// (mount root ends in /etc/machine-id), not an arbitrary shared file.
		if !found || m.point != "/etc/machine-id" || !strings.HasSuffix(m.root, "/etc/machine-id") {
			return "", ErrNoFingerprint
		}
		b, err := fs.readFile("/etc/machine-id")
		if err != nil {
			return "", ErrNoFingerprint
		}
		return parseMachineID(string(b))
	}
	lastErr := ErrNoFingerprint
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

// appContainer reports application containers, whose machine-id comes from
// the image. System containers (container=lxc, lxc-libvirt, systemd-nspawn)
// keep their own machine-id like a VM and are not counted. Unknown container
// types are treated as application containers (fail closed).
func appContainer(fs linuxFS) bool {
	if fs.exists("/.dockerenv") || fs.exists("/run/.containerenv") {
		return true
	}
	kind := ""
	if b, err := fs.readFile("/run/systemd/container"); err == nil {
		kind = trimASCII(string(b))
	} else if environ, err := fs.readFile("/proc/1/environ"); err == nil {
		for _, kv := range bytes.Split(environ, []byte{0}) {
			if v, ok := bytes.CutPrefix(kv, []byte("container=")); ok {
				kind = string(v)
			}
		}
	}
	switch kind {
	case "", "lxc", "lxc-libvirt", "systemd-nspawn":
		return false
	default:
		return true
	}
}

type mount struct{ root, point, fstype string }

// containingMount returns the mount that holds path: the longest mount point
// that is path or a parent of it, using the last entry for that mount point
// (later mounts stack on top of earlier ones).
func containingMount(mountinfo []byte, path string) (mount, bool) {
	var best mount
	found := false
	for _, line := range strings.Split(string(mountinfo), "\n") {
		pre, post, ok := strings.Cut(line, " - ")
		f, g := strings.Fields(pre), strings.Fields(post)
		if !ok || len(f) < 5 || len(g) < 1 {
			continue
		}
		m := mount{root: unescapeMount(f[3]), point: unescapeMount(f[4]), fstype: g[0]}
		if !isParentOrSelf(m.point, path) {
			continue
		}
		if !found || len(m.point) >= len(best.point) {
			best, found = m, true
		}
	}
	return best, found
}

func isParentOrSelf(dir, path string) bool {
	return dir == path || dir == "/" || strings.HasPrefix(path, dir+"/")
}

// unescapeMount decodes the octal escapes (\040 etc.) used in /proc/self/mountinfo.
func unescapeMount(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
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
