package fingerprint

import (
	"errors"
	"os"
	"testing"
)

const validID = "0123456789abcdef0123456789abcdef"

func fakeFS(files map[string]string) linuxFS {
	return linuxFS{
		readFile: func(p string) ([]byte, error) {
			if s, ok := files[p]; ok {
				return []byte(s), nil
			}
			return nil, os.ErrNotExist
		},
		exists: func(p string) bool { _, ok := files[p]; return ok },
	}
}

const rootExt4 = "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"

// bindMount is a mountinfo line for something mounted at /etc/machine-id.
func bindMount(root, fstype string) string {
	return "35 22 0:31 " + root + " /etc/machine-id ro,relatime - " + fstype + " src rw\n"
}

func TestLinuxMachineID(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  string // "" = ErrNoFingerprint
	}{
		{"host", map[string]string{"/etc/machine-id": validID + "\n"}, validID},
		{"dbus fallback when etc is uninitialized", map[string]string{"/etc/machine-id": "uninitialized\n", "/var/lib/dbus/machine-id": validID}, validID},
		{"dbus fallback when etc is missing", map[string]string{"/var/lib/dbus/machine-id": validID}, validID},
		{"transient tmpfs machine-id refused", map[string]string{"/etc/machine-id": validID, "/proc/self/mountinfo": rootExt4 + bindMount("/machine-id", "tmpfs")}, ""},
		{"persistent bind mount on host ok", map[string]string{"/etc/machine-id": validID, "/proc/self/mountinfo": rootExt4 + bindMount("/persist/etc/machine-id", "btrfs")}, validID},
		{"root on tmpfs refused", map[string]string{"/etc/machine-id": validID, "/proc/self/mountinfo": "22 1 0:5 / / rw - tmpfs none rw\n"}, ""},
		{"etc on ramfs refused", map[string]string{"/etc/machine-id": validID, "/proc/self/mountinfo": rootExt4 + "30 22 0:6 / /etc rw - ramfs none rw\n"}, ""},
		{"last stacked mount wins (tmpfs on top)", map[string]string{"/etc/machine-id": validID, "/proc/self/mountinfo": rootExt4 + bindMount("/etc/machine-id", "ext4") + bindMount("/machine-id", "tmpfs")}, ""},
		{"last stacked mount wins (ext4 on top)", map[string]string{"/etc/machine-id": validID, "/proc/self/mountinfo": rootExt4 + bindMount("/machine-id", "tmpfs") + bindMount("/etc/machine-id", "ext4")}, validID},
		{"docker with image machine-id refused", map[string]string{"/.dockerenv": "", "/etc/machine-id": validID}, ""},
		{"docker with host machine-id mounted", map[string]string{"/.dockerenv": "", "/etc/machine-id": validID, "/proc/self/mountinfo": rootExt4 + bindMount("/etc/machine-id", "ext4")}, validID},
		{"docker with ostree-style host path", map[string]string{"/.dockerenv": "", "/etc/machine-id": validID, "/proc/self/mountinfo": rootExt4 + bindMount("/ostree/deploy/fedora/deploy/abc/etc/machine-id", "xfs")}, validID},
		{"docker with arbitrary shared file refused", map[string]string{"/.dockerenv": "", "/etc/machine-id": validID, "/proc/self/mountinfo": rootExt4 + bindMount("/home/user/shared-id", "ext4")}, ""},
		{"docker with escaped path", map[string]string{"/.dockerenv": "", "/etc/machine-id": validID, "/proc/self/mountinfo": rootExt4 + bindMount("/my\\040disk/etc/machine-id", "ext4")}, validID},
		{"podman marker", map[string]string{"/run/.containerenv": "", "/etc/machine-id": validID}, ""},
		{"systemd container marker docker", map[string]string{"/run/systemd/container": "docker\n", "/etc/machine-id": validID}, ""},
		{"unknown container type fails closed", map[string]string{"/run/systemd/container": "something-new", "/etc/machine-id": validID}, ""},
		{"nspawn system container uses its own id", map[string]string{"/run/systemd/container": "systemd-nspawn\n", "/etc/machine-id": validID}, validID},
		{"lxc system container uses its own id", map[string]string{"/proc/1/environ": "PATH=/bin\x00container=lxc\x00", "/etc/machine-id": validID}, validID},
		{"oci container in pid 1 environ", map[string]string{"/proc/1/environ": "container=oci\x00", "/etc/machine-id": validID}, ""},
		{"no machine-id at all", map[string]string{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, err := linuxMachineID(fakeFS(tc.files))
			if tc.want == "" {
				if err == nil {
					t.Fatalf("got %q, want an error", id)
				}
				return
			}
			if err != nil || id != tc.want {
				t.Fatalf("got %q, %v", id, err)
			}
		})
	}
}

func TestParseMachineID(t *testing.T) {
	for _, bad := range []string{"", "uninitialized\n", "0123456789ABCDEF0123456789ABCDEF", "short"} {
		if _, err := parseMachineID(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestLinuxMachineIDErrorIsNoFingerprint(t *testing.T) {
	if _, err := linuxMachineID(fakeFS(map[string]string{"/.dockerenv": ""})); !errors.Is(err, ErrNoFingerprint) {
		t.Fatalf("got %v", err)
	}
}

func TestUnescapeMount(t *testing.T) {
	if got := unescapeMount(`/my\040disk\134x`); got != "/my disk\\x" {
		t.Fatalf("got %q", got)
	}
}
