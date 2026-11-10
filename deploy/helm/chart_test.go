// Package helm tests the Helm chart's rendered workloads against the
// hardening it promises (compliance/kubernetes-hardening.md): the Pod Security
// Standard "restricted" profile and the NSA/CISA Kubernetes Hardening
// Guidance items the chart controls. It needs helm on PATH; without it the
// test skips, unless LICENSEFORGE_REQUIRE_HELM is set (the chart CI job).
package helm

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type container struct {
	Name            string `yaml:"name"`
	SecurityContext struct {
		AllowPrivilegeEscalation *bool `yaml:"allowPrivilegeEscalation"`
		ReadOnlyRootFilesystem   *bool `yaml:"readOnlyRootFilesystem"`
		Privileged               *bool `yaml:"privileged"`
		RunAsNonRoot             *bool `yaml:"runAsNonRoot"`
		Capabilities             struct {
			Drop []string `yaml:"drop"`
			Add  []string `yaml:"add"`
		} `yaml:"capabilities"`
	} `yaml:"securityContext"`
	Resources struct {
		Limits   map[string]string `yaml:"limits"`
		Requests map[string]string `yaml:"requests"`
	} `yaml:"resources"`
	Ports []struct {
		HostPort int `yaml:"hostPort"`
	} `yaml:"ports"`
}

type podSpec struct {
	AutomountServiceAccountToken *bool `yaml:"automountServiceAccountToken"`
	HostNetwork                  bool  `yaml:"hostNetwork"`
	HostPID                      bool  `yaml:"hostPID"`
	HostIPC                      bool  `yaml:"hostIPC"`
	SecurityContext              struct {
		RunAsNonRoot   *bool `yaml:"runAsNonRoot"`
		RunAsUser      *int  `yaml:"runAsUser"`
		SeccompProfile struct {
			Type string `yaml:"type"`
		} `yaml:"seccompProfile"`
	} `yaml:"securityContext"`
	Containers     []container `yaml:"containers"`
	InitContainers []container `yaml:"initContainers"`
	Volumes        []struct {
		Name     string         `yaml:"name"`
		HostPath map[string]any `yaml:"hostPath"`
	} `yaml:"volumes"`
}

type object struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Template struct {
			Spec podSpec `yaml:"spec"`
		} `yaml:"template"`
		JobTemplate struct {
			Spec struct {
				Template struct {
					Spec podSpec `yaml:"spec"`
				} `yaml:"template"`
			} `yaml:"spec"`
		} `yaml:"jobTemplate"`
	} `yaml:"spec"`
}

// Value sets that render every workload the chart has.
var renders = map[string][]string{
	"defaults":       {},
	"retention":      {"--set", "auditRetention.enabled=true", "--set", "auditRetention.secret=r"},
	"autoscaling":    {"--set", "autoscaling.enabled=true"},
	"no-migrate-job": {"--set", "migrate.enabled=false"},
}

func render(t *testing.T, extra []string) []object {
	t.Helper()
	args := append([]string{"template", "t", "licenseforge", "--set", "secrets.server=s", "--set", "secrets.migrate=m"}, extra...)
	out, err := exec.Command("helm", args...).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("helm %v: %v\n%s", args, err, ee.Stderr)
		}
		t.Fatal(err)
	}
	var objs []object
	dec := yaml.NewDecoder(bytes.NewReader(out))
	for {
		var o object
		if err := dec.Decode(&o); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		objs = append(objs, o)
	}
	return objs
}

func TestWorkloadsAreRestricted(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		if os.Getenv("LICENSEFORGE_REQUIRE_HELM") != "" {
			t.Fatal("helm not found and LICENSEFORGE_REQUIRE_HELM is set")
		}
		t.Skip("helm not installed")
	}
	kinds := map[string]bool{}
	for name, extra := range renders {
		for _, o := range render(t, extra) {
			var ps podSpec
			switch o.Kind {
			case "Deployment", "Job", "StatefulSet", "DaemonSet":
				ps = o.Spec.Template.Spec
			case "CronJob":
				ps = o.Spec.JobTemplate.Spec.Template.Spec
			default:
				continue
			}
			kinds[o.Kind] = true
			where := name + ": " + o.Kind + "/" + o.Metadata.Name
			checkPod(t, where, ps)
		}
	}
	for _, k := range []string{"Deployment", "Job", "CronJob"} {
		if !kinds[k] {
			t.Errorf("no %s rendered: the test doesn't cover it", k)
		}
	}
}

func checkPod(t *testing.T, where string, ps podSpec) {
	t.Helper()
	bad := func(format string, a ...any) { t.Errorf(where+": "+format, a...) }
	if ps.AutomountServiceAccountToken == nil || *ps.AutomountServiceAccountToken {
		bad("mounts a service account token")
	}
	if ps.HostNetwork || ps.HostPID || ps.HostIPC {
		bad("shares host namespaces")
	}
	for _, v := range ps.Volumes {
		if v.HostPath != nil {
			bad("hostPath volume %s", v.Name)
		}
	}
	sc := ps.SecurityContext
	if sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot || sc.RunAsUser == nil || *sc.RunAsUser == 0 {
		bad("may run as root")
	}
	if sc.SeccompProfile.Type != "RuntimeDefault" && sc.SeccompProfile.Type != "Localhost" {
		bad("seccomp profile %q", sc.SeccompProfile.Type)
	}
	if len(ps.Containers) == 0 {
		bad("no containers")
	}
	for _, c := range append(append([]container{}, ps.InitContainers...), ps.Containers...) {
		cs := c.SecurityContext
		in := func(format string, a ...any) { bad("container %s: "+format, append([]any{c.Name}, a...)...) }
		if cs.AllowPrivilegeEscalation == nil || *cs.AllowPrivilegeEscalation {
			in("allows privilege escalation")
		}
		if cs.Privileged != nil && *cs.Privileged {
			in("privileged")
		}
		if cs.ReadOnlyRootFilesystem == nil || !*cs.ReadOnlyRootFilesystem {
			in("writable root filesystem")
		}
		if cs.RunAsNonRoot != nil && !*cs.RunAsNonRoot {
			in("runAsNonRoot false")
		}
		if strings.Join(cs.Capabilities.Drop, ",") != "ALL" || len(cs.Capabilities.Add) > 0 {
			in("capabilities drop %v add %v, want drop [ALL] and nothing added", cs.Capabilities.Drop, cs.Capabilities.Add)
		}
		if c.Resources.Limits["memory"] == "" || c.Resources.Requests["cpu"] == "" {
			in("no memory limit or cpu request")
		}
		for _, p := range c.Ports {
			if p.HostPort != 0 {
				in("hostPort %d", p.HostPort)
			}
		}
	}
}
