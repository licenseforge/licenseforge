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

// securityFields are the security context fields that both pods and
// containers can set, and that the restricted profile constrains.
type securityFields struct {
	RunAsNonRoot   *bool `yaml:"runAsNonRoot"`
	RunAsUser      *int  `yaml:"runAsUser"`
	RunAsGroup     *int  `yaml:"runAsGroup"`
	SeccompProfile struct {
		Type string `yaml:"type"`
	} `yaml:"seccompProfile"`
	SELinuxOptions struct {
		Type string `yaml:"type"`
	} `yaml:"seLinuxOptions"`
	WindowsOptions struct {
		HostProcess *bool `yaml:"hostProcess"`
	} `yaml:"windowsOptions"`
	AppArmorProfile struct {
		Type string `yaml:"type"`
	} `yaml:"appArmorProfile"`
}

type container struct {
	Name            string `yaml:"name"`
	SecurityContext struct {
		securityFields           `yaml:",inline"`
		AllowPrivilegeEscalation *bool  `yaml:"allowPrivilegeEscalation"`
		ReadOnlyRootFilesystem   *bool  `yaml:"readOnlyRootFilesystem"`
		Privileged               *bool  `yaml:"privileged"`
		ProcMount                string `yaml:"procMount"`
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
	Env []struct {
		Name      string `yaml:"name"`
		Value     string `yaml:"value"`
		ValueFrom struct {
			SecretKeyRef map[string]any `yaml:"secretKeyRef"`
		} `yaml:"valueFrom"`
	} `yaml:"env"`
	EnvFrom []map[string]any `yaml:"envFrom"`
}

type podSpec struct {
	AutomountServiceAccountToken *bool `yaml:"automountServiceAccountToken"`
	HostNetwork                  bool  `yaml:"hostNetwork"`
	HostPID                      bool  `yaml:"hostPID"`
	HostIPC                      bool  `yaml:"hostIPC"`
	SecurityContext              struct {
		securityFields `yaml:",inline"`
		Sysctls        []struct {
			Name string `yaml:"name"`
		} `yaml:"sysctls"`
	} `yaml:"securityContext"`
	Containers          []container      `yaml:"containers"`
	InitContainers      []container      `yaml:"initContainers"`
	EphemeralContainers []container      `yaml:"ephemeralContainers"`
	Volumes             []map[string]any `yaml:"volumes"`
}

type template struct {
	Metadata struct {
		Annotations map[string]string `yaml:"annotations"`
	} `yaml:"metadata"`
	Spec podSpec `yaml:"spec"`
}

type object struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		podSpec     `yaml:",inline"`
		Template    template `yaml:"template"`
		JobTemplate struct {
			Spec struct {
				Template template `yaml:"template"`
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
	"mounts":         {"--set", "extraCA.secretName=ca"}, // adds a volume and mounts
	"every secret": {"--set", "extraCA.secretName=ca", "--set", "auditRetention.enabled=true", "--set", "auditRetention.secret=r",
		"--set", "oidc.enabled=true", "--set", "oidc.issuer=https://idp.example", "--set", "oidc.clientID=lf", "--set", "oidc.redirectURL=https://lf.example/auth/callback", "--set", "oidc.clientSecret.secretName=oidc",
		"--set", "audit.export.otlp.endpoint=https://otel.example:4318/v1/logs", "--set", "audit.export.otlp.headersSecret=otlp"},
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
			var annotations map[string]string
			switch o.Kind {
			case "Deployment", "Job", "StatefulSet", "DaemonSet", "ReplicaSet":
				ps, annotations = o.Spec.Template.Spec, o.Spec.Template.Metadata.Annotations
			case "CronJob":
				ps, annotations = o.Spec.JobTemplate.Spec.Template.Spec, o.Spec.JobTemplate.Spec.Template.Metadata.Annotations
			case "Pod":
				ps = o.Spec.podSpec
			default:
				if len(o.Spec.Containers) > 0 || len(o.Spec.Template.Spec.Containers) > 0 { // e.g. an Argo Rollout
					t.Errorf("%s: %s/%s has containers the test doesn't check", name, o.Kind, o.Metadata.Name)
				}
				continue
			}
			// The annotation form of AppArmor, still checked by the restricted profile.
			for k, v := range annotations {
				if strings.HasPrefix(k, "container.apparmor.security.beta.kubernetes.io/") && v != "runtime/default" && !strings.HasPrefix(v, "localhost/") {
					t.Errorf("%s: %s/%s: AppArmor annotation %s=%s", name, o.Kind, o.Metadata.Name, k, v)
				}
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
	// The restricted profile's volume types.
	allowed := map[string]bool{"configMap": true, "csi": true, "downwardAPI": true, "emptyDir": true, "ephemeral": true, "persistentVolumeClaim": true, "projected": true, "secret": true}
	for _, v := range ps.Volumes {
		for k := range v {
			if k != "name" && !allowed[k] {
				bad("volume %v of type %s", v["name"], k)
			}
		}
	}
	sc := ps.SecurityContext
	if sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot || sc.RunAsUser == nil || *sc.RunAsUser == 0 {
		bad("may run as root")
	}
	if sc.RunAsGroup == nil {
		bad("runAsGroup unset, want 65532")
	}
	if sc.SeccompProfile.Type != "RuntimeDefault" && sc.SeccompProfile.Type != "Localhost" {
		bad("seccomp profile %q", sc.SeccompProfile.Type)
	}
	if len(sc.Sysctls) > 0 {
		bad("sets sysctls %v", sc.Sysctls)
	}
	checkFields(bad, sc.securityFields)
	if len(ps.Containers) == 0 {
		bad("no containers")
	}
	for _, c := range append(append(append([]container{}, ps.InitContainers...), ps.EphemeralContainers...), ps.Containers...) {
		cs := c.SecurityContext
		in := func(format string, a ...any) { bad("container %s: "+format, append([]any{c.Name}, a...)...) }
		checkFields(in, cs.securityFields)
		if cs.ProcMount != "" && cs.ProcMount != "Default" {
			in("procMount %s", cs.ProcMount)
		}
		if cs.AllowPrivilegeEscalation == nil || *cs.AllowPrivilegeEscalation {
			in("allows privilege escalation")
		}
		if cs.Privileged != nil && *cs.Privileged {
			in("privileged")
		}
		if cs.ReadOnlyRootFilesystem == nil || !*cs.ReadOnlyRootFilesystem {
			in("writable root filesystem")
		}
		if strings.Join(cs.Capabilities.Drop, ",") != "ALL" || len(cs.Capabilities.Add) > 0 {
			in("capabilities drop %v add %v, want drop [ALL] and nothing added", cs.Capabilities.Drop, cs.Capabilities.Add)
		}
		if c.Resources.Limits["memory"] == "" || c.Resources.Requests["cpu"] == "" || c.Resources.Requests["memory"] == "" {
			in("no memory limit, or no cpu or memory request")
		}
		for _, p := range c.Ports {
			if p.HostPort != 0 {
				in("hostPort %d", p.HostPort)
			}
		}
		// Secrets reach the program as mounted files (LICENSEFORGE_*_FILE),
		// never as environment variables (DISA Kubernetes STIG V-242415).
		for _, e := range c.Env {
			if e.ValueFrom.SecretKeyRef != nil {
				in("env %s from a Secret", e.Name)
			}
		}
		if len(c.EnvFrom) > 0 {
			in("envFrom")
		}
	}
}

// checkFields applies the restricted profile to fields a pod or a container
// can set (a container's value overrides the pod's).
func checkFields(bad func(string, ...any), f securityFields) {
	if f.RunAsUser != nil && *f.RunAsUser == 0 {
		bad("runAsUser 0")
	}
	if f.RunAsNonRoot != nil && !*f.RunAsNonRoot {
		bad("runAsNonRoot false")
	}
	if f.RunAsGroup != nil && *f.RunAsGroup != 65532 {
		bad("runAsGroup %d, want 65532", *f.RunAsGroup)
	}
	if t := f.SeccompProfile.Type; t != "" && t != "RuntimeDefault" && t != "Localhost" {
		bad("seccomp profile %q", t)
	}
	if t := f.SELinuxOptions.Type; t != "" && t != "container_t" && t != "container_init_t" && t != "container_kvm_t" {
		bad("SELinux type %q", t)
	}
	if f.WindowsOptions.HostProcess != nil && *f.WindowsOptions.HostProcess {
		bad("Windows hostProcess")
	}
	if t := f.AppArmorProfile.Type; t != "" && t != "RuntimeDefault" && t != "Localhost" {
		bad("AppArmor profile %q", t)
	}
}

// The platform and session values reach the server as its LICENSEFORGE_*
// settings, and nothing is set while they're empty (the server's defaults).
func TestPlatformSettings(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		if os.Getenv("LICENSEFORGE_REQUIRE_HELM") != "" {
			t.Fatal("helm not found and LICENSEFORGE_REQUIRE_HELM is set")
		}
		t.Skip("helm not installed")
	}
	want := map[string]string{
		"LICENSEFORGE_API_HOST": "api.example.com", "LICENSEFORGE_BOOTSTRAP_ADMIN": "admin@example.com",
		"LICENSEFORGE_PLATFORM_MFA_POLICY": "phishing_resistant", "LICENSEFORGE_LOGIN_BANNER": "Authorized use only, monitored",
		"LICENSEFORGE_SESSION_IDLE_TIMEOUT": "30m", "LICENSEFORGE_SESSION_MAX_AGE": "8h",
	}
	env := func(extra ...string) map[string]string {
		got := map[string]string{}
		for _, o := range render(t, extra) {
			if o.Kind == "Deployment" {
				for _, e := range o.Spec.Template.Spec.Containers[0].Env {
					if _, ok := want[e.Name]; ok {
						got[e.Name] = e.Value
					}
				}
			}
		}
		return got
	}
	if got := env(); len(got) != 0 {
		t.Errorf("defaults set %v, want none", got)
	}
	got := env("--set", "apiHost=api.example.com", "--set", "bootstrapAdmin=admin@example.com", "--set", "platformMFAPolicy=phishing_resistant",
		"--set", "loginBanner=Authorized use only\\, monitored", "--set", "session.idleTimeout=30m", "--set", "session.maxAge=8h")
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if _, err := exec.Command("helm", "template", "t", "licenseforge", "--set", "secrets.server=s", "--set", "secrets.migrate=m", "--set", "platformMFAPolicy=strong").Output(); err == nil {
		t.Error("platformMFAPolicy=strong rendered, want the schema to refuse it")
	}
}
