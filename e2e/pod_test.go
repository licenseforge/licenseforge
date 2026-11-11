//go:build e2e

package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The images the drivers run in, inside the cluster.
const (
	podNodeImage = "node:22.20.0-alpine"
	podJavaImage = "eclipse-temurin:21.0.8_9-jre-alpine"
)

// The SDKs inside the cluster, as a vendor's cluster-bound app runs: the
// driver in a pod, with nothing configured but the license, keys and the
// server's CA. The SDK finds the cluster's fingerprint (the kube-system
// namespace UID, binding cluster) and keeps the lease in a ConfigMap through
// the pod's own service account (its token, CA and namespace files), with
// only the RBAC the READMEs ask for. A second pod (a replica, or the app
// rescheduled) is the same machine: one seat, the lease it finds. Pulls the
// two images above; the server's nip.io name resolves through the CoreDNS
// hosts entry up.sh adds.
func TestSDKInPod(t *testing.T) {
	e := loadEnv(t)
	b, tn := owner(t, e)
	api := "/api/v1/tenants/" + tn.Slug
	var keys []map[string]string
	for _, k := range trustedKeys(t, b, tn.Slug) {
		keys = append(keys, map[string]string{"kid": k.KID, "alg": k.Alg, "public_key": base64.RawURLEncoding.EncodeToString(k.Key)})
	}
	keySet, _ := json.Marshal(keys)
	ca, err := os.ReadFile(e.CAFile)
	if err != nil {
		t.Fatal(err)
	}

	// What goes into the pods: the drivers with the built SDKs, laid out as in
	// the repository (driver.mjs imports ../../sdk/ts/dist), the Java driver
	// compiled for the JRE image, and the server's CA.
	app := t.TempDir()
	cp := func(from, to string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(app, to)), 0o755); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("cp", "-r", from, filepath.Join(app, to)).CombinedOutput(); err != nil {
			t.Fatalf("cp %s: %v\n%s", from, err, out)
		}
	}
	cp("sdk/driver.mjs", "e2e/sdk/driver.mjs")
	cp("../sdk/ts/dist/src", "sdk/ts/dist/src")
	cp("../sdk/ts/package.json", "sdk/ts/package.json") // "type": "module"
	cp("../sdk/java/target/classes", "java")
	if out, err := exec.Command("javac", "--release", "17", "-cp", "../sdk/java/target/classes", "-d", filepath.Join(app, "java"), "sdk/Driver.java").CombinedOutput(); err != nil {
		t.Fatalf("javac: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(app, "ca.pem"), ca, 0o644); err != nil {
		t.Fatal(err)
	}

	ns := e.Namespace
	run := strings.ToLower(rand.Text()[:8])
	sa := "e2e-pod-" + run
	stores := map[string]string{"typescript": "e2e-pod-lease-typescript-" + run, "java": "e2e-pod-lease-java-" + run}
	// One ServiceAccount per SDK, allowed get and update on its own ConfigMap
	// only, and get on the kube-system namespace (the READMEs' RBAC). The
	// cluster-scoped objects carry a label: an interrupted run leaves them
	// behind after the namespace is gone (see e2e/env/README.md).
	pod := func(name, account, image string) string {
		return `---
apiVersion: v1
kind: Pod
metadata: {name: ` + name + `, namespace: ` + ns + `}
spec:
  serviceAccountName: ` + account + `
  restartPolicy: Never
  terminationGracePeriodSeconds: 0
  securityContext: {runAsNonRoot: true, runAsUser: 1000, seccompProfile: {type: RuntimeDefault}}
  containers:
  - name: app
    image: ` + image + `
    command: [sleep, "3600"]
    securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
`
	}
	var manifest, subjects strings.Builder
	var pods []string
	for _, x := range []struct{ name, short, image string }{{"typescript", "ts", podNodeImage}, {"java", "java", podJavaImage}} {
		account := sa + "-" + x.short
		subjects.WriteString(`{kind: ServiceAccount, name: ` + account + `, namespace: ` + ns + `}, `)
		manifest.WriteString(`---
apiVersion: v1
kind: ServiceAccount
metadata: {name: ` + account + `, namespace: ` + ns + `}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: ` + account + `, namespace: ` + ns + `}
rules: [{apiGroups: [""], resources: [configmaps], resourceNames: [` + stores[x.name] + `], verbs: [get, update]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: ` + account + `, namespace: ` + ns + `}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: ` + account + `}
subjects: [{kind: ServiceAccount, name: ` + account + `, namespace: ` + ns + `}]
---
apiVersion: v1
kind: ConfigMap
metadata: {name: ` + stores[x.name] + `, namespace: ` + ns + `}
` + pod(account+"-a", account, x.image) + pod(account+"-b", account, x.image))
		pods = append(pods, account+"-a", account+"-b")
	}
	manifest.WriteString(`---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: ` + sa + `, labels: {licenseforge.io/e2e: "true"}}
rules: [{apiGroups: [""], resources: [namespaces], resourceNames: [kube-system], verbs: [get]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: ` + sa + `, labels: {licenseforge.io/e2e: "true"}}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: ` + sa + `}
subjects: [` + strings.TrimSuffix(subjects.String(), ", ") + `]
`)
	t.Cleanup(func() { kube(t, e, manifest.String(), "delete", "--ignore-not-found", "--wait=false", "-f", "-") })
	kube(t, e, manifest.String(), "apply", "-f", "-")
	wait := exec.Command("kubectl", append([]string{"--context", e.KubeContext, "-n", ns, "wait", "--for=condition=Ready", "--timeout=300s"}, prefix("pod/", pods)...)...)
	if out, err := wait.CombinedOutput(); err != nil { // an image pull that failed, most likely: say why
		t.Fatalf("pods not ready: %v\n%s\n%s", err, out, kube(t, e, "", append([]string{"-n", ns, "describe"}, prefix("pod/", pods)...)...))
	}
	for _, p := range pods {
		kube(t, e, "", "-n", ns, "cp", app, p+":/tmp/app")
	}

	for _, sdk := range []struct{ name, short string }{{"typescript", "ts"}, {"java", "java"}} {
		t.Run(sdk.name, func(t *testing.T) {
			product, lic, _ := newLicense(t, b, tn, map[string]any{"bind_type": "cluster"})
			store := stores[sdk.name]
			type result struct {
				OK                bool
				Code, Detail, Lid string
				Iat, Binding      string
				Warnings          []string
			}
			// One step of the app in pod p (a or b).
			step := func(p, op string) result {
				t.Helper()
				args := []string{"-n", ns, "exec", sa + "-" + sdk.short + "-" + p, "--", "env",
					"LF_BASE_URL=" + e.BaseURL, "LF_TENANT_ID=" + tn.ID, "LF_PRODUCT=" + product.Slug, "LF_LICENSE_KEY=" + lic.Key,
					"LF_KEYS=" + string(keySet), "LF_CA=/tmp/app/ca.pem", "LF_K8S_STORE=configmap", "LF_K8S_NAME=" + store}
				if sdk.name == "typescript" {
					args = append(args, "node", "/tmp/app/e2e/sdk/driver.mjs", op)
				} else {
					args = append(args, "java", "-cp", "/tmp/app/java", "Driver", op)
				}
				c := exec.Command("kubectl", append([]string{"--context", e.KubeContext}, args...)...)
				var stderr bytes.Buffer
				c.Stderr = &stderr
				out, err := c.Output()
				var r result
				if err != nil || json.Unmarshal(out, &r) != nil {
					t.Fatalf("pod %s %s: %v\n%s%s", p, op, err, out, stderr.String())
				}
				if len(r.Warnings) > 0 {
					t.Fatalf("pod %s %s: warnings %q", p, op, r.Warnings)
				}
				return r
			}
			first := step("a", "activate")
			if !first.OK || first.Lid != lic.ID || first.Binding != "cluster" {
				t.Fatalf("activate in a pod: %+v, want the license bound to the cluster", first)
			}
			if v := kubeValue(t, e, "configmap", store, "lease"); !strings.Contains(v, "\nlf1.") {
				t.Errorf("the ConfigMap holds %q, want the lease", v)
			}
			if r := step("a", "current"); !r.OK || r.Iat != first.Iat {
				t.Errorf("a restart: %+v, want the lease from the ConfigMap", r)
			}
			// The other pod: the same cluster, so the same machine.
			if r := step("b", "current"); !r.OK || r.Iat != first.Iat || r.Binding != "cluster" {
				t.Errorf("another pod: %+v, want the lease from the ConfigMap", r)
			}
			if r := step("b", "refresh"); !r.OK || r.Lid != lic.ID {
				t.Errorf("another pod refreshing: %+v", r)
			}
			var acts struct{ Items []struct{ ID string } }
			b.do("GET", api+"/licenses/"+lic.ID+"/activations", nil, 200, &acts)
			if len(acts.Items) != 1 {
				t.Errorf("activations %+v, want one: a cluster is one machine", acts.Items)
			}
			if r := step("b", "deactivate"); !r.OK {
				t.Fatalf("deactivate in a pod: %+v", r)
			}
			if v := kubeValue(t, e, "configmap", store, "lease"); v != "" {
				t.Errorf("the ConfigMap still holds %q after deactivate", v)
			}
			if r := step("a", "current"); r.OK || r.Code != "no_lease" {
				t.Errorf("after deactivate, the first pod: %+v, want no_lease", r)
			}
		})
	}
}

func prefix(p string, names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = p + n
	}
	return out
}
