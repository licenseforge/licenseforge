//go:build e2e

package e2e

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// kube runs kubectl on the e2e cluster (the env's context: up.sh's minikube
// profile) and returns its output.
func kube(t *testing.T, e env, stdin string, args ...string) string {
	t.Helper()
	c := exec.Command("kubectl", append([]string{"--context", e.KubeContext}, args...)...)
	c.Stdin = strings.NewReader(stdin)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		t.Fatalf("kubectl %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return string(out)
}

// kubeLeaseStores sets up what a vendor's cluster-bound app needs for the SDK
// Kubernetes lease stores, as the SDK READMEs say: a ServiceAccount whose Role
// allows only get and update on the named ConfigMaps and Secrets, created
// beforehand (missing: allowed by the Role but not created). It returns the
// LF_K8S_* environment for the drivers (without the store kind and name) and
// removes everything after the test.
func kubeLeaseStores(t *testing.T, e env, run string, configMaps, secrets, missing []string) []string {
	t.Helper()
	ns := e.Namespace
	sa := "e2e-leases-" + run
	quoted := func(names []string) string { return `["` + strings.Join(names, `","`) + `"]` }
	var objects strings.Builder
	for _, n := range configMaps {
		objects.WriteString("---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: " + n + ", namespace: " + ns + "}\n")
	}
	for _, n := range secrets {
		objects.WriteString("---\napiVersion: v1\nkind: Secret\nmetadata: {name: " + n + ", namespace: " + ns + "}\n")
	}
	manifest := `apiVersion: v1
kind: ServiceAccount
metadata: {name: ` + sa + `, namespace: ` + ns + `}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: ` + sa + `, namespace: ` + ns + `}
rules:
- {apiGroups: [""], resources: [configmaps], resourceNames: ` + quoted(append(append([]string{}, configMaps...), missing...)) + `, verbs: [get, update]}
- {apiGroups: [""], resources: [secrets], resourceNames: ` + quoted(append(append([]string{}, secrets...), missing...)) + `, verbs: [get, update]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: ` + sa + `, namespace: ` + ns + `}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: ` + sa + `}
subjects: [{kind: ServiceAccount, name: ` + sa + `, namespace: ` + ns + `}]
` + objects.String()
	// Registered first: an apply failing halfway leaves nothing behind either.
	// (An interrupted run leaves these randomly named objects until the
	// namespace is deleted.)
	t.Cleanup(func() {
		kube(t, e, manifest, "delete", "--ignore-not-found", "-f", "-")
		for _, n := range missing { // in case a store created one after all
			kube(t, e, "", "-n", ns, "delete", "--ignore-not-found", "configmap,secret", n)
		}
	})
	kube(t, e, manifest, "apply", "-f", "-")

	token := strings.TrimSpace(kube(t, e, "", "-n", ns, "create", "token", sa, "--duration", "10m"))
	server := mustURL(t, kube(t, e, "", "config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}"))
	// --flatten inlines a CA file, so kubeconfigs with either form work.
	caData := kube(t, e, "", "config", "view", "--minify", "--flatten", "--raw", "-o", "jsonpath={.clusters[0].cluster.certificate-authority-data}")
	pem, err := base64.StdEncoding.DecodeString(caData)
	if err != nil || len(pem) == 0 {
		t.Fatalf("the kubeconfig's cluster CA: %v", err)
	}
	ca := filepath.Join(t.TempDir(), "kube-ca.crt")
	if err := os.WriteFile(ca, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	port := server.Port()
	if port == "" {
		port = "443"
	}
	return []string{"LF_K8S_HOST=" + server.Hostname(), "LF_K8S_PORT=" + port, "LF_K8S_CA=" + ca, "LF_K8S_NAMESPACE=" + ns, "LF_K8S_TOKEN=" + token}
}

// kubeValue is a key of a ConfigMap's data, or a Secret's (decoded), "" when absent.
func kubeValue(t *testing.T, e env, kind, name, key string) string {
	t.Helper()
	v := kube(t, e, "", "-n", e.Namespace, "get", kind, name, "-o", "jsonpath={.data."+key+"}")
	if kind == "secret" {
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			t.Fatalf("secret %s: %v", name, err)
		}
		return string(b)
	}
	return v
}
