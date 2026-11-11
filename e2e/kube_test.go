//go:build e2e

package e2e

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// kube runs kubectl on the e2e cluster (E2E_KUBE_CONTEXT, default minikube:
// up.sh's) and returns its output.
func kube(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	ctx := os.Getenv("E2E_KUBE_CONTEXT")
	if ctx == "" {
		ctx = "minikube"
	}
	c := exec.Command("kubectl", append([]string{"--context", ctx}, args...)...)
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
// beforehand. It returns the LF_K8S_* environment for the drivers (without
// the store kind and name) and removes everything after the test.
func kubeLeaseStores(t *testing.T, run string, configMaps, secrets []string) []string {
	t.Helper()
	const ns = "licenseforge-e2e"
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
- {apiGroups: [""], resources: [configmaps], resourceNames: ` + quoted(configMaps) + `, verbs: [get, update]}
- {apiGroups: [""], resources: [secrets], resourceNames: ` + quoted(secrets) + `, verbs: [get, update]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: ` + sa + `, namespace: ` + ns + `}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: ` + sa + `}
subjects: [{kind: ServiceAccount, name: ` + sa + `, namespace: ` + ns + `}]
` + objects.String()
	kube(t, manifest, "apply", "-f", "-")
	t.Cleanup(func() { kube(t, manifest, "delete", "--ignore-not-found", "-f", "-") })

	token := strings.TrimSpace(kube(t, "", "-n", ns, "create", "token", sa, "--duration", "10m"))
	server := mustURL(t, kube(t, "", "config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}"))
	ca := kube(t, "", "config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.certificate-authority}")
	if ca == "" {
		t.Fatal("the kubeconfig's cluster has no certificate-authority file")
	}
	port := server.Port()
	if port == "" {
		port = "443"
	}
	return []string{"LF_K8S_HOST=" + server.Hostname(), "LF_K8S_PORT=" + port, "LF_K8S_CA=" + ca, "LF_K8S_NAMESPACE=" + ns, "LF_K8S_TOKEN=" + token}
}

// kubeValue is a key of a ConfigMap's data, or a Secret's (decoded), "" when absent.
func kubeValue(t *testing.T, kind, name, key string) string {
	t.Helper()
	v := kube(t, "", "-n", "licenseforge-e2e", "get", kind, name, "-o", "jsonpath={.data."+key+"}")
	if kind == "secret" {
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			t.Fatalf("secret %s: %v", name, err)
		}
		return string(b)
	}
	return v
}
