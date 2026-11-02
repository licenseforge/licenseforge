package fingerprint

import (
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func fakeEnv(vars map[string]string, files ...string) env {
	return env{
		getenv: func(k string) string { return vars[k] },
		exists: func(p string) bool {
			for _, f := range files {
				if f == p {
					return true
				}
			}
			return false
		},
		k8s:       func() (string, error) { return "kube-uid-1", nil },
		machineID: func() (string, error) { return "0123456789abcdef0123456789abcdef", nil },
	}
}

func TestComputeSourceOrder(t *testing.T) {
	for _, tc := range []struct {
		name   string
		e      env
		source Source
		raw    string
		bind   string
		err    error
	}{
		{"override wins over kubernetes", fakeEnv(map[string]string{EnvOverride: " my-id ", "KUBERNETES_SERVICE_HOST": "10.0.0.1"}), SourceEnv, "my-id", "machine", nil},
		{"kubernetes", fakeEnv(map[string]string{"KUBERNETES_SERVICE_HOST": "10.0.0.1"}), SourceKubernetes, "kube-uid-1", "cluster", nil},
		{"machine id", fakeEnv(nil), SourceMachineID, "0123456789abcdef0123456789abcdef", "machine", nil},
		{"docker without override", fakeEnv(nil, "/.dockerenv"), "", "", "", ErrNoFingerprint},
		{"podman without override", fakeEnv(nil, "/run/.containerenv"), "", "", "", ErrNoFingerprint},
		{"docker with override", fakeEnv(map[string]string{EnvOverride: "x"}, "/.dockerenv"), SourceEnv, "x", "machine", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := compute("acme-db", tc.e)
			if !errors.Is(err, tc.err) {
				t.Fatalf("err = %v, want %v", err, tc.err)
			}
			if tc.err != nil {
				return
			}
			if r.Source != tc.source || r.Fingerprint != Hash("acme-db", tc.raw) || r.Binding != tc.bind {
				t.Fatalf("got %+v", r)
			}
		})
	}
}

func TestComputeKubernetesErrorIsNotSilentlyIgnored(t *testing.T) {
	e := fakeEnv(map[string]string{"KUBERNETES_SERVICE_HOST": "10.0.0.1"})
	e.k8s = func() (string, error) { return "", errors.New("forbidden") }
	if _, err := compute("acme-db", e); err == nil {
		t.Fatal("expected error when kubernetes lookup fails, not a fallback to machine-id")
	}
}

func TestHash(t *testing.T) {
	a, b := Hash("p1", "id"), Hash("p2", "id")
	if a == b || len(a) != len("sha256:")+64 || a[:7] != "sha256:" {
		t.Fatalf("Hash = %q, %q", a, b)
	}
	// Pinned value so all SDKs derive the same fingerprint.
	if got, want := Hash("acme-db", "0123456789abcdef0123456789abcdef"), "sha256:44fd0d30659f018c9db00ba857ac97aa63d9b1e99471a6899c49796cfc1698c0"; got != want {
		t.Fatalf("Hash = %s, want %s", got, want)
	}
}

func TestNamespaceUID(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/namespaces/kube-system" || r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"metadata":{"name":"kube-system","uid":"5f0c-uid"}}`))
	}))
	defer srv.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})

	if uid, err := namespaceUID(srv.URL, "tok", ca); err != nil || uid != "5f0c-uid" {
		t.Fatalf("got %q, %v", uid, err)
	}
	if _, err := namespaceUID(srv.URL, "wrong", ca); err == nil {
		t.Fatal("expected error on 403")
	}
	if _, err := namespaceUID(srv.URL, "tok", []byte("not a cert")); err == nil {
		t.Fatal("expected error on bad CA")
	}
}
