package online

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFileStore(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lease")
	s := FileStore{Path: p}
	if got, err := s.Load(); err != nil || got != "" {
		t.Fatalf("empty: %q, %v", got, err)
	}
	if err := s.Save("lf1.a.b.c"); err != nil {
		t.Fatal(err)
	}
	if got, err := (FileStore{Path: p}).Load(); err != nil || got != "lf1.a.b.c" { // another process's store
		t.Fatalf("Load = %q, %v", got, err)
	}
	if fi, err := os.Stat(p); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Errorf("file mode %v, %v", fi.Mode(), err)
	}
	if err := os.WriteFile(p, []byte("lf1.edited\r\n"), 0o600); err != nil { // put there by hand or a tool
		t.Fatal(err)
	}
	if got, err := s.Load(); err != nil || got != "lf1.edited" {
		t.Errorf("hand-written file: %q, %v", got, err)
	}
	if runtime.GOOS != "windows" && os.Getuid() != 0 { // an unreadable old file: the new one is written, Save succeeds
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
		if err := s.Save("lf1.new"); err != nil {
			t.Errorf("Save over an unreadable file: %v", err)
		}
		if got, _ := s.Load(); got != "lf1.new" {
			t.Errorf("after: %q", got)
		}
	}
	if err := s.Save(""); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Load(); err != nil || got != "" {
		t.Errorf("after Save(\"\"): %q, %v", got, err)
	}
	if _, err := (FileStore{}).Load(); !errors.Is(err, errNoPath) {
		t.Errorf("empty Path: %v", err)
	}
	if err := (FileStore{}).Save("x"); !errors.Is(err, errNoPath) {
		t.Errorf("empty Path: %v", err)
	}
}

// fakeKube stands in for the API server: one namespace's ConfigMaps and
// Secrets as plain JSON (independent of the store's types), with
// resourceVersion checks.
type fakeKube struct {
	mu        sync.Mutex
	objects   map[string]map[string]any // "configmaps/name", "secrets/name"
	rv        int
	conflicts int  // updates to answer 409 (someone else wrote) before accepting
	gone      bool // the next update finds the object deleted (404)
	forbid    bool
	tokens    []string
}

func (f *fakeKube) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens = append(f.tokens, r.Header.Get("Authorization"))
	fail := func(code int, reason string) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]any{"kind": "Status", "reason": reason, "message": reason + " (fake)"})
	}
	if f.forbid {
		fail(http.StatusForbidden, "Forbidden")
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/api/v1/namespaces/ns/")
	if !ok {
		fail(http.StatusBadRequest, "BadPath")
		return
	}
	var in map[string]any
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&in)
	}
	switch r.Method {
	case http.MethodGet:
		obj, ok := f.objects[rest]
		if !ok {
			fail(http.StatusNotFound, "NotFound")
			return
		}
		_ = json.NewEncoder(w).Encode(obj)
	case http.MethodPost:
		name, _ := in["metadata"].(map[string]any)["name"].(string)
		key := rest + "/" + name
		if _, ok := f.objects[key]; ok {
			fail(http.StatusConflict, "AlreadyExists")
			return
		}
		f.rv++
		in["metadata"].(map[string]any)["resourceVersion"] = strconv.Itoa(f.rv)
		f.objects[key] = in
		w.WriteHeader(http.StatusCreated)
	case http.MethodPut:
		cur, ok := f.objects[rest]
		if f.gone {
			f.gone = false
			delete(f.objects, rest)
			ok = false
		}
		if !ok {
			fail(http.StatusNotFound, "NotFound")
			return
		}
		if f.conflicts > 0 {
			f.conflicts--
			f.rv++
			cur["metadata"].(map[string]any)["resourceVersion"] = strconv.Itoa(f.rv)
		}
		if in["metadata"].(map[string]any)["resourceVersion"] != cur["metadata"].(map[string]any)["resourceVersion"] {
			fail(http.StatusConflict, "Conflict")
			return
		}
		f.rv++
		in["metadata"].(map[string]any)["resourceVersion"] = strconv.Itoa(f.rv)
		f.objects[rest] = in
	}
}

func (f *fakeKube) data(obj string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.objects[obj]
	if !ok {
		return nil
	}
	d, _ := o["data"].(map[string]any)
	return d
}

func TestKubernetesStores(t *testing.T) {
	for _, kind := range []string{"ConfigMap", "Secret"} {
		t.Run(kind, func(t *testing.T) {
			fk := &fakeKube{objects: map[string]map[string]any{}}
			srv := httptest.NewTLSServer(fk)
			defer srv.Close()
			token := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(token, []byte("t1\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			obj, value := "configmaps/lf-lease", func(v string) any { return v }
			var s Store
			if kind == "Secret" {
				obj, value = "secrets/lf-lease", func(v string) any { return base64.StdEncoding.EncodeToString([]byte(v)) }
				k := &KubernetesSecret{Name: "lf-lease"}
				k.base, k.tokenFile, k.client, k.ns = srv.URL, token, srv.Client(), "ns"
				s = k
			} else {
				k := &KubernetesConfigMap{Name: "lf-lease"}
				k.base, k.tokenFile, k.client, k.ns = srv.URL, token, srv.Client(), "ns"
				s = k
			}
			if got, err := s.Load(); err != nil || got != "" {
				t.Fatalf("missing: %q, %v", got, err)
			}
			if err := s.Save(""); err != nil || fk.data(obj) != nil {
				t.Fatalf("removing from nothing: %v", err)
			}
			if err := s.Save("lf1.first"); err != nil { // created
				t.Fatal(err)
			}
			if d := fk.data(obj); d["lease"] != value("lf1.first") {
				t.Fatalf("wire value %v", d["lease"])
			}
			if got, err := s.Load(); err != nil || got != "lf1.first" {
				t.Fatalf("Load = %q, %v", got, err)
			}
			// An object made beforehand (as the README advises), with more in
			// it than the store knows: everything else survives a Save.
			fk.mu.Lock()
			fk.objects[obj] = map[string]any{"apiVersion": "v1", "kind": kind, "type": "example.com/license",
				"metadata": map[string]any{"name": "lf-lease", "resourceVersion": "100", "labels": map[string]any{"app": "acme"},
					"annotations": map[string]any{"note": "keep"}, "managedFields": []any{map[string]any{"manager": "kubectl"}}},
				"data": map[string]any{"other": value("keep")}}
			fk.rv, fk.conflicts = 100, 2 // two concurrent writers first
			fk.mu.Unlock()
			if err := os.WriteFile(token, []byte("t2"), 0o600); err != nil { // rotated
				t.Fatal(err)
			}
			if err := s.Save("lf1.second"); err != nil {
				t.Fatalf("Save after conflicts: %v", err)
			}
			fk.mu.Lock()
			o := fk.objects[obj]
			md := o["metadata"].(map[string]any)
			if o["type"] != "example.com/license" || md["labels"].(map[string]any)["app"] != "acme" || md["annotations"].(map[string]any)["note"] != "keep" ||
				md["managedFields"] == nil || o["data"].(map[string]any)["other"] != value("keep") || o["data"].(map[string]any)["lease"] != value("lf1.second") {
				t.Errorf("object after Save: %v", o)
			}
			last := fk.tokens[len(fk.tokens)-1]
			fk.mu.Unlock()
			if last != "Bearer t2" {
				t.Errorf("rotated token not used: %q", last)
			}
			// Deleted between the read and the update: another round creates it.
			fk.mu.Lock()
			fk.gone = true
			fk.mu.Unlock()
			if err := s.Save("lf1.third"); err != nil {
				t.Fatalf("deleted meanwhile: %v", err)
			}
			if got, _ := s.Load(); got != "lf1.third" {
				t.Errorf("after recreate: %q", got)
			}
			if err := s.Save(""); err != nil {
				t.Fatal(err)
			}
			if _, ok := fk.data(obj)["lease"]; ok {
				t.Error("Save(\"\") kept the key")
			}
			// Endless conflicts and RBAC refusals are errors; a 403 says what to grant.
			fk.mu.Lock()
			fk.conflicts = 100
			fk.mu.Unlock()
			if err := s.Save("lf1.x"); err == nil {
				t.Error("endless conflicts: no error")
			}
			fk.mu.Lock()
			fk.conflicts, fk.forbid = 0, true
			fk.mu.Unlock()
			if _, err := s.Load(); err == nil {
				t.Error("forbidden Load: no error")
			}
			if err := s.Save("x"); err == nil || !strings.Contains(err.Error(), "beforehand") {
				t.Errorf("forbidden Save: %v", err)
			}
		})
	}
}

func TestKubernetesStoreNames(t *testing.T) {
	// A server that would accept anything: only the name checks refuse.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	cm := func(ns, name, key string) Store {
		k := &KubernetesConfigMap{Namespace: ns, Name: name, Key: key}
		k.base, k.tokenFile, k.client, k.ns = srv.URL, token, srv.Client(), "ns"
		return k
	}
	sec := func(name, key string) Store {
		k := &KubernetesSecret{Name: name, Key: key}
		k.base, k.tokenFile, k.client, k.ns = srv.URL, token, srv.Client(), "ns"
		return k
	}
	if err := cm("", "fine.example-1", "a.b_c-1").Save("x"); err != nil {
		t.Fatalf("valid names refused: %v", err)
	}
	for name, s := range map[string]Store{
		"dot-dot name":    cm("", "..", ""),
		"slash name":      sec("a/b", ""),
		"empty name":      cm("", "", ""),
		"bad namespace":   cm("Bad_NS", "x", ""),
		"slash key":       sec("x", "a/b"),
		"upper-case name": sec("Lease", ""),
		"empty label":     cm("", "a..b", ""),
		"dash label":      cm("", "a.-b", ""),
		"long name":       cm("", strings.Repeat("a", 254), ""),
		"dot key":         cm("", "x", "."),
		"dot-dot key":     cm("", "x", "..x"),
	} {
		if _, err := s.Load(); err == nil || !strings.Contains(err.Error(), "valid") {
			t.Errorf("%s: Load: %v", name, err)
		}
		if err := s.Save("x"); err == nil || !strings.Contains(err.Error(), "valid") {
			t.Errorf("%s: Save: %v", name, err)
		}
	}
	// A server that never answers: Save gives up at apiTimeout.
	hang := make(chan struct{})
	slow := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-hang }))
	defer slow.Close()
	defer close(hang)
	defer func(d time.Duration) { apiTimeout = d }(apiTimeout)
	apiTimeout = 300 * time.Millisecond
	k := &KubernetesConfigMap{Name: "x"}
	k.base, k.tokenFile, k.client, k.ns = slow.URL, token, slow.Client(), "ns"
	done := make(chan error, 1)
	go func() { done <- k.Save("x") }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("hung server: no error")
		}
	case <-time.After(5 * time.Second):
		t.Error("hung server: Save didn't give up")
	}
	// Outside a cluster, a clear error.
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if err := (&KubernetesSecret{Name: "x"}).Save("x"); err == nil || !strings.Contains(err.Error(), "not in a Kubernetes cluster") {
		t.Errorf("no cluster: %v", err)
	}
}
