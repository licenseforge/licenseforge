package online

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
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
	if err := s.Save(""); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Load(); err != nil || got != "" {
		t.Errorf("after Save(\"\"): %q, %v", got, err)
	}
}

// fakeKube is the part of the API server the store uses: one namespace's
// Secrets, with resourceVersion checks.
type fakeKube struct {
	mu        sync.Mutex
	secrets   map[string]secret
	rv        int
	conflicts int      // PUTs to answer 409 before accepting
	forbid    bool     // answer 403 (RBAC)
	tokens    []string // Authorization tokens seen
}

func (f *fakeKube) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens = append(f.tokens, r.Header.Get("Authorization"))
	if f.forbid {
		http.Error(w, `{"reason":"Forbidden"}`, http.StatusForbidden)
		return
	}
	name := filepath.Base(r.URL.Path)
	if filepath.Dir(r.URL.Path) != "/api/v1/namespaces/ns/secrets" && r.URL.Path != "/api/v1/namespaces/ns/secrets" {
		http.Error(w, "bad path "+r.URL.Path, http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s, ok := f.secrets[name]
		if !ok {
			http.Error(w, `{"reason":"NotFound"}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(s)
	case http.MethodPost:
		var s secret
		_ = json.NewDecoder(r.Body).Decode(&s)
		n, _ := s.Metadata["name"].(string)
		if _, ok := f.secrets[n]; ok {
			http.Error(w, `{"reason":"AlreadyExists"}`, http.StatusConflict)
			return
		}
		f.rv++
		s.Metadata["resourceVersion"] = strconv.Itoa(f.rv)
		f.secrets[n] = s
		w.WriteHeader(http.StatusCreated)
	case http.MethodPut:
		var s secret
		_ = json.NewDecoder(r.Body).Decode(&s)
		cur, ok := f.secrets[name]
		if !ok {
			http.Error(w, `{"reason":"NotFound"}`, http.StatusNotFound)
			return
		}
		if f.conflicts > 0 || s.Metadata["resourceVersion"] != cur.Metadata["resourceVersion"] {
			if f.conflicts > 0 {
				f.conflicts--
				f.rv++ // someone else wrote meanwhile
				cur.Metadata["resourceVersion"] = strconv.Itoa(f.rv)
				f.secrets[name] = cur
			}
			http.Error(w, `{"reason":"Conflict"}`, http.StatusConflict)
			return
		}
		f.rv++
		s.Metadata["resourceVersion"] = strconv.Itoa(f.rv)
		f.secrets[name] = s
	default:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	}
}

func TestKubernetesSecretStore(t *testing.T) {
	fk := &fakeKube{secrets: map[string]secret{}}
	srv := httptest.NewTLSServer(fk)
	defer srv.Close()
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("t1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &KubernetesSecret{Namespace: "ns", Name: "lf-lease", api: &kubeAPI{base: srv.URL, tokenFile: token, client: srv.Client()}}
	if got, err := s.Load(); err != nil || got != "" {
		t.Fatalf("no Secret: %q, %v", got, err)
	}
	if err := s.Save(""); err != nil || len(fk.secrets) != 0 {
		t.Fatalf("removing from no Secret: %v, %v", err, fk.secrets)
	}
	if err := s.Save("lf1.first"); err != nil { // created
		t.Fatal(err)
	}
	if got, err := s.Load(); err != nil || got != "lf1.first" {
		t.Fatalf("Load = %q, %v", got, err)
	}
	// Another key of the Secret survives; a concurrent writer (409) means a retry.
	fk.mu.Lock()
	sec := fk.secrets["lf-lease"]
	sec.Data["other"] = []byte("keep")
	fk.secrets["lf-lease"] = sec
	fk.conflicts = 2
	fk.mu.Unlock()
	if err := os.WriteFile(token, []byte("t2"), 0o600); err != nil { // rotated
		t.Fatal(err)
	}
	if err := s.Save("lf1.second"); err != nil {
		t.Fatalf("Save after conflicts: %v", err)
	}
	if got, _ := s.Load(); got != "lf1.second" || string(fk.secrets["lf-lease"].Data["other"]) != "keep" {
		t.Errorf("after update: %q, other %q", got, fk.secrets["lf-lease"].Data["other"])
	}
	if last := fk.tokens[len(fk.tokens)-1]; last != "Bearer t2" {
		t.Errorf("rotated token not used: %q", last)
	}
	if err := s.Save(""); err != nil {
		t.Fatal(err)
	}
	if _, ok := fk.secrets["lf-lease"].Data["lease"]; ok || string(fk.secrets["lf-lease"].Data["other"]) != "keep" {
		t.Errorf("Save(\"\") left %v", fk.secrets["lf-lease"].Data)
	}
	// Endless conflicts and RBAC refusals are errors.
	fk.conflicts = 10
	if err := s.Save("lf1.third"); err == nil {
		t.Error("endless conflicts: no error")
	}
	fk.conflicts, fk.forbid = 0, true
	if _, err := s.Load(); err == nil {
		t.Error("forbidden Load: no error")
	}
	if err := s.Save("x"); err == nil {
		t.Error("forbidden Save: no error")
	}
	// Outside a cluster, a clear error.
	if err := (&KubernetesSecret{Namespace: "ns", Name: "x"}).Save("x"); err == nil {
		t.Error("no service account: no error")
	}
}
