package online

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"licenseforge.io/licenseforge/sdk/go/clock"
)

// FileStore keeps the lease in a file: locked across processes, written
// atomically with mode 0600 (clock.FileStore). Save("") empties it. Use a
// persistent path; a lease that fails to load or verify is ignored (New).
type FileStore struct{ Path string }

// Load implements Store.
func (f FileStore) Load() (string, error) {
	var lease string
	err := clock.FileStore{Path: f.Path}.Update(func(cur []byte) ([]byte, error) {
		lease = strings.TrimSpace(string(cur))
		return nil, nil // no change
	})
	return lease, err
}

// Save implements Store.
func (f FileStore) Save(lease string) error {
	return clock.FileStore{Path: f.Path}.Update(func([]byte) ([]byte, error) {
		return []byte(lease), nil // non-nil even when empty: "" empties the file
	})
}

// KubernetesSecret keeps the lease in one key of a Secret, through the
// in-cluster API with the pod's service account (ADR-0004): every replica
// of a cluster-bound app shares it. RBAC: get and update on the Secret
// (resourceNames: [Name]); create in the namespace too, unless the Secret
// is created beforehand (recommended: create can't be limited by name).
// The token is read on every request (projected tokens rotate).
type KubernetesSecret struct {
	Namespace string // "": the pod's own
	Name      string
	Key       string // "": "lease"

	once sync.Once
	api  *kubeAPI
	err  error
}

const serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// kubeAPI is the API server as the pod's service account sees it.
type kubeAPI struct {
	base      string
	tokenFile string
	client    *http.Client
}

func (k *KubernetesSecret) init() error {
	k.once.Do(func() {
		if k.api != nil { // set by tests
			return
		}
		k.api, k.err = inCluster(serviceAccountDir)
		if k.err == nil && k.Namespace == "" {
			ns, err := os.ReadFile(serviceAccountDir + "/namespace")
			k.Namespace, k.err = strings.TrimSpace(string(ns)), err
		}
	})
	switch {
	case k.err != nil:
		return fmt.Errorf("online: kubernetes secret store: %w", k.err)
	case k.Name == "" || k.Namespace == "":
		return errors.New("online: kubernetes secret store: Name (and a namespace) required")
	}
	return nil
}

func inCluster(dir string) (*kubeAPI, error) {
	ca, err := os.ReadFile(dir + "/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("not in a cluster, or no service account (automountServiceAccountToken?): %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid service account CA")
	}
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if port == "" {
		port = "443"
	}
	return &kubeAPI{base: "https://" + net.JoinHostPort(os.Getenv("KUBERNETES_SERVICE_HOST"), port), tokenFile: dir + "/token",
		client: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}}, nil
}

func (k *KubernetesSecret) key() string {
	if k.Key == "" {
		return "lease"
	}
	return k.Key
}

// secret is the part of a Secret the store reads and writes.
type secret struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   map[string]any    `json:"metadata"`
	Type       string            `json:"type,omitempty"`
	Data       map[string][]byte `json:"data,omitempty"` // base64 in JSON, as the API wants
}

// errKubeStatus carries an unexpected API answer.
type errKubeStatus struct {
	code int
	body string
}

func (e *errKubeStatus) Error() string { return fmt.Sprintf("kubernetes API: %d %s", e.code, e.body) }

func (k *KubernetesSecret) do(method, path string, in any, out any) error {
	token, err := os.ReadFile(k.api.tokenFile)
	if err != nil {
		return err
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, k.api.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := k.api.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return &errKubeStatus{resp.StatusCode, strings.TrimSpace(string(raw))}
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func (k *KubernetesSecret) path(name string) string {
	p := "/api/v1/namespaces/" + url.PathEscape(k.Namespace) + "/secrets"
	if name != "" {
		p += "/" + url.PathEscape(name)
	}
	return p
}

func status(err error) int {
	var s *errKubeStatus
	if errors.As(err, &s) {
		return s.code
	}
	return 0
}

// Load implements Store: "" when the Secret or the key is missing.
func (k *KubernetesSecret) Load() (string, error) {
	if err := k.init(); err != nil {
		return "", err
	}
	var s secret
	err := k.do(http.MethodGet, k.path(k.Name), nil, &s)
	if status(err) == http.StatusNotFound {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("online: loading the lease from secret %s/%s: %w", k.Namespace, k.Name, err)
	}
	return string(s.Data[k.key()]), nil
}

// Save implements Store: sets (or, for "", removes) the key, creating the
// Secret if it doesn't exist. A concurrent writer (409) means a retry with
// the Secret as it is now; the Client already serializes its own saves.
func (k *KubernetesSecret) Save(lease string) error {
	if err := k.init(); err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		err := k.save(lease)
		if status(err) == http.StatusConflict && attempt < 3 { // also a create that lost a race (AlreadyExists)
			continue
		}
		if err != nil {
			return fmt.Errorf("online: saving the lease to secret %s/%s: %w", k.Namespace, k.Name, err)
		}
		return nil
	}
}

func (k *KubernetesSecret) save(lease string) error {
	var s secret
	err := k.do(http.MethodGet, k.path(k.Name), nil, &s)
	switch {
	case status(err) == http.StatusNotFound:
		if lease == "" {
			return nil // nothing to remove
		}
		return k.do(http.MethodPost, k.path(""), secret{APIVersion: "v1", Kind: "Secret", Type: "Opaque",
			Metadata: map[string]any{"name": k.Name}, Data: map[string][]byte{k.key(): []byte(lease)}}, nil)
	case err != nil:
		return err
	}
	if s.Data == nil {
		s.Data = map[string][]byte{}
	}
	if lease == "" {
		delete(s.Data, k.key())
	} else {
		s.Data[k.key()] = []byte(lease)
	}
	// The resourceVersion read above makes the update conditional: a
	// concurrent change answers 409 and the loop reads again.
	return k.do(http.MethodPut, k.path(k.Name), s, nil)
}
