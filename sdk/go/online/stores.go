package online

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"licenseforge.io/licenseforge/sdk/go/clock"
)

// FileStore keeps the lease in a file: locked across processes, written
// atomically with mode 0600 (clock.FileStore). Save("") empties it. Use a
// persistent path; a lease that fails to load or verify is ignored (New).
type FileStore struct{ Path string }

var errNoPath = errors.New("lease store: FileStore.Path is empty")

// Load implements Store.
func (f FileStore) Load() (string, error) {
	if f.Path == "" {
		return "", errNoPath
	}
	var lease string
	err := clock.FileStore{Path: f.Path}.Update(func(cur []byte) ([]byte, error) {
		lease = strings.TrimSpace(string(cur))
		return nil, nil // no change
	})
	return lease, err
}

// Save implements Store.
func (f FileStore) Save(lease string) error {
	if f.Path == "" {
		return errNoPath
	}
	err := clock.FileStore{Path: f.Path}.Update(func([]byte) ([]byte, error) {
		return []byte(lease), nil // non-nil even when empty: "" empties the file
	})
	if err != nil {
		// The old file may have been unreadable while the write went
		// through (clock.FileStore reports both): written is stored.
		if got, lerr := f.Load(); lerr == nil && got == strings.TrimSpace(lease) {
			return nil
		}
	}
	return err
}

// KubernetesConfigMap keeps the lease in one key of a ConfigMap, through
// the in-cluster API with the pod's service account (ADR-0004: the lease is
// signed, not secret), so every replica of a cluster-bound app shares it.
// RBAC: get and update on that ConfigMap (resourceNames: [Name]); create it
// beforehand, since create can't be limited to one name.
type KubernetesConfigMap struct {
	Namespace string // "": the pod's own
	Name      string
	Key       string // "": "lease"
	kubeStore
}

// KubernetesSecret is KubernetesConfigMap on a Secret, for clusters whose
// policy prefers Secrets (ADR-0004, amended).
type KubernetesSecret struct {
	Namespace string // "": the pod's own
	Name      string
	Key       string // "": "lease"
	kubeStore
}

// Load implements Store: "" when the ConfigMap or the key is missing.
func (k *KubernetesConfigMap) Load() (string, error) {
	return k.load("configmaps", "ConfigMap", k.Namespace, k.Name, k.Key)
}

// Save implements Store: sets (or, for "", removes) the key, creating the
// ConfigMap if it doesn't exist.
func (k *KubernetesConfigMap) Save(lease string) error {
	return k.save("configmaps", "ConfigMap", k.Namespace, k.Name, k.Key, lease)
}

// Load implements Store: "" when the Secret or the key is missing.
func (k *KubernetesSecret) Load() (string, error) {
	return k.load("secrets", "Secret", k.Namespace, k.Name, k.Key)
}

// Save implements Store: sets (or, for "", removes) the key, creating the
// Secret if it doesn't exist.
func (k *KubernetesSecret) Save(lease string) error {
	return k.save("secrets", "Secret", k.Namespace, k.Name, k.Key, lease)
}

const serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// saveTimeout bounds a whole Save (every attempt): the Client holds its
// commit lock meanwhile.
const saveTimeout = 15 * time.Second

var (
	dnsLabel     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	dnsSubdomain = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
	dataKey      = regexp.MustCompile(`^[-._a-zA-Z0-9]{1,253}$`)
)

// kubeStore is the shared part: the API server as the pod's service account
// sees it. The token is read on every request (projected tokens rotate).
type kubeStore struct {
	once      sync.Once
	base      string
	tokenFile string
	client    *http.Client
	ns        string // the pod's namespace
	err       error
}

func (k *kubeStore) init() error {
	k.once.Do(func() {
		if k.client != nil { // set by tests
			return
		}
		k.err = k.inCluster(serviceAccountDir)
	})
	return k.err
}

func (k *kubeStore) inCluster(dir string) error {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	if host == "" {
		return errors.New("lease store: not in a Kubernetes cluster (no KUBERNETES_SERVICE_HOST)")
	}
	ca, err := os.ReadFile(dir + "/ca.crt")
	if err != nil {
		return fmt.Errorf("lease store: no service account (automountServiceAccountToken?): %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return errors.New("lease store: invalid service account CA")
	}
	ns, err := os.ReadFile(dir + "/namespace")
	if err != nil {
		return fmt.Errorf("lease store: the pod's namespace: %w", err)
	}
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if port == "" {
		port = "443"
	}
	k.base, k.tokenFile, k.ns = "https://"+net.JoinHostPort(host, port), dir+"/token", strings.TrimSpace(string(ns))
	k.client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	return nil
}

// target checks the names and returns the object's API path and data key.
func (k *kubeStore) target(resource, kind, namespace, name, key string) (path, dkey string, err error) {
	if err := k.init(); err != nil {
		return "", "", err
	}
	if namespace == "" {
		namespace = k.ns
	}
	if key == "" {
		key = "lease"
	}
	switch {
	case !dnsLabel.MatchString(namespace):
		return "", "", fmt.Errorf("lease store: namespace %q isn't a valid name", namespace)
	case !dnsSubdomain.MatchString(name):
		return "", "", fmt.Errorf("lease store: %s name %q isn't a valid name", kind, name)
	case !dataKey.MatchString(key):
		return "", "", fmt.Errorf("lease store: key %q isn't a valid %s key", key, kind)
	}
	return "/api/v1/namespaces/" + namespace + "/" + resource + "/" + name, key, nil
}

// apiError is an unexpected API answer: its status and the API's message.
type apiError struct {
	code int
	msg  string
}

func (e *apiError) Error() string { return fmt.Sprintf("kubernetes API: %d %s", e.code, e.msg) }

func code(err error) int {
	var e *apiError
	if errors.As(err, &e) {
		return e.code
	}
	return 0
}

func (k *kubeStore) do(ctx context.Context, method, path string, in, out any) error {
	token, err := os.ReadFile(k.tokenFile)
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
	req, err := http.NewRequestWithContext(ctx, method, k.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := k.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // a near-limit object (1 MiB of base64 data and metadata)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var st struct{ Message string }
		if json.Unmarshal(raw, &st) != nil || st.Message == "" {
			st.Message = string(raw[:min(len(raw), 200)])
		}
		return &apiError{resp.StatusCode, st.Message}
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// decodeValue and encodeValue convert between the lease and the object's
// data value: base64 in a Secret, plain in a ConfigMap.
func decodeValue(kind string, v any) (string, error) {
	s, _ := v.(string)
	if kind != "Secret" {
		return s, nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	return string(b), err
}

func encodeValue(kind, lease string) string {
	if kind != "Secret" {
		return lease
	}
	return base64.StdEncoding.EncodeToString([]byte(lease))
}

func (k *kubeStore) load(resource, kind, namespace, name, key string) (string, error) {
	path, key, err := k.target(resource, kind, namespace, name, key)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), saveTimeout)
	defer cancel()
	var obj map[string]any
	err = k.do(ctx, http.MethodGet, path, nil, &obj)
	if code(err) == http.StatusNotFound {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("lease store: loading %s %s: %w", kind, path, err)
	}
	data, _ := obj["data"].(map[string]any)
	lease, err := decodeValue(kind, data[key])
	if err != nil {
		return "", fmt.Errorf("lease store: %s %s key %s: %w", kind, path, key, err)
	}
	return lease, nil
}

// save reads the object and writes it back with the key set or removed,
// conditional on the resourceVersion read; everything else in it (type,
// labels, annotations, other keys) stays as it was. A concurrent writer
// (409) or a deletion meanwhile (404 on update) means another round, after
// a short jittered pause (replicas sharing the lease refresh together).
func (k *kubeStore) save(resource, kind, namespace, name, key, lease string) error {
	path, key, err := k.target(resource, kind, namespace, name, key)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), saveTimeout)
	defer cancel()
	for attempt := 0; ; attempt++ {
		err = k.saveOnce(ctx, path, kind, name, key, lease)
		if c := code(err); (c == http.StatusConflict || c == http.StatusNotFound) && attempt < 4 {
			pause, _ := rand.Int(rand.Reader, big.NewInt(200))
			select {
			case <-ctx.Done():
			case <-time.After(time.Duration(50+pause.Int64()) * time.Millisecond):
				continue
			}
		}
		switch {
		case err == nil:
			return nil
		case code(err) == http.StatusForbidden:
			return fmt.Errorf("lease store: saving %s %s: %w (create the %s beforehand and grant get and update on it by name)", kind, path, err, kind)
		default:
			return fmt.Errorf("lease store: saving %s %s: %w", kind, path, err)
		}
	}
}

func (k *kubeStore) saveOnce(ctx context.Context, path, kind, name, key, lease string) error {
	var obj map[string]any
	err := k.do(ctx, http.MethodGet, path, nil, &obj)
	switch {
	case code(err) == http.StatusNotFound:
		if lease == "" {
			return nil // nothing to remove
		}
		create := map[string]any{"apiVersion": "v1", "kind": kind, "metadata": map[string]any{"name": name},
			"data": map[string]any{key: encodeValue(kind, lease)}}
		return k.do(ctx, http.MethodPost, path[:strings.LastIndex(path, "/")], create, nil) // 409 if created meanwhile: another round
	case err != nil:
		return err
	}
	data, _ := obj["data"].(map[string]any)
	if data == nil {
		data = map[string]any{}
	}
	if lease == "" {
		delete(data, key)
	} else {
		data[key] = encodeValue(kind, lease)
	}
	obj["data"] = data
	return k.do(ctx, http.MethodPut, path, obj, nil) // carries the resourceVersion read: conditional
}
