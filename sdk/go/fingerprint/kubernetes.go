package fingerprint

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// kubeSystemUID reads the kube-system namespace UID with the pod's service
// account. RBAC: get on namespaces/kube-system.
func kubeSystemUID() (string, error) {
	token, err := os.ReadFile(saDir + "/token")
	if err != nil {
		return "", err
	}
	ca, err := os.ReadFile(saDir + "/ca.crt")
	if err != nil {
		return "", err
	}
	host := net.JoinHostPort(os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT"))
	return namespaceUID("https://"+host, strings.TrimSpace(string(token)), ca)
}

func namespaceUID(baseURL, token string, caPEM []byte) (string, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return "", errors.New("invalid service account CA")
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/namespaces/kube-system", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET namespace kube-system: %s (needs RBAC get on namespaces/kube-system)", resp.Status)
	}
	var ns struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ns); err != nil {
		return "", err
	}
	if ns.Metadata.UID == "" {
		return "", errors.New("kube-system namespace has no uid")
	}
	return ns.Metadata.UID, nil
}
