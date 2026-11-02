package fingerprint

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// kubeSystemUID reads the kube-system namespace UID with the pod's service
// account. RBAC: get on namespaces/kube-system.
func kubeSystemUID(ctx context.Context) (string, error) {
	token, err := os.ReadFile(saDir + "/token")
	if err != nil {
		return "", fmt.Errorf("no service account token (is automountServiceAccountToken disabled?): %w", err)
	}
	ca, err := os.ReadFile(saDir + "/ca.crt")
	if err != nil {
		return "", fmt.Errorf("no service account CA: %w", err)
	}
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if port == "" {
		port = "443"
	}
	host := net.JoinHostPort(os.Getenv("KUBERNETES_SERVICE_HOST"), port)
	return namespaceUID(ctx, "https://"+host, trimASCII(string(token)), ca, []time.Duration{500 * time.Millisecond, 2 * time.Second})
}

// errPermanent marks responses that retrying won't fix (auth, RBAC, missing namespace).
var errPermanent = errors.New("permanent")

// namespaceUID fetches the UID, retrying transient failures after each backoff.
func namespaceUID(ctx context.Context, baseURL, token string, caPEM []byte, backoff []time.Duration) (string, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return "", errors.New("invalid service account CA")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Timeout: 5 * time.Second, Transport: tr}

	var lastErr error
	for attempt := 0; ; attempt++ {
		uid, err := getNamespaceUID(ctx, client, baseURL, token)
		if err == nil || errors.Is(err, errPermanent) {
			return uid, err
		}
		lastErr = err
		if attempt >= len(backoff) {
			return "", fmt.Errorf("%w: %v", ErrTransient, lastErr)
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("%w: %v", ErrTransient, ctx.Err())
		case <-time.After(backoff[attempt]):
		}
	}
}

func getNamespaceUID(ctx context.Context, client *http.Client, baseURL, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v1/namespaces/kube-system", nil)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errPermanent, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		// Certificate problems are configuration errors; retrying won't help.
		var certErr *tls.CertificateVerificationError
		var unknownCA x509.UnknownAuthorityError
		var hostErr x509.HostnameError
		var invalid x509.CertificateInvalidError
		if errors.As(err, &certErr) || errors.As(err, &unknownCA) || errors.As(err, &hostErr) || errors.As(err, &invalid) {
			return "", fmt.Errorf("%w: %v", errPermanent, err)
		}
		return "", err // network error or timeout: transient
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return "", fmt.Errorf("GET namespace kube-system: %s", resp.Status)
	default:
		return "", fmt.Errorf("%w: GET namespace kube-system: %s (needs RBAC get on namespaces/kube-system)", errPermanent, resp.Status)
	}
	var ns struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ns); err != nil {
		return "", fmt.Errorf("%w: decode namespace: %v", errPermanent, err)
	}
	if ns.Metadata.UID == "" {
		return "", fmt.Errorf("%w: kube-system namespace has no uid", errPermanent)
	}
	return ns.Metadata.UID, nil
}
