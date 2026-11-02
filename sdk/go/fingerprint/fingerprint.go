// Package fingerprint computes the default machine or cluster fingerprint a
// license is bound to (ADR-0017).
//
// Sources, first match wins:
//  1. LICENSEFORGE_FINGERPRINT environment variable (explicit, vendor/admin supplied)
//  2. Kubernetes: the kube-system namespace UID (cluster binding)
//  3. The OS machine ID: /etc/machine-id (Linux), MachineGuid (Windows), IOPlatformUUID (macOS)
//
// Plain containers outside Kubernetes have no reliable ID (images often bake
// in the same machine-id), so Compute fails there unless the override is set.
//
// The raw ID never leaves the machine: the fingerprint is
// "sha256:" + hex(sha256(productID + ":" + rawID)), so different products see
// different fingerprints for the same machine.
package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Source says where a fingerprint came from; it is recorded with activations.
type Source string

const (
	SourceEnv        Source = "env"
	SourceKubernetes Source = "kubernetes"
	SourceMachineID  Source = "machine-id"
)

// Result is a computed fingerprint.
type Result struct {
	Fingerprint string // "sha256:<hex>"
	Source      Source
	Binding     string // "cluster" for Kubernetes, else "machine"
}

// EnvOverride is the environment variable that supplies an explicit raw ID.
const EnvOverride = "LICENSEFORGE_FINGERPRINT"

// ErrNoFingerprint means no reliable ID was found; set EnvOverride.
var ErrNoFingerprint = errors.New("fingerprint: no reliable machine ID; set " + EnvOverride)

// Hash derives the fingerprint for productID from a raw ID.
func Hash(productID, rawID string) string {
	sum := sha256.Sum256([]byte(productID + ":" + rawID))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Compute returns the default fingerprint for productID on this machine.
func Compute(productID string) (Result, error) {
	return compute(productID, env{getenv: os.Getenv, exists: exists, k8s: kubeSystemUID, machineID: osMachineID})
}

type env struct {
	getenv    func(string) string
	exists    func(string) bool
	k8s       func() (string, error)
	machineID func() (string, error)
}

func compute(productID string, e env) (Result, error) {
	if productID == "" {
		return Result{}, errors.New("fingerprint: empty product ID")
	}
	if raw := strings.TrimSpace(e.getenv(EnvOverride)); raw != "" {
		return Result{Hash(productID, raw), SourceEnv, "machine"}, nil
	}
	if e.getenv("KUBERNETES_SERVICE_HOST") != "" {
		uid, err := e.k8s()
		if err != nil {
			return Result{}, fmt.Errorf("fingerprint: kubernetes: %w", err)
		}
		return Result{Hash(productID, uid), SourceKubernetes, "cluster"}, nil
	}
	if e.exists("/.dockerenv") || e.exists("/run/.containerenv") {
		return Result{}, ErrNoFingerprint
	}
	id, err := e.machineID()
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrNoFingerprint, err)
	}
	return Result{Hash(productID, id), SourceMachineID, "machine"}, nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
