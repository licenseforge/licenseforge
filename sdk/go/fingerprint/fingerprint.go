// Package fingerprint computes the default machine or cluster fingerprint a
// license is bound to (ADR-0017).
//
// Sources, first match wins:
//  1. Options.Override, or the LICENSEFORGE_FINGERPRINT environment variable
//     if the vendor enabled Options.AllowEnvOverride
//  2. Kubernetes: the kube-system namespace UID (cluster binding)
//  3. The OS machine ID: /etc/machine-id (Linux), MachineGuid (Windows),
//     IOPlatformUUID (macOS)
//
// On Linux, containers outside Kubernetes only get a fingerprint when the
// host's /etc/machine-id is bind-mounted in; a machine-id baked into an image
// is shared by every container, and a tmpfs machine-id changes every boot, so
// both are refused.
//
// The raw ID never leaves the machine: the fingerprint is
// "sha256:" + hex(sha256(productID + ":" + rawID)).
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
	SourceOverride   Source = "override"
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

// EnvOverride is the environment variable that supplies an explicit raw ID
// when Options.AllowEnvOverride is set.
const EnvOverride = "LICENSEFORGE_FINGERPRINT"

var (
	// ErrNoFingerprint means no stable, unique ID was found.
	ErrNoFingerprint = errors.New("fingerprint: no stable machine ID (mount the host /etc/machine-id, or have the vendor enable an override)")
	// ErrTransient means a source was temporarily unavailable (e.g. the
	// Kubernetes API); retrying later may succeed.
	ErrTransient = errors.New("fingerprint: source temporarily unavailable")
)

// Options are set by the vendor embedding the SDK, not by end users.
type Options struct {
	// Override returns a raw ID chosen by the vendor (hardware serial, cloud
	// instance ID, TPM-backed ID...). It wins over every other source.
	Override func() (string, error)
	// AllowEnvOverride lets end users set LICENSEFORGE_FINGERPRINT. Off by
	// default: anyone who can set it can share one binding across machines.
	AllowEnvOverride bool
}

// Hash derives the fingerprint for productID from a raw ID.
func Hash(productID, rawID string) string {
	sum := sha256.Sum256([]byte(productID + ":" + rawID))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Compute returns the default fingerprint for productID on this machine.
func Compute(productID string, opts Options) (Result, error) {
	return compute(productID, opts, env{getenv: os.Getenv, k8s: kubeSystemUID, machineID: osMachineID})
}

type env struct {
	getenv    func(string) string
	k8s       func() (string, error)
	machineID func() (string, error)
}

// trimASCII removes only SP, HT, CR and LF, so every SDK trims identically.
func trimASCII(s string) string { return strings.Trim(s, " \t\r\n") }

func compute(productID string, opts Options, e env) (Result, error) {
	if productID == "" {
		return Result{}, errors.New("fingerprint: empty product ID")
	}
	if opts.Override != nil {
		raw, err := opts.Override()
		if err != nil {
			return Result{}, fmt.Errorf("fingerprint: override: %w", err)
		}
		if raw = trimASCII(raw); raw == "" {
			return Result{}, errors.New("fingerprint: override returned an empty ID")
		}
		return Result{Hash(productID, raw), SourceOverride, "machine"}, nil
	}
	if opts.AllowEnvOverride {
		if raw := trimASCII(e.getenv(EnvOverride)); raw != "" {
			return Result{Hash(productID, raw), SourceEnv, "machine"}, nil
		}
	}
	if e.getenv("KUBERNETES_SERVICE_HOST") != "" {
		uid, err := e.k8s()
		if err != nil {
			return Result{}, fmt.Errorf("fingerprint: kubernetes: %w", err)
		}
		return Result{Hash(productID, uid), SourceKubernetes, "cluster"}, nil
	}
	id, err := e.machineID()
	if err != nil {
		if errors.Is(err, ErrNoFingerprint) {
			return Result{}, err
		}
		return Result{}, fmt.Errorf("%w: %v", ErrNoFingerprint, err)
	}
	return Result{Hash(productID, id), SourceMachineID, "machine"}, nil
}
