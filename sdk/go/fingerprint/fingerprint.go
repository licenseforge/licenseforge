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
// "sha256:" + hex(sha256("lf-fp-v1" NUL tenant NUL product NUL rawID)), so
// different vendors (tenants) and products see unrelated fingerprints for the
// same machine.
package fingerprint

import (
	"context"
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

// Hash derives the fingerprint for a tenant's product from a raw ID. Fields
// are NUL-separated so no combination of IDs can collide.
func Hash(tenantID, productID, rawID string) string {
	sum := sha256.Sum256([]byte("lf-fp-v1\x00" + tenantID + "\x00" + productID + "\x00" + rawID))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Compute returns the default fingerprint for a tenant's product on this
// machine. tenantID and productID are the same IDs the license carries. ctx
// bounds the Kubernetes lookup (up to ~17s with retries).
func Compute(ctx context.Context, tenantID, productID string, opts Options) (Result, error) {
	return compute(ctx, tenantID, productID, opts, env{getenv: os.Getenv, k8s: kubeSystemUID, machineID: osMachineID})
}

type env struct {
	getenv    func(string) string
	k8s       func(context.Context) (string, error)
	machineID func() (string, error)
}

// trimASCII removes only SP, HT, CR and LF, so every SDK trims identically.
func trimASCII(s string) string { return strings.Trim(s, " \t\r\n") }

func compute(ctx context.Context, tenantID, productID string, opts Options, e env) (Result, error) {
	if tenantID == "" || productID == "" || strings.ContainsRune(tenantID+productID, 0) {
		return Result{}, errors.New("fingerprint: tenant and product IDs must be non-empty and contain no NUL")
	}
	if opts.Override != nil {
		raw, err := opts.Override()
		if err != nil {
			return Result{}, fmt.Errorf("fingerprint: override: %w", err)
		}
		if raw = trimASCII(raw); raw == "" {
			return Result{}, errors.New("fingerprint: override returned an empty ID")
		}
		return Result{Hash(tenantID, productID, raw), SourceOverride, "machine"}, nil
	}
	if opts.AllowEnvOverride {
		if raw := trimASCII(e.getenv(EnvOverride)); raw != "" {
			return Result{Hash(tenantID, productID, raw), SourceEnv, "machine"}, nil
		}
	}
	if e.getenv("KUBERNETES_SERVICE_HOST") != "" {
		uid, err := e.k8s(ctx)
		if err != nil {
			return Result{}, fmt.Errorf("fingerprint: kubernetes: %w", err)
		}
		return Result{Hash(tenantID, productID, uid), SourceKubernetes, "cluster"}, nil
	}
	id, err := e.machineID()
	if err != nil {
		if errors.Is(err, ErrNoFingerprint) {
			return Result{}, err
		}
		return Result{}, fmt.Errorf("%w: %v", ErrNoFingerprint, err)
	}
	return Result{Hash(tenantID, productID, id), SourceMachineID, "machine"}, nil
}
