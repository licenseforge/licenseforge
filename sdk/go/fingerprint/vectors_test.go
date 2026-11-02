package fingerprint

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"testing"
)

var update = flag.Bool("update", false, "regenerate spec/vectors/fingerprint.json")

const vectorsPath = "../../../spec/vectors/fingerprint.json"

type hashCase struct {
	Name        string `json:"name"`
	Tenant      string `json:"tenant"`
	Product     string `json:"product"`
	RawID       string `json:"raw_id"`
	Fingerprint string `json:"fingerprint,omitempty"` // empty = must be rejected
}

type hashVectors struct {
	Format      string     `json:"format"`
	Note        string     `json:"note"`
	Conventions []string   `json:"conventions"`
	Cases       []hashCase `json:"cases"`
}

func buildHashVectors(t *testing.T) hashVectors {
	t.Helper()
	c := func(name, tenant, product, raw string, valid bool) hashCase {
		hc := hashCase{Name: name, Tenant: tenant, Product: product, RawID: raw}
		if valid {
			hc.Fingerprint = mustHash(t, tenant, product, raw)
		}
		return hc
	}
	return hashVectors{
		Format: "lf-fp-v1",
		Note:   "Fingerprint derivation vectors (spec/license-format.md, Fingerprints). Every SDK must produce exactly these values and reject the cases without a fingerprint.",
		Conventions: []string{
			"fingerprint = \"sha256:\" + lowercase hex of SHA-256 over the UTF-8 bytes of \"lf-fp-v1\", tenant, product and raw_id joined by single 0x00 bytes; no trailing separator, no Unicode normalisation.",
			"Standard UTF-8 (not Java modified UTF-8). Cases without a fingerprint must be rejected (empty tenant/product, or NUL inside them).",
		},
		Cases: []hashCase{
			c("basic", "tnt_acme", "acme-db", "0123456789abcdef0123456789abcdef", true),
			c("other_tenant_same_machine", "tnt_other", "acme-db", "0123456789abcdef0123456789abcdef", true),
			c("kubernetes_uid", "tnt_acme", "acme-db", "5f0c2d8e-1b2a-4c3d-9e8f-0a1b2c3d4e5f", true),
			c("non_ascii_ids", "tnt_café", "数据库", "ÜNÏCÖDÉ-ID", true),
			c("nfd_is_not_normalised", "tnt_café", "数据库", "ÜNÏCÖDÉ-ID", true),
			c("nul_inside_raw_id_allowed", "tnt_acme", "acme-db", "a\x00b", true),
			c("reject_empty_tenant", "", "acme-db", "x", false),
			c("reject_empty_product", "tnt_acme", "", "x", false),
			c("reject_nul_in_tenant", "tnt\x00acme", "db", "x", false),
			c("reject_nul_in_product", "tnt", "acme\x00db", "x", false),
		},
	}
}

func TestHashVectors(t *testing.T) {
	want, err := json.MarshalIndent(buildHashVectors(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	if *update {
		if err := os.WriteFile(vectorsPath, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat("../../../go.mod"); errors.Is(err, os.ErrNotExist) {
		t.Skip("not inside the licenseforge repository")
	}
	got, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("spec/vectors/fingerprint.json is stale; run: go test ./fingerprint -update")
	}
	var vf hashVectors
	if err := json.Unmarshal(got, &vf); err != nil {
		t.Fatal(err)
	}
	for _, c := range vf.Cases {
		fp, err := Hash(c.Tenant, c.Product, c.RawID)
		if c.Fingerprint == "" {
			if err == nil {
				t.Errorf("%s: accepted, want rejection", c.Name)
			}
		} else if err != nil || fp != c.Fingerprint {
			t.Errorf("%s: got %q, %v; want %s", c.Name, fp, err, c.Fingerprint)
		}
	}
	// The spec's pinned value.
	if vf.Cases[0].Fingerprint != "sha256:81fe9b1a2812e068c320c4264f01b6d4d186a83cc0008fe954fd5d1b6e3f3684" {
		t.Fatalf("basic vector = %s", vf.Cases[0].Fingerprint)
	}
}
