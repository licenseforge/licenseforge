package licensefile

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

const offlineVectorsPath = "../../../spec/vectors/offline.json"

type offlineCase struct {
	Name   string         `json:"name"`
	Kind   string         `json:"kind"`   // request or receipt
	Input  string         `json:"input"`  // the token as carried
	Result string         `json:"result"` // ok, malformed or unsupported_version
	Want   map[string]any `json:"want,omitempty"`
}

type offlineVectors struct {
	Format      string        `json:"format"`
	Note        string        `json:"note"`
	Conventions []string      `json:"conventions"`
	Cases       []offlineCase `json:"cases"`
}

const (
	vFP    = "sha256:81fe9b1a2812e068c320c4264f01b6d4d186a83cc0008fe954fd5d1b6e3f3684"
	vNonce = "AAECAwQFBgcICQoLDA0ODw" // bytes 0..15
	vHash  = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	vReq   = `{"v":1,"tenant":"tnt_acme","product":"acme-db","key":"LF-ABCDE-FGHIJ-KLMNO-PQRST-UVWXYZ","bind":{"type":"machine","fp":"` + vFP + `"},"fp_source":"machine-id","nonce":"` + vNonce + `","created":"2026-11-08T10:00:00Z"}`
	vRcpt  = `{"v":1,"tenant":"tnt_acme","license_id":"lic_aaaaaaaaaaaaaaaaaaaaaaaaaa","fp":"` + vFP + `","file_sha256":"` + vHash + `","nonce":"` + vNonce + `","created":"2026-11-08T10:00:00Z"}`
)

// with replaces old in payload (exactly once) and encodes it as a token.
func with(t *testing.T, version, payload, old, repl string) string {
	t.Helper()
	if old != "" {
		if strings.Count(payload, old) != 1 {
			t.Fatalf("vector edit %q doesn't match exactly once", old)
		}
		payload = strings.Replace(payload, old, repl, 1)
	}
	return version + "." + b64.EncodeToString([]byte(payload))
}

func buildOfflineVectors(t *testing.T) offlineVectors {
	t.Helper()
	req := func(name, old, repl, result string) offlineCase {
		return offlineCase{Name: name, Kind: "request", Input: with(t, RequestVersion, vReq, old, repl), Result: result}
	}
	rcpt := func(name, old, repl, result string) offlineCase {
		return offlineCase{Name: name, Kind: "receipt", Input: with(t, ReceiptVersion, vRcpt, old, repl), Result: result}
	}
	okReq := req("request", "", "", "ok")
	okReq.Want = map[string]any{"tenant": "tnt_acme", "product": "acme-db", "key": "LF-ABCDE-FGHIJ-KLMNO-PQRST-UVWXYZ",
		"bind_type": "machine", "fp": vFP, "fp_source": "machine-id", "nonce": vNonce, "created": "2026-11-08T10:00:00Z"}
	optional := req("request_optional_fields", `"created"`, `"hostname":"build-01","app_version":"4.2.0","sdk_version":"go/0.1.0","created"`, "ok")
	optional.Want = map[string]any{"hostname": "build-01", "app_version": "4.2.0", "sdk_version": "go/0.1.0"}
	okRcpt := rcpt("receipt", "", "", "ok")
	okRcpt.Want = map[string]any{"tenant": "tnt_acme", "license_id": "lic_aaaaaaaaaaaaaaaaaaaaaaaaaa", "fp": vFP,
		"file_sha256": vHash, "nonce": vNonce, "created": "2026-11-08T10:00:00Z"}
	wrapped := okReq
	wrapped.Name, wrapped.Input = "request_wrapped_with_bom", "\uFEFF\r\n"+okReq.Input[:20]+"\n "+okReq.Input[20:]+"\r\n"
	return offlineVectors{
		Format: "lfreq1 / lfrcpt1",
		Note:   "Offline activation request and deactivation receipt vectors (spec/license-format.md, Offline activation). Every SDK and the server must accept the ok cases with exactly these fields and reject the others with the given class.",
		Conventions: []string{
			"input is the token as carried: \"lfreq1.\" or \"lfrcpt1.\" + base64url (no padding, canonical) of the JSON payload; SP, HT, CR, LF anywhere and one leading UTF-8 BOM are ignored; at most 4096 bytes.",
			"want lists the decoded fields to compare (bind_type and fp for the request's bind; nonce as base64url; created as YYYY-MM-DDTHH:MM:SSZ).",
		},
		Cases: []offlineCase{
			okReq, optional, wrapped, okRcpt,
			req("cluster_binding", `"type":"machine","fp":"`+vFP+`"},"fp_source":"machine-id"`, `"type":"cluster","fp":"`+vFP+`"},"fp_source":"kubernetes"`, "ok"),
			req("cluster_from_machine_id", `"type":"machine"`, `"type":"cluster"`, "malformed"),
			req("machine_from_kubernetes", `"fp_source":"machine-id"`, `"fp_source":"kubernetes"`, "malformed"),
			req("fp_source_unknown", `"fp_source":"machine-id"`, `"fp_source":"bios"`, "malformed"),
			req("fp_source_missing", `"fp_source":"machine-id",`, ``, "malformed"),
			req("unsupported_version", `"v":1`, `"v":2`, "unsupported_version"),
			req("v_missing", `"v":1,`, ``, "malformed"),
			req("v_not_integer", `"v":1`, `"v":1.0`, "malformed"),
			req("unknown_field", `"created"`, `"extra":1,"created"`, "malformed"),
			req("duplicate_key", `"product":"acme-db"`, `"product":"acme-db","product":"other"`, "malformed"),
			req("null_field", `"key":"LF-ABCDE-FGHIJ-KLMNO-PQRST-UVWXYZ"`, `"key":null`, "malformed"),
			req("empty_tenant", `"tenant":"tnt_acme"`, `"tenant":""`, "malformed"),
			req("nul_in_product", `"product":"acme-db"`, `"product":"acme\u0000db"`, "malformed"),
			req("key_with_space", `LF-ABCDE-FGHIJ-KLMNO-PQRST-UVWXYZ`, `LF ABCDE`, "malformed"),
			req("bind_none", `"type":"machine"`, `"type":"none"`, "malformed"),
			req("bind_none_without_fp", `"bind":{"type":"machine","fp":"`+vFP+`"}`, `"bind":{"type":"none"}`, "malformed"),
			req("bind_missing", `"bind":{"type":"machine","fp":"`+vFP+`"},`, ``, "malformed"),
			req("bind_unknown_field", `"type":"machine"`, `"type":"machine","x":"y"`, "malformed"),
			req("fp_uppercase", vFP, strings.ToUpper(vFP[7:]), "malformed"),
			req("fp_wrong_prefix", vFP, "md5:"+vFP[7:], "malformed"),
			req("nonce_short", vNonce, "AAECAwQFBgcICQoLDA0O", "malformed"),
			req("nonce_padded", vNonce, vNonce+"==", "malformed"),
			req("created_offset", "2026-11-08T10:00:00Z", "2026-11-08T10:00:00+00:00", "malformed"),
			req("created_not_a_date", "2026-11-08T10:00:00Z", "2026-02-30T10:00:00Z", "malformed"),
			req("hostname_empty", `"created"`, `"hostname":"","created"`, "malformed"),
			req("hostname_control_char", `"created"`, `"hostname":"a\nb","created"`, "malformed"),
			req("trailing_data", vReq, vReq+"{}", "malformed"),
			{Name: "wrong_prefix", Kind: "request", Input: with(t, ReceiptVersion, vReq, "", ""), Result: "malformed"},
			{Name: "padded_base64", Kind: "request", Input: with(t, RequestVersion, vReq, "", "") + "=", Result: "malformed"},
			{Name: "oversize", Kind: "request", Input: with(t, RequestVersion, vReq, "", "") + strings.Repeat(" ", MaxOfflineSize), Result: "malformed"},
			rcpt("receipt_unknown_field", `"created"`, `"lease":"x","created"`, "malformed"),
			rcpt("receipt_hash_uppercase", vHash, strings.ToUpper(vHash), "malformed"),
			rcpt("receipt_hash_short", vHash, vHash[:62], "malformed"),
			rcpt("receipt_empty_license", `"license_id":"lic_aaaaaaaaaaaaaaaaaaaaaaaaaa"`, `"license_id":""`, "malformed"),
			rcpt("receipt_unsupported_version", `"v":1`, `"v":3`, "unsupported_version"),
		},
	}
}

func TestOfflineVectors(t *testing.T) {
	want, err := json.MarshalIndent(buildOfflineVectors(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	if *update {
		if err := os.WriteFile(offlineVectorsPath, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat("../../../go.mod"); errors.Is(err, os.ErrNotExist) {
		t.Skip("not inside the licenseforge repository")
	}
	got, err := os.ReadFile(offlineVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("spec/vectors/offline.json is stale; run: go test ./licensefile -update")
	}
	var vf offlineVectors
	if err := json.Unmarshal(got, &vf); err != nil {
		t.Fatal(err)
	}
	for _, c := range vf.Cases {
		var fields map[string]any
		var err error
		if c.Kind == "request" {
			var r *Request
			if r, err = ParseRequest(c.Input); err == nil {
				fields = map[string]any{"tenant": r.Tenant, "product": r.Product, "key": r.Key, "bind_type": string(r.Binding.Type),
					"fp": r.Binding.Fingerprint, "fp_source": r.FPSource, "nonce": b64.EncodeToString(r.Nonce), "created": r.Created.Format(timeLayout),
					"hostname": r.Hostname, "app_version": r.AppVersion, "sdk_version": r.SDKVersion}
			}
		} else {
			var r *Receipt
			if r, err = ParseReceipt(c.Input); err == nil {
				fields = map[string]any{"tenant": r.Tenant, "license_id": r.LicenseID, "fp": r.Fingerprint, "file_sha256": r.FileSHA256,
					"nonce": b64.EncodeToString(r.Nonce), "created": r.Created.Format(timeLayout)}
			}
		}
		switch c.Result {
		case "ok":
			if err != nil {
				t.Errorf("%s: %v, want ok", c.Name, err)
			}
			for k, v := range c.Want {
				if fields[k] != v {
					t.Errorf("%s: %s = %v, want %v", c.Name, k, fields[k], v)
				}
			}
		case "malformed":
			if !errors.Is(err, ErrMalformed) {
				t.Errorf("%s: %v, want malformed", c.Name, err)
			}
		case "unsupported_version":
			if !errors.Is(err, ErrUnsupportedVersion) {
				t.Errorf("%s: %v, want unsupported_version", c.Name, err)
			}
		default:
			t.Fatalf("%s: unknown result %q", c.Name, c.Result)
		}
	}
}

// What an SDK encodes, the parser reads back; what the parser refuses, the
// encoder refuses too.
func TestOfflineRoundTrip(t *testing.T) {
	created := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	nonce := bytes.Repeat([]byte{7}, 16)
	r := Request{Tenant: "tnt_a", Product: "p", Key: "LF-KEY", Binding: Binding{Type: BindCluster, Fingerprint: vFP}, FPSource: "kubernetes",
		Nonce: nonce, Created: created, Hostname: "h", AppVersion: "1", SDKVersion: "go/1"}
	s, err := EncodeRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ParseRequest(s); err != nil || got.Tenant != r.Tenant || got.Binding != r.Binding || !bytes.Equal(got.Nonce, nonce) ||
		!got.Created.Equal(created) || got.Hostname != "h" || got.SDKVersion != "go/1" {
		t.Errorf("request round trip: %+v, %v", got, err)
	}
	// The hash is the token's, whatever armor and line endings carry it.
	token := "lf1.k1.cGF5bG9hZA.c2ln"
	h, err := FileSHA256(token)
	if err != nil {
		t.Fatal(err)
	}
	for _, carried := range []string{
		"-----BEGIN LICENSEFORGE LICENSE-----\n" + token + "\n-----END LICENSEFORGE LICENSE-----\n",
		"\uFEFF-----BEGIN LICENSEFORGE LICENSE-----\r\n" + token[:9] + "\r\n" + token[9:] + "\r\n-----END LICENSEFORGE LICENSE-----\r\n\r\n",
	} {
		if got, err := FileSHA256(carried); err != nil || got != h {
			t.Errorf("FileSHA256(%q) = %s, %v; want the token's %s", carried, got, err, h)
		}
	}
	if _, err := FileSHA256("not a license"); !errors.Is(err, ErrMalformed) {
		t.Errorf("FileSHA256 of a non-license: %v", err)
	}
	rc := Receipt{Tenant: "tnt_a", LicenseID: "lic_x", Fingerprint: vFP, FileSHA256: h, Nonce: nonce, Created: created}
	s, err = EncodeReceipt(rc)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ParseReceipt(s); err != nil || got.LicenseID != rc.LicenseID || got.FileSHA256 != h || got.Fingerprint != vFP || !bytes.Equal(got.Nonce, nonce) {
		t.Errorf("receipt round trip: %+v, %v", got, err)
	}
	for name, bad := range map[string]Request{
		"no binding":  {Tenant: "t", Product: "p", Key: "k", Nonce: nonce, Created: created},
		"short nonce": {Tenant: "t", Product: "p", Key: "k", Binding: r.Binding, FPSource: "kubernetes", Nonce: nonce[:8], Created: created},
		"no tenant":   {Product: "p", Key: "k", Binding: r.Binding, FPSource: "kubernetes", Nonce: nonce, Created: created},
		"no source":   {Tenant: "t", Product: "p", Key: "k", Binding: r.Binding, Nonce: nonce, Created: created},
	} {
		if _, err := EncodeRequest(bad); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: encoded (%v)", name, err)
		}
	}
}
