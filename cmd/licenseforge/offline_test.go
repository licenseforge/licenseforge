package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfflineCommand(t *testing.T) {
	var got struct {
		path, auth string
		body       map[string]string
	}
	answer := func(w http.ResponseWriter, status int, body string) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.path, got.auth, got.body = r.URL.Path, r.Header.Get("Authorization"), nil
		_ = json.NewDecoder(r.Body).Decode(&got.body)
		switch {
		case strings.Contains(got.body["request"], "refused"):
			answer(w, 409, `{"code":"offline_not_allowed","detail":"The license's plan doesn't allow offline use.","request_id":"R1"}`)
		case strings.HasSuffix(r.URL.Path, "/activation-requests"):
			answer(w, 201, `{"license_file":"-----BEGIN LICENSEFORGE LICENSE-----\nlf1.x\n-----END LICENSEFORGE LICENSE-----\n","activation_id":"act_1"}`)
		default:
			answer(w, 200, `{"id":"act_1","deactivated_at":"2026-11-09T12:00:00Z"}`)
		}
	}))
	defer srv.Close()
	env := map[string]string{"LICENSEFORGE_URL": srv.URL + "/", "LICENSEFORGE_TENANT": "acme", "LICENSEFORGE_TOKEN": "lft_secret"}
	run := func(in string, args ...string) (string, error) {
		var out strings.Builder
		err := offline(context.Background(), args, func(k string) string { return env[k] }, strings.NewReader(in), &out, srv.Client())
		return out.String(), err
	}

	out, err := run("lfreq1.abc\n", "activate", "--request", "-")
	if err != nil || !strings.Contains(out, "lf1.x") || got.path != "/api/v1/tenants/acme/activation-requests" ||
		got.auth != "Bearer lft_secret" || got.body["request"] != "lfreq1.abc" {
		t.Errorf("activate: %q, %v, %+v", out, err, got)
	}
	receipt := filepath.Join(t.TempDir(), "r.txt")
	if err := os.WriteFile(receipt, []byte("lfrcpt1.def\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = run("", "return", "--receipt", receipt)
	if err != nil || out != "activation act_1 returned at 2026-11-09T12:00:00Z\n" || got.path != "/api/v1/tenants/acme/deactivation-receipts" || got.body["receipt"] != "lfrcpt1.def" {
		t.Errorf("return: %q, %v, %+v", out, err, got)
	}
	if _, err := run("refused", "activate", "--request", "-"); err == nil || !strings.Contains(err.Error(), "409 offline_not_allowed") || !strings.Contains(err.Error(), "R1") {
		t.Errorf("refusal: %v", err)
	}
	for name, args := range map[string][]string{"no op": nil, "bad op": {"renew"}, "no file": {"activate"}, "extra": {"return", "--receipt", receipt, "y"}} {
		if _, err := run("", args...); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	env["LICENSEFORGE_URL"] = "http://vendor.example"
	if _, err := run("x", "activate", "--request", "-"); err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("plain http to a remote host: %v", err)
	}
	env["LICENSEFORGE_URL"], env["LICENSEFORGE_TOKEN"] = srv.URL, ""
	if _, err := run("x", "activate", "--request", "-"); err == nil {
		t.Error("no token: no error")
	}
}
