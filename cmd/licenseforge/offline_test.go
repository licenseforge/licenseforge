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
		case strings.Contains(got.body["request"], "proxy"):
			w.Header().Set("X-Request-Id", "R2")
			answer(w, 502, "<html>bad gateway</html>")
		case strings.Contains(got.body["request"], "odd"):
			answer(w, 201, `{"activation_id":"act_1"}`)
		case strings.Contains(got.body["receipt"], "odd"):
			answer(w, 200, `{"id":"act_1"}`)
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
	if err != nil || out != "-----BEGIN LICENSEFORGE LICENSE-----\nlf1.x\n-----END LICENSEFORGE LICENSE-----\n" || got.path != "/api/v1/tenants/acme/activation-requests" ||
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
	if _, err := run("proxy", "activate", "--request", "-"); err == nil || !strings.Contains(err.Error(), "502 Bad Gateway") || !strings.Contains(err.Error(), "R2") {
		t.Errorf("not a problem body: %v", err)
	}
	if _, err := run("odd", "activate", "--request", "-"); err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Errorf("activate without a file: %v", err)
	}
	if _, err := run("odd", "return", "--receipt", "-"); err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Errorf("return without deactivated_at: %v", err)
	}
	if _, err := run(strings.Repeat("A", 4097), "activate", "--request", "-"); err == nil || !strings.Contains(err.Error(), "4096") {
		t.Errorf("oversize: %v", err)
	}
	good := env["LICENSEFORGE_URL"]
	for _, bad := range []string{"http://vendor.example", "http://localhost.:1", "", "https://u:p@vendor.example", "https://vendor.example/?q=1", "https://vendor.example/#f"} {
		env["LICENSEFORGE_URL"] = bad
		if _, err := run("x", "activate", "--request", "-"); err == nil || !strings.Contains(err.Error(), "LICENSEFORGE_URL") {
			t.Errorf("URL %q: %v", bad, err)
		}
	}
	env["LICENSEFORGE_URL"] = good
	env["LICENSEFORGE_TENANT"] = ""
	if _, err := run("x", "activate", "--request", "-"); err == nil {
		t.Error("no tenant: no error")
	}
	env["LICENSEFORGE_TENANT"] = "acme"
	// offlineMain: errors and usage on stderr, stdout only the file.
	var stdout, stderr strings.Builder
	if code := offlineMain(context.Background(), []string{"activate", "--request", "-"}, func(k string) string { return env[k] }, strings.NewReader("refused"), &stdout, &stderr, srv.Client()); code != 1 ||
		stdout.Len() != 0 || !strings.Contains(stderr.String(), "offline_not_allowed") {
		t.Errorf("failure: %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
	stderr.Reset()
	if code := offlineMain(context.Background(), []string{"--help"}, func(k string) string { return env[k] }, nil, &stdout, &stderr, srv.Client()); code != 0 || !strings.Contains(stderr.String(), "usage") || stdout.Len() != 0 {
		t.Errorf("help: %d %q", code, stderr.String())
	}
	env["LICENSEFORGE_URL"], env["LICENSEFORGE_TOKEN"] = srv.URL, ""
	if _, err := run("x", "activate", "--request", "-"); err == nil {
		t.Error("no token: no error")
	}
}
