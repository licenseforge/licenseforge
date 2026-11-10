package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `licenseforge api METHOD PATH` (ADR-0048): one request under /api/v1 with
// the token, {tenant} filled in, the body printed; exit 0 / 1 (the API said
// no) / 2 (usage) / 3 (transport).
func TestAPICommand(t *testing.T) {
	type seen struct{ method, uri, auth, ctype, idem, body string }
	var got []seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, seen{r.Method, r.URL.RequestURI(), r.Header.Get("Authorization"), r.Header.Get("Content-Type"), r.Header.Get("Idempotency-Key"), string(b)})
		switch {
		case strings.HasSuffix(r.URL.Path, "/missing"):
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"status":404,"code":"not_found","detail":"No such license.","request_id":"REQ1"}`)
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/moved"):
			http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
		default:
			_, _ = io.WriteString(w, `{"ok":true}`)
		}
	}))
	defer srv.Close()
	env := map[string]string{"LICENSEFORGE_URL": srv.URL, "LICENSEFORGE_TENANT": "acme", "LICENSEFORGE_TOKEN": "lf_tok"}
	getenv := func(k string) string { return env[k] }
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	dir := t.TempDir()
	file := filepath.Join(dir, "body.json")
	if err := os.WriteFile(file, []byte(`{"from":"file"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(stdin string, args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := apiMain(context.Background(), args, getenv, strings.NewReader(stdin), &out, &errOut, client)
		return code, out.String(), errOut.String()
	}

	for _, c := range []struct {
		args  []string
		stdin string
		want  seen
	}{
		{[]string{"GET", "/tenants/{tenant}/licenses?limit=5&cursor=abc"}, "", seen{"GET", "/api/v1/tenants/acme/licenses?limit=5&cursor=abc", "Bearer lf_tok", "", "", ""}},
		{[]string{"--data", `{"name":"Globex"}`, "--idempotency-key", "k1", "POST", "/tenants/{tenant}/customers"}, "", seen{"POST", "/api/v1/tenants/acme/customers", "Bearer lf_tok", "application/json", "k1", `{"name":"Globex"}`}},
		{[]string{"PATCH", "/tenants/{tenant}/products/prd_1", "--data", "@" + file}, "", seen{"PATCH", "/api/v1/tenants/acme/products/prd_1", "Bearer lf_tok", "application/merge-patch+json", "", `{"from":"file"}`}},
		{[]string{"post", "/tenants/{tenant}/licenses/lic_1/suspend", "--data", "-"}, `{"from":"stdin"}`, seen{"POST", "/api/v1/tenants/acme/licenses/lic_1/suspend", "Bearer lf_tok", "application/json", "", `{"from":"stdin"}`}},
		{[]string{"GET", "/me/tenants"}, "", seen{"GET", "/api/v1/me/tenants", "Bearer lf_tok", "", "", ""}},
	} {
		got = nil
		code, out, errOut := run(c.stdin, c.args...)
		if code != 0 || out != "{\"ok\":true}\n" || errOut != "" || len(got) != 1 || got[0] != c.want {
			t.Errorf("%v: %d %q %q %+v", c.args, code, out, errOut, got)
		}
	}
	// 204: nothing printed, success.
	if code, out, _ := run("", "DELETE", "/tenants/{tenant}/webhooks/wh_1"); code != 0 || out != "" {
		t.Errorf("delete: %d %q", code, out)
	}
	// The API said no: the problem on stdout, a summary on stderr, exit 1.
	code, out, errOut := run("", "GET", "/tenants/{tenant}/licenses/missing")
	if code != 1 || !strings.Contains(out, `"code":"not_found"`) || !strings.Contains(errOut, "404 not_found: No such license. (request REQ1)") {
		t.Errorf("problem: %d %q %q", code, out, errOut)
	}
	// A redirect isn't followed (the token stays with this host): exit 1.
	if code, _, errOut := run("", "GET", "/moved"); code != 1 || !strings.Contains(errOut, "302") {
		t.Errorf("redirect: %d %q", code, errOut)
	}
	// Usage errors, before any request: exit 2.
	got = nil
	for _, args := range [][]string{
		{},
		{"GET"},
		{"PUT", "/me/tenants"},
		{"GET", "me/tenants"},                         // not absolute
		{"GET", "https://evil.example/api/v1/x"},      // another host
		{"GET", "//evil.example/x"},                   // scheme-relative
		{"GET", "/tenants/{tenant}/../../admin"},      // out of /api/v1
		{"GET", "/tenants/%2e%2e/x"},                  // encoded dot segment
		{"GET", "/tenants/%2e%2e%2fadmin"},            // an encoded slash: one segment that is "../admin"
		{"GET", "/x#frag"},                            // fragment
		{"GET", "/tenants/{tenant}/{id}"},             // an unfilled placeholder
		{"GET", "/me/tenants", "--data", `{}`},        // a body on GET
		{"POST", "/x", "--data", `{not json`},         // not JSON
		{"POST", "/x", "--data", "@" + dir + "/nope"}, // no such file
		{"GET", "/me/tenants", "extra"},
	} {
		if code, _, errOut := run("", args...); code != 2 || errOut == "" {
			t.Errorf("%v: %d %q", args, code, errOut)
		}
	}
	if len(got) != 0 {
		t.Errorf("a usage error sent a request: %+v", got)
	}
	// The environment: https only (http for loopback), a token; the tenant
	// only when the path names it.
	for k, v := range map[string]string{"LICENSEFORGE_URL": "http://api.example", "LICENSEFORGE_TOKEN": ""} {
		old := env[k]
		env[k] = v
		if code, _, errOut := run("", "GET", "/me/tenants"); code != 2 || !strings.Contains(errOut, "LICENSEFORGE_") {
			t.Errorf("%s=%q: %d %q", k, v, code, errOut)
		}
		env[k] = old
	}
	env["LICENSEFORGE_TENANT"] = ""
	if code, _, _ := run("", "GET", "/me/tenants"); code != 0 {
		t.Errorf("no tenant, no {tenant}: %d", code)
	}
	if code, _, errOut := run("", "GET", "/tenants/{tenant}/licenses"); code != 2 || !strings.Contains(errOut, "LICENSEFORGE_TENANT") {
		t.Errorf("{tenant} without a tenant: %d %q", code, errOut)
	}
	// Transport errors: exit 3.
	env["LICENSEFORGE_URL"] = "http://127.0.0.1:1"
	if code, _, errOut := run("", "GET", "/me/tenants"); code != 3 || errOut == "" {
		t.Errorf("unreachable: %d %q", code, errOut)
	}
	// Help.
	if code, _, errOut := run("", "--help"); code != 0 || !strings.Contains(errOut, "usage: licenseforge api") {
		t.Errorf("help: %d %q", code, errOut)
	}
}
