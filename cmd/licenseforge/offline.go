package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// offline runs `licenseforge offline activate|return` (ADR-0043): it carries
// an air-gapped machine's request or receipt to the API with an API token,
// for vendors scripting it. The server needs no database access from here:
//
//	LICENSEFORGE_URL     the API's base URL, https://api.vendor.example (http only for loopback)
//	LICENSEFORGE_TENANT  the tenant's slug
//	LICENSEFORGE_TOKEN   an API token with activation:offline on the product
//
// activate writes the license file to out; return writes the returned
// activation's ID and time. Refusals print the API's problem and fail.
func offline(ctx context.Context, args []string, getenv func(string) string, in io.Reader, out io.Writer, client *http.Client) error {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "-help" || args[0] == "--help") {
		return flag.ErrHelp
	}
	if len(args) == 0 || (args[0] != "activate" && args[0] != "return") {
		return errors.New(offlineUsage)
	}
	op := args[0]
	fs := flag.NewFlagSet("offline "+op, flag.ContinueOnError)
	fs.SetOutput(io.Discard) // offlineMain prints the usage
	name, field, path := "request", "request", "activation-requests"
	if op == "return" {
		name, field, path = "receipt", "receipt", "deactivation-receipts"
	}
	file := fs.String(name, "", "the "+name+" file the machine wrote; - for stdin (required)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *file == "" || fs.NArg() > 0 {
		return fmt.Errorf("offline %s: --%s is required, and nothing else", op, name)
	}
	base, tenant, token := strings.TrimRight(getenv("LICENSEFORGE_URL"), "/"), getenv("LICENSEFORGE_TENANT"), getenv("LICENSEFORGE_TOKEN")
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || !secure(u) || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("offline: LICENSEFORGE_URL must be an https URL (http only for loopback hosts) without credentials, query or fragment: the token travels with the request")
	}
	if tenant == "" || token == "" {
		return errors.New("offline: LICENSEFORGE_TENANT and LICENSEFORGE_TOKEN are required")
	}
	if strings.ContainsAny(tenant, "/%?#\\") || tenant == "." || tenant == ".." { // one path segment: a slug or tnt_ ID
		return fmt.Errorf("offline: LICENSEFORGE_TENANT %q is not a tenant slug or ID", tenant)
	}
	text, err := readArg(*file, in)
	if err != nil {
		return fmt.Errorf("offline %s: %w", op, err)
	}
	if text = strings.TrimSpace(text); len(text) > 4096 {
		return fmt.Errorf("offline %s: the %s is over 4096 bytes: not a %s file?", op, name, name)
	}
	body, err := json.Marshal(map[string]string{field: text})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.JoinPath("api/v1/tenants", tenant, path).String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("offline %s: %w", op, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("offline %s: %w", op, err)
	}
	if resp.StatusCode/100 != 2 {
		var p struct {
			Code      string `json:"code"`
			Detail    string `json:"detail"`
			RequestID string `json:"request_id"`
		}
		_ = json.Unmarshal(raw, &p)
		if p.Code == "" { // not the API's problem: a proxy, a redirect
			p.Code, p.Detail = http.StatusText(resp.StatusCode), resp.Header.Get("Location")
		}
		if p.RequestID == "" {
			p.RequestID = resp.Header.Get("X-Request-Id")
		}
		return fmt.Errorf("offline %s: %d %s: %s (request %s)", op, resp.StatusCode, p.Code, p.Detail, p.RequestID)
	}
	if op == "activate" {
		var v struct {
			LicenseFile string `json:"license_file"`
		}
		if err := json.Unmarshal(raw, &v); err != nil || v.LicenseFile == "" {
			return fmt.Errorf("offline activate: unexpected answer: %s", raw)
		}
		_, err = io.WriteString(out, v.LicenseFile)
		return err
	}
	var a struct {
		ID            string     `json:"id"`
		DeactivatedAt *time.Time `json:"deactivated_at"`
	}
	if err := json.Unmarshal(raw, &a); err != nil || a.DeactivatedAt == nil {
		return fmt.Errorf("offline return: unexpected answer: %s", raw)
	}
	_, err = fmt.Fprintf(out, "activation %s returned at %s\n", a.ID, a.DeactivatedAt.UTC().Format(time.RFC3339))
	return err
}

const offlineUsage = "usage: licenseforge offline activate --request FILE  |  licenseforge offline return --receipt FILE  (FILE - reads stdin)"

// offlineMain runs offline and returns the exit code: errors (and the usage)
// go to errOut, so stdout carries only the license file.
func offlineMain(ctx context.Context, args []string, getenv func(string) string, in io.Reader, out, errOut io.Writer, client *http.Client) int {
	err := offline(ctx, args, getenv, in, out, client)
	switch {
	case errors.Is(err, flag.ErrHelp):
		_, _ = fmt.Fprintln(errOut, offlineUsage)
		return 0
	case err != nil:
		_, _ = fmt.Fprintln(errOut, "licenseforge:", err)
		return 1
	}
	return 0
}

// readArg reads path, or in for "-"; requests and receipts are small.
func readArg(path string, in io.Reader) (string, error) {
	r := in
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return "", err
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, 64<<10)) // more than any request: refused after trimming
	return string(b), err
}

// secure: https, or http to a loopback host (tests, a local proxy).
func secure(u *url.URL) bool {
	return u.Scheme == "https" || (u.Scheme == "http" && loopback(u.Hostname()))
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
