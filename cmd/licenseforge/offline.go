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
	if len(args) == 0 || (args[0] != "activate" && args[0] != "return") {
		return errors.New("usage: licenseforge offline activate --request FILE  |  licenseforge offline return --receipt FILE  (FILE - reads stdin)")
	}
	op := args[0]
	fs := flag.NewFlagSet("offline "+op, flag.ContinueOnError)
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
	if err != nil || u.Host == "" || !secure(u) {
		return errors.New("offline: LICENSEFORGE_URL must be an https URL (http only for loopback hosts): the token travels with the request")
	}
	if tenant == "" || token == "" {
		return errors.New("offline: LICENSEFORGE_TENANT and LICENSEFORGE_TOKEN are required")
	}
	text, err := readArg(*file, in)
	if err != nil {
		return fmt.Errorf("offline %s: %w", op, err)
	}
	body, err := json.Marshal(map[string]string{field: strings.TrimSpace(text)})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v1/tenants/"+url.PathEscape(tenant)+"/"+path, bytes.NewReader(body))
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
		var p struct{ Code, Detail, RequestID string }
		_ = json.Unmarshal(raw, &p)
		var pid struct {
			RequestID string `json:"request_id"`
		}
		_ = json.Unmarshal(raw, &pid)
		return fmt.Errorf("offline %s: %d %s: %s (request %s)", op, resp.StatusCode, p.Code, p.Detail, pid.RequestID)
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
	b, err := io.ReadAll(io.LimitReader(r, 64<<10))
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
