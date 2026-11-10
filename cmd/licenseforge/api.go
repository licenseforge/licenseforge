package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const apiUsage = `usage: licenseforge api [--data JSON|@FILE|-] [--idempotency-key KEY] METHOD PATH
  One request to $LICENSEFORGE_URL/api/v1 + PATH with $LICENSEFORGE_TOKEN (ADR-0048);
  {tenant} in PATH is $LICENSEFORGE_TENANT. METHOD: GET, POST, PATCH, DELETE.
  Prints the JSON answer. Exit 0 ok, 1 the API refused (problem on stdout,
  summary on stderr), 2 usage, 3 the API couldn't be reached.
  e.g. licenseforge api GET '/tenants/{tenant}/licenses?limit=50'`

// maxAnswer bounds a response body (lists are paged at 200 items).
const maxAnswer = 16 << 20

// cliClient is the HTTP client of the API commands (api, offline): it
// follows no redirect, so the token never reaches another host or path.
func cliClient() *http.Client {
	return &http.Client{Timeout: time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// usageError is a mistake in the command line or environment: exit 2.
type usageError struct{ error }

// apiMain runs `licenseforge api` (ADR-0048) and returns its exit code.
func apiMain(ctx context.Context, args []string, getenv func(string) string, in io.Reader, out, errOut io.Writer, client *http.Client) int {
	code, err := apiRequest(ctx, args, getenv, in, out, client)
	switch {
	case errors.Is(err, flag.ErrHelp):
		_, _ = fmt.Fprintln(errOut, apiUsage)
		return 0
	case err != nil:
		_, _ = fmt.Fprintln(errOut, "licenseforge api:", err)
		var u usageError
		if errors.As(err, &u) {
			_, _ = fmt.Fprintln(errOut, apiUsage)
		}
	}
	return code
}

func apiRequest(ctx context.Context, args []string, getenv func(string) string, in io.Reader, out io.Writer, client *http.Client) (int, error) {
	fs := flag.NewFlagSet("api", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	data := fs.String("data", "", "the JSON body, @FILE, or - for stdin")
	idem := fs.String("idempotency-key", "", "an Idempotency-Key header, for retrying a POST safely")
	// Flags before or after METHOD PATH.
	var pos []string
	for rest := args; ; {
		if err := fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0, err
			}
			return 2, usageError{err}
		}
		if fs.NArg() == 0 {
			break
		}
		pos, rest = append(pos, fs.Arg(0)), fs.Args()[1:]
	}
	if len(pos) != 2 {
		return 2, usageError{errors.New("METHOD and PATH are required, and nothing else")}
	}
	method, path := strings.ToUpper(pos[0]), pos[1]
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodDelete:
	default:
		return 2, usageError{fmt.Errorf("method %q: GET, POST, PATCH or DELETE", pos[0])}
	}
	u, tenant, token, err := apiTarget(getenv, "api", false)
	if err != nil {
		return 2, usageError{err}
	}
	target, err := apiURL(u, path, tenant)
	if err != nil {
		return 2, usageError{err}
	}
	var body []byte
	if *data != "" {
		if method == http.MethodGet || method == http.MethodDelete {
			return 2, usageError{fmt.Errorf("%s takes no --data", method)}
		}
		if body, err = readData(*data, in); err != nil {
			return 2, usageError{err}
		}
		if !json.Valid(body) {
			return 2, usageError{errors.New("--data is not JSON")}
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return 2, usageError{err}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		if method == http.MethodPatch {
			req.Header.Set("Content-Type", "application/merge-patch+json") // the API's patches (ADR-0032)
		}
	}
	if *idem != "" {
		if strings.ContainsFunc(*idem, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return 2, usageError{errors.New("--idempotency-key has control characters")}
		}
		req.Header.Set("Idempotency-Key", *idem)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 3, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return 3, err
	}
	if len(raw) > maxAnswer { // never print a cut answer as if it were whole
		return 3, fmt.Errorf("the answer is over %d bytes", maxAnswer)
	}
	if len(raw) > 0 {
		if _, err := out.Write(append(bytes.TrimRight(raw, "\n"), '\n')); err != nil {
			return 3, err
		}
	}
	if resp.StatusCode/100 == 2 {
		return 0, nil
	}
	var p struct {
		Code      string `json:"code"`
		Detail    string `json:"detail"`
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(raw, &p)
	if p.Code == "" { // not the API's problem: a proxy, a redirect (not followed)
		p.Code, p.Detail = http.StatusText(resp.StatusCode), resp.Header.Get("Location")
	}
	if p.RequestID == "" {
		p.RequestID = resp.Header.Get("X-Request-Id")
	}
	return 1, fmt.Errorf("%d %s: %s (request %s)", resp.StatusCode, p.Code, p.Detail, p.RequestID)
}

// apiURL joins path (an absolute API path, query allowed) onto base's
// /api/v1, filling {tenant}. Anything that could leave /api/v1 or the host
// is refused: the token goes with the request.
func apiURL(base *url.URL, path, tenant string) (string, error) {
	p, query, _ := strings.Cut(path, "?")
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(path, "#\\") || strings.ContainsFunc(path, func(r rune) bool { return r < 0x21 || r == 0x7f }) {
		return "", fmt.Errorf("PATH %q: an API path like /tenants/{tenant}/licenses, without host or fragment", path)
	}
	if strings.Contains(p, "{tenant}") {
		if tenant == "" {
			return "", errors.New("PATH has {tenant}: set LICENSEFORGE_TENANT")
		}
		p = strings.ReplaceAll(p, "{tenant}", tenant)
	}
	if strings.ContainsAny(p, "{}") {
		return "", fmt.Errorf("PATH %q: fill in the {placeholders}", path)
	}
	for _, seg := range strings.Split(p, "/") {
		s, err := url.PathUnescape(seg)
		if err != nil {
			return "", fmt.Errorf("PATH %q: a bad %%-escape", path)
		}
		if s == "." || s == ".." || strings.Contains(s, "/") {
			return "", fmt.Errorf("PATH %q: no . or .. segments", path)
		}
	}
	if _, err := url.ParseQuery(query); err != nil {
		return "", fmt.Errorf("PATH %q: %w", path, err)
	}
	target := base.JoinPath("api/v1").String() + p
	if query != "" {
		target += "?" + query
	}
	return target, nil
}

// readData reads --data: literal JSON, @FILE, or - for stdin.
func readData(v string, in io.Reader) ([]byte, error) {
	var r io.Reader
	switch {
	case v == "-":
		r = in
	case strings.HasPrefix(v, "@"):
		f, err := os.Open(v[1:])
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		r = f
	default:
		return []byte(v), nil
	}
	return io.ReadAll(io.LimitReader(r, 16<<20))
}
