package auditexport

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// otlpCollector is an OTLP/HTTP JSON receiver over TLS that answers with
// respond (status, body) and keeps the requests.
type otlpCollector struct {
	srv     *httptest.Server
	mu      sync.Mutex
	bodies  []map[string]any
	headers []http.Header
	status  int
	reply   string
	ctype   string // response Content-Type; "" with a reply: application/json, "-": none
}

func startOTLP(t *testing.T, p pki, mtls bool) *otlpCollector {
	t.Helper()
	c := &otlpCollector{status: http.StatusOK}
	c.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		c.mu.Lock()
		c.bodies, c.headers = append(c.bodies, m), append(c.headers, r.Header.Clone())
		status, reply, ctype := c.status, c.reply, c.ctype
		c.mu.Unlock()
		if status == http.StatusFound {
			w.Header().Set("Location", "/elsewhere")
		}
		switch {
		case ctype == "-":
			w.Header()["Content-Type"] = nil // no Content-Type at all (and no sniffing)
		case ctype != "":
			w.Header().Set("Content-Type", ctype)
		case reply != "":
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	c.srv.TLS = &tls.Config{Certificates: []tls.Certificate{p.server}}
	if mtls {
		c.srv.TLS.ClientAuth, c.srv.TLS.ClientCAs = tls.RequireAndVerifyClientCert, p.ca
	}
	c.srv.StartTLS()
	t.Cleanup(c.srv.Close)
	return c
}

func (c *otlpCollector) set(status int, reply string, ctype ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status, c.reply, c.ctype = status, reply, ""
	if len(ctype) > 0 {
		c.ctype = ctype[0]
	}
}

func (c *otlpCollector) records(t *testing.T) []any {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []any
	for _, b := range c.bodies {
		rl := b["resourceLogs"].([]any)[0].(map[string]any)
		sl := rl["scopeLogs"].([]any)[0].(map[string]any)
		out = append(out, sl["logRecords"].([]any)...)
	}
	return out
}

func attr(rec any, key string) any {
	for _, a := range rec.(map[string]any)["attributes"].([]any) {
		if a.(map[string]any)["key"] == key {
			return a.(map[string]any)["value"]
		}
	}
	return nil
}

func TestOTLPDelivers(t *testing.T) {
	p := newPKI(t)
	c := startOTLP(t, p, true)
	o, err := NewOTLP(OTLPConfig{Endpoint: c.srv.URL + "/v1/logs", CAFile: p.caFile, CertFile: p.clientCert, KeyFile: p.clientKey,
		Headers: "authorization=Bearer%20abc, x-tenant = lf", Hostname: "lf-1"})
	if err != nil {
		t.Fatal(err)
	}
	denied := entry(2, `{}`)
	denied.Outcome = "denied"
	if err := o.Send(context.Background(), []Entry{entry(1, `{"name":"ci"}`), denied}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	recs := c.records(t)
	if len(recs) != 2 {
		t.Fatalf("%d records", len(recs))
	}
	r := recs[0].(map[string]any)
	if r["timeUnixNano"] != "1793840523456789000" || r["severityNumber"] != float64(9) || r["severityText"] != "INFO" ||
		r["eventName"] != "lf.audit.api_token.create" || r["body"].(map[string]any)["stringValue"] != "api_token.create success" {
		t.Errorf("record %v", r)
	}
	for k, want := range map[string]any{
		"lf.audit.id": map[string]any{"stringValue": "aud_1"}, "lf.audit.seq": map[string]any{"intValue": "1"},
		"lf.audit.details": map[string]any{"stringValue": `{"name":"ci"}`}, "lf.audit.hash": map[string]any{"stringValue": "ff"},
		"lf.audit.prev_hash": map[string]any{"stringValue": "00"}, "lf.audit.user_agent": map[string]any{"stringValue": `evil"] [x@1 a="b"\`},
		"lf.audit.source_ip": map[string]any{"stringValue": "10.0.0.1"}, "lf.audit.tenant_id": map[string]any{"stringValue": "tnt_x"},
	} {
		if got, _ := json.Marshal(attr(r, k)); string(got) != mustJSON(want) {
			t.Errorf("%s = %s, want %s", k, got, mustJSON(want))
		}
	}
	if s := recs[1].(map[string]any); s["severityNumber"] != float64(13) || s["severityText"] != "WARN" {
		t.Errorf("denied record %v", s)
	}
	h := c.headers[0]
	if h.Get("Authorization") != "Bearer abc" || h.Get("X-Tenant") != "lf" || h.Get("Content-Type") != "application/json" {
		t.Errorf("headers %v", h)
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// Delivered only on a 2xx that rejects no record.
func TestOTLPDeliveryRule(t *testing.T) {
	p := newPKI(t)
	c := startOTLP(t, p, false)
	o, err := NewOTLP(OTLPConfig{Endpoint: c.srv.URL + "/v1/logs", CAFile: p.caFile})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		status int
		reply  string
		ok     bool
		ctype  string
	}{
		{200, "", true, ""},
		{200, `<html>ok</html>`, false, "text/html"},
		{200, `{}`, false, "text/plain"}, // JSON-looking, but not declared OTLP JSON
		{200, `{"partialSuccess":{"rejectedLogRecords":"1"}}`, false, "Application/JSON; charset=utf-8"},
		{200, `{"partialSuccess":{"rejectedLogRecords":"1"}}`, false, "-"},
		{200, `{}`, true, "Application/JSON"},
		{200, `{}`, true, ""},
		{200, `{"partialSuccess":{}}`, true, ""},
		{200, `{"partialSuccess":{"rejectedLogRecords":"0"}}`, true, ""},
		{202, `{"partialSuccess":{"rejectedLogRecords":0}}`, true, ""},
		{200, `{"partialSuccess":{"rejectedLogRecords":"1","errorMessage":"too big"}}`, false, ""},
		{200, `{"partialSuccess":{"rejectedLogRecords":2}}`, false, ""},
		{200, `not json`, false, ""},
		{302, "", false, ""},
		{400, "", false, ""},
		{429, "", false, ""},
		{503, "", false, ""},
	} {
		c.set(tc.status, tc.reply, tc.ctype)
		if err := o.Send(context.Background(), []Entry{entry(1, `{}`)}); (err == nil) != tc.ok {
			t.Errorf("%d %s: Send = %v, want delivered=%v", tc.status, tc.reply, err, tc.ok)
		}
	}
}

func TestOTLPRefuses(t *testing.T) {
	p := newPKI(t)
	strict, open := startOTLP(t, p, true), startOTLP(t, p, false)
	for name, cfg := range map[string]OTLPConfig{
		"untrusted collector": {Endpoint: open.srv.URL + "/v1/logs"},
		"mTLS without a cert": {Endpoint: strict.srv.URL + "/v1/logs", CAFile: p.caFile},
	} {
		o, err := NewOTLP(cfg)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := o.Send(context.Background(), []Entry{entry(1, `{}`)}); err == nil {
			t.Errorf("%s: delivered", name)
		}
	}
	for name, cfg := range map[string]OTLPConfig{
		"http to a remote host":    {Endpoint: "http://otel.example:4318/v1/logs"},
		"no host":                  {Endpoint: "https:///v1/logs"},
		"userinfo":                 {Endpoint: "https://u:p@otel.example/v1/logs"},
		"cert, no key":             {Endpoint: "https://otel.example/v1/logs", CertFile: p.clientCert},
		"bad header":               {Endpoint: "https://otel.example/v1/logs", Headers: "novalue"},
		"header with CRLF":         {Endpoint: "https://otel.example/v1/logs", Headers: "a=b%0d%0aEvil: 1"},
		"header value with NUL":    {Endpoint: "https://otel.example/v1/logs", Headers: "a=b%00c"},
		"header name not a token":  {Endpoint: "https://otel.example/v1/logs", Headers: "x key=v"},
		"header name with colon":   {Endpoint: "https://otel.example/v1/logs", Headers: "x:k=v"},
		"query in the endpoint":    {Endpoint: "https://otel.example/v1/logs?api_key=secret"},
		"fragment in the endpoint": {Endpoint: "https://otel.example/v1/logs#secret"},
		"missing CA file":          {Endpoint: "https://otel.example/v1/logs", CAFile: p.dir + "/nope"},
	} {
		if _, err := NewOTLP(cfg); err == nil {
			t.Errorf("NewOTLP accepted %s", name)
		}
	}
	if _, err := NewOTLP(OTLPConfig{Endpoint: "http://127.0.0.1:4318/v1/logs"}); err != nil {
		t.Errorf("http on loopback refused: %v", err)
	}
}

// End to end: the exporter advances on delivery and not on a rejection.
func TestOTLPExport(t *testing.T) {
	p := newPKI(t)
	d := openDB(t)
	tn, _ := chain(t, d, 3)
	c := startOTLP(t, p, false)
	o, err := NewOTLP(OTLPConfig{Endpoint: c.srv.URL + "/v1/logs", CAFile: p.caFile})
	if err != nil {
		t.Fatal(err)
	}
	c.set(200, `{"partialSuccess":{"rejectedLogRecords":"1"}}`)
	name := sinkName()
	x := exporter(t, d, name, o)
	for range 50 { // every chain is refused; this one stays at 0
		if n, _ := x.Once(context.Background()); n != 0 {
			t.Fatalf("Once delivered %d despite a rejection", n)
		}
		if seq, _ := cursorSeq(t, name, tn); seq != 0 {
			t.Fatalf("cursor advanced to %d on a rejection", seq)
		}
	}
	c.set(200, "")
	drain(t, x)
	if seq, _ := cursorSeq(t, name, tn); seq != 3 {
		t.Errorf("cursor %d after delivery", seq)
	}
	var seqs []string
	for _, r := range c.records(t) {
		if attr(r, "lf.audit.tenant_id").(map[string]any)["stringValue"] == tn {
			seqs = append(seqs, attr(r, "lf.audit.seq").(map[string]any)["intValue"].(string))
		}
	}
	if !strings.HasSuffix(strings.Join(seqs, ","), "1,2,3") {
		t.Errorf("collector got seqs %v", seqs)
	}
}

// Header values keep '+' (PathUnescape), and errors never echo the endpoint.
func TestOTLPHeadersAndRedaction(t *testing.T) {
	p := newPKI(t)
	c := startOTLP(t, p, false)
	o, err := NewOTLP(OTLPConfig{Endpoint: c.srv.URL + "/v1/logs", CAFile: p.caFile, Headers: "x-api-key=ab+c/d=="})
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Send(context.Background(), []Entry{entry(1, `{}`)}); err != nil {
		t.Fatal(err)
	}
	if got := c.headers[0].Get("X-Api-Key"); got != "ab+c/d==" {
		t.Errorf("x-api-key = %q", got)
	}
	for _, ep := range []string{"https://otel.example/v1/logs?api_key=hunter2", "http://otel.example/hunter2"} {
		if _, err := NewOTLP(OTLPConfig{Endpoint: ep}); err == nil || strings.Contains(err.Error(), "hunter2") {
			t.Errorf("endpoint %s: %v", ep, err)
		}
	}
}

// A redirect is not delivery, and nothing (headers included) goes to its target.
func TestOTLPDoesNotFollowRedirects(t *testing.T) {
	p := newPKI(t)
	target := startOTLP(t, p, false)
	first := startOTLP(t, p, false)
	first.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.srv.URL+"/v1/logs", http.StatusTemporaryRedirect)
	})
	o, err := NewOTLP(OTLPConfig{Endpoint: first.srv.URL + "/v1/logs", CAFile: p.caFile, Headers: "authorization=Bearer%20secret"})
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Send(context.Background(), []Entry{entry(1, `{}`)}); err == nil {
		t.Error("a 307 counted as delivered")
	}
	target.mu.Lock()
	defer target.mu.Unlock()
	if len(target.headers) != 0 {
		t.Errorf("the redirect target got %d requests", len(target.headers))
	}
}
