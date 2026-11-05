package auditexport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// OTLPConfig configures the OTLP sink (ADR-0036): OTLP logs over HTTP with
// the JSON encoding (OTLP/HTTP, protocol "http/json"), no OpenTelemetry
// dependency. TLS 1.2+, verification always on.
type OTLPConfig struct {
	Endpoint string // full logs URL, e.g. https://otel-collector:4318/v1/logs; https (http only on loopback)
	CAFile   string // PEM roots; empty: system roots
	CertFile string // optional client certificate (mTLS), with KeyFile
	KeyFile  string
	// Headers sent with every request, "k=v,k2=v2" as in
	// OTEL_EXPORTER_OTLP_HEADERS (e.g. an API key); values may be %-encoded.
	Headers  string
	Hostname string // host.name resource attribute; default os.Hostname
}

// OTLP is the OTLP/HTTP JSON sink. A batch counts as delivered only on a 2xx
// response that rejects no record (partialSuccess.rejectedLogRecords = 0).
type OTLP struct {
	url                       *url.URL
	caFile, certFile, keyFile string
	headers                   http.Header
	hostname                  string
}

// NewOTLP checks c and its files; errors stop the server at start.
func NewOTLP(c OTLPConfig) (*OTLP, error) {
	// Errors never echo the endpoint: a mistyped one may carry a secret.
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("otlp: endpoint: want https://host[:port]/path, without userinfo, query or fragment")
	}
	ip := net.ParseIP(u.Hostname())
	loopback := u.Hostname() == "localhost" || ip != nil && ip.IsLoopback()
	if u.Scheme != "https" && (u.Scheme != "http" || !loopback) {
		return nil, fmt.Errorf("otlp: endpoint %s://%s must be https (http only on loopback)", u.Scheme, u.Host)
	}
	if (c.CertFile == "") != (c.KeyFile == "") {
		return nil, errors.New("otlp: a client certificate needs both the certificate and the key")
	}
	o := &OTLP{url: u, caFile: c.CAFile, certFile: c.CertFile, keyFile: c.KeyFile, headers: http.Header{}, hostname: c.Hostname}
	for _, kv := range strings.Split(c.Headers, ",") {
		if strings.TrimSpace(kv) == "" {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		k = strings.TrimSpace(k)
		// PathUnescape: '+' stays '+' (API keys often contain it).
		if v, err = url.PathUnescape(strings.TrimSpace(v)); !ok || err != nil || !headerName(k) || !headerValue(v) {
			return nil, errors.New("otlp: headers: want k=v,k2=v2 with token names and values without control characters")
		}
		o.headers.Add(k, v)
	}
	if o.hostname == "" {
		o.hostname, _ = os.Hostname()
	}
	if _, err := o.tlsConfig(); err != nil {
		return nil, err
	}
	if o.certFile != "" {
		if _, err := tls.LoadX509KeyPair(o.certFile, o.keyFile); err != nil {
			return nil, fmt.Errorf("otlp: client certificate: %w", err)
		}
	}
	return o, nil
}

// headerName reports whether s is an RFC 7230 token.
func headerName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum := c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if !alnum && strings.IndexByte("!#$%&'*+-.^_`|~", c) < 0 {
			return false
		}
	}
	return true
}

// headerValue reports whether s has no control characters (HTAB allowed).
func headerValue(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 && c != '\t' || c == 0x7f {
			return false
		}
	}
	return true
}

func (o *OTLP) tlsConfig() (*tls.Config, error) {
	return clientTLS("otlp", o.url.Hostname(), o.caFile, o.certFile, o.keyFile)
}

// Send posts the batch as one ExportLogsServiceRequest. ctx bounds the
// request (the exporter gives it half the lease).
func (o *OTLP) Send(ctx context.Context, batch []Entry) error {
	body, err := json.Marshal(o.request(batch))
	if err != nil {
		return err
	}
	cfg, err := o.tlsConfig()
	if err != nil {
		return err
	}
	// A client per batch: the CA and client certificate are read fresh, and
	// no connection outlives the batch. No redirects: a 3xx isn't delivery.
	client := &http.Client{
		// No proxy, like syslog: the collector is reached directly (NetworkPolicy egress).
		Transport:     &http.Transport{TLSClientConfig: cfg, Proxy: nil, ForceAttemptHTTP2: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.url.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, vs := range o.headers {
		req.Header[k] = vs
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("otlp: %s://%s: %w", o.url.Scheme, o.url.Host, errors.Unwrap(err))
	}
	defer func() { _ = resp.Body.Close() }()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("otlp: response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("otlp: collector answered %s", resp.Status)
	}
	// 2xx: delivered if the body is empty, or is an OTLP JSON response that
	// rejects no record (partial success). Anything else isn't proof.
	if len(bytes.TrimSpace(rb)) == 0 {
		return nil
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return fmt.Errorf("otlp: collector answered %s with a non-JSON body", resp.Status)
	}
	var r struct {
		PartialSuccess struct {
			RejectedLogRecords json.Number `json:"rejectedLogRecords"`
			ErrorMessage       string      `json:"errorMessage"`
		} `json:"partialSuccess"`
	}
	if err := json.Unmarshal(rb, &r); err != nil {
		return fmt.Errorf("otlp: response: %w", err)
	}
	if n := r.PartialSuccess.RejectedLogRecords.String(); n != "" && n != "0" {
		return fmt.Errorf("otlp: collector rejected %s of %d records: %s", n, len(batch), r.PartialSuccess.ErrorMessage)
	}
	return nil
}

// OTLP/JSON types (opentelemetry-proto, JSON mapping: camelCase names, 64-bit
// integers as strings).
type (
	kv struct {
		Key   string   `json:"key"`
		Value anyValue `json:"value"`
	}
	anyValue struct {
		StringValue *string `json:"stringValue,omitempty"`
		IntValue    *string `json:"intValue,omitempty"`
	}
	logRecord struct {
		TimeUnixNano         string   `json:"timeUnixNano"`
		ObservedTimeUnixNano string   `json:"observedTimeUnixNano"`
		SeverityNumber       int      `json:"severityNumber"`
		SeverityText         string   `json:"severityText"`
		EventName            string   `json:"eventName"`
		Body                 anyValue `json:"body"`
		Attributes           []kv     `json:"attributes"`
	}
)

func str(k, v string) kv { return kv{k, anyValue{StringValue: &v}} }

// request maps the batch to one ExportLogsServiceRequest. Every AU-3 field
// and the chain links are attributes (lf.audit.*); severity is INFO for a
// success and WARN for a refusal or failure.
func (o *OTLP) request(batch []Entry) any {
	now := strconv.FormatInt(time.Now().UnixNano(), 10)
	records := make([]logRecord, 0, len(batch))
	for _, e := range batch {
		sev, text := 9, "INFO"
		if e.Outcome != "success" {
			sev, text = 13, "WARN"
		}
		seq := strconv.FormatInt(e.Seq, 10)
		attrs := []kv{str("lf.audit.id", e.ID), str("lf.audit.tenant_id", e.TenantID), {"lf.audit.seq", anyValue{IntValue: &seq}},
			str("lf.audit.actor_type", e.ActorType), str("lf.audit.action", e.Action), str("lf.audit.outcome", e.Outcome),
			str("lf.audit.details", string(e.Details)), str("lf.audit.prev_hash", e.PrevHash), str("lf.audit.hash", e.Hash)}
		for _, a := range [][2]string{{"lf.audit.actor_id", e.ActorID}, {"lf.audit.object_type", e.ObjectType}, {"lf.audit.object_id", e.ObjectID},
			{"lf.audit.source_ip", e.SourceIP}, {"lf.audit.user_agent", e.UserAgent}} {
			if a[1] != "" {
				attrs = append(attrs, str(a[0], a[1]))
			}
		}
		body := e.Action + " " + e.Outcome
		records = append(records, logRecord{TimeUnixNano: strconv.FormatInt(e.OccurredAt.UnixNano(), 10), ObservedTimeUnixNano: now,
			SeverityNumber: sev, SeverityText: text, EventName: "lf.audit." + e.Action, Body: anyValue{StringValue: &body}, Attributes: attrs})
	}
	return map[string]any{"resourceLogs": []any{map[string]any{
		"resource": map[string]any{"attributes": []kv{str("service.name", "licenseforge"), str("host.name", o.hostname)}},
		"scopeLogs": []any{map[string]any{
			"scope":      map[string]any{"name": "licenseforge.io/audit"},
			"logRecords": records,
		}},
	}}}
}
