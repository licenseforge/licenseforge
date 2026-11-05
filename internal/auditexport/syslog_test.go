package auditexport

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// pki is a throwaway CA with a server certificate for 127.0.0.1 and a client
// certificate, written as PEM files.
type pki struct {
	dir                           string
	ca                            *x509.CertPool
	server                        tls.Certificate
	caFile, clientCert, clientKey string
}

func newPKI(t *testing.T) pki {
	t.Helper()
	dir := t.TempDir()
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	write := func(name, typ string, der []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	caKey := key()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leaf := func(n int64, usage x509.ExtKeyUsage) (*ecdsa.PrivateKey, []byte) {
		k := key()
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(n), Subject: pkix.Name{CommonName: "leaf"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
			ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return k, der
	}
	p := pki{dir: dir, ca: x509.NewCertPool()}
	p.ca.AddCert(caCert)
	p.caFile = write("ca.crt", "CERTIFICATE", caDER)
	sk, sder := leaf(2, x509.ExtKeyUsageServerAuth)
	p.server = tls.Certificate{Certificate: [][]byte{sder}, PrivateKey: sk}
	ck, cder := leaf(3, x509.ExtKeyUsageClientAuth)
	p.clientCert = write("tls.crt", "CERTIFICATE", cder)
	ckDER, _ := x509.MarshalECPrivateKey(ck)
	p.clientKey = write("tls.key", "EC PRIVATE KEY", ckDER)
	return p
}

type collectorOpts struct {
	mtls     bool
	maxTLS   uint16
	noNotify bool // close the TCP connection without close_notify
	appData  bool // send 2 bytes of application data, then close without close_notify
	hang     bool // never close
}

// collector is an RFC 5425 receiver: it reads octet-counted frames until the
// sender's close_notify, then closes cleanly.
type collector struct {
	addr string
	mu   sync.Mutex
	msgs []string
	errs []error
}

func (c *collector) messages() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.msgs...)
}

func startCollector(t *testing.T, p pki, o collectorOpts) *collector {
	t.Helper()
	cfg := &tls.Config{Certificates: []tls.Certificate{p.server}, MaxVersion: o.maxTLS}
	if o.maxTLS != 0 {
		cfg.MinVersion = tls.VersionTLS10 // an old collector really offers its old version
	}
	if o.mtls {
		cfg.ClientAuth, cfg.ClientCAs = tls.RequireAndVerifyClientCert, p.ca
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	c := &collector{addr: ln.Addr().String()}
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				conn := tls.Server(raw, cfg)
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				r := bufio.NewReader(conn)
				for {
					n, err := r.ReadString(' ')
					if err != nil {
						if err != io.EOF {
							c.mu.Lock()
							c.errs = append(c.errs, err)
							c.mu.Unlock()
						}
						break
					}
					size, err := strconv.Atoi(strings.TrimSuffix(n, " "))
					if err != nil {
						break
					}
					b := make([]byte, size)
					if _, err := io.ReadFull(r, b); err != nil {
						break
					}
					c.mu.Lock()
					c.msgs = append(c.msgs, string(b))
					c.mu.Unlock()
				}
				switch {
				case o.hang:
					time.Sleep(5 * time.Second)
				case o.appData:
					_, _ = conn.Write([]byte("ok"))
					_ = raw.Close()
				case o.noNotify:
					_ = raw.Close()
				default:
					_ = conn.Close()
				}
			}()
		}
	}()
	return c
}

func entry(seq int64, details string) Entry {
	return Entry{ID: "aud_" + strconv.FormatInt(seq, 10), TenantID: "tnt_x", Seq: seq, OccurredAt: time.Date(2026, 11, 5, 1, 2, 3, 456789000, time.UTC),
		ActorType: "user", ActorID: "usr_1", Action: "api_token.create", ObjectType: "api_token", ObjectID: "tok_1", Outcome: "success",
		SourceIP: "10.0.0.1", UserAgent: `evil"] [x@1 a="b"\`, Details: json.RawMessage(details), PrevHash: "00", Hash: "ff"}
}

func TestSyslogDelivers(t *testing.T) {
	p := newPKI(t)
	c := startCollector(t, p, collectorOpts{mtls: true})
	s, err := NewSyslog(SyslogConfig{Addr: c.addr, CAFile: p.caFile, CertFile: p.clientCert, KeyFile: p.clientKey, Hostname: "lf-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), []Entry{entry(1, `{"name":"ci"}`), entry(2, `{}`)}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got := c.messages()
	if len(got) != 2 {
		t.Fatalf("collector got %d messages", len(got))
	}
	c.mu.Lock()
	if len(c.errs) != 0 { // the collector saw the sender's close_notify, not a timeout
		t.Errorf("collector errors: %v", c.errs)
	}
	c.mu.Unlock()
	want := `<110>1 2026-11-05T01:02:03.456789Z lf-1 licenseforge - audit [licenseforge@32473 id="aud_1" tenant="tnt_x" seq="1" ` +
		`actor_type="user" actor="usr_1" action="api_token.create" object_type="api_token" object="tok_1" outcome="success" ip="10.0.0.1" ` +
		`ua="evil\"\] [x@1 a=\"b\"\\" details="{\"name\":\"ci\"}" prev_hash="00" hash="ff"] api_token.create success`
	if got[0] != want {
		t.Errorf("message\n got %s\nwant %s", got[0], want)
	}
	if !strings.Contains(got[1], `seq="2"`) {
		t.Errorf("second message %s", got[1])
	}
	// A clean close counts over TLS 1.2 too (alerts have their own record type there).
	c12 := startCollector(t, p, collectorOpts{maxTLS: tls.VersionTLS12})
	s12, err := NewSyslog(SyslogConfig{Addr: c12.addr, CAFile: p.caFile})
	if err != nil {
		t.Fatal(err)
	}
	if err := s12.Send(context.Background(), []Entry{entry(1, `{}`)}); err != nil || len(c12.messages()) != 1 {
		t.Errorf("TLS 1.2 delivery: %v, %d messages", err, len(c12.messages()))
	}
	e := entry(3, `{}`)
	e.Outcome = "denied"
	if m := s.message(e); !strings.HasPrefix(m, "<108>1 ") {
		t.Errorf("denied priority: %s", m)
	}
}

func TestSyslogRefuses(t *testing.T) {
	p := newPKI(t)
	ok := SyslogConfig{CAFile: p.caFile, CertFile: p.clientCert, KeyFile: p.clientKey, Timeout: time.Second}
	for name, c := range map[string]struct {
		opts collectorOpts
		cfg  func(SyslogConfig) SyslogConfig
	}{
		"untrusted collector":              {collectorOpts{}, func(c SyslogConfig) SyslogConfig { c.CAFile = ""; return c }},
		"wrong server name":                {collectorOpts{}, func(c SyslogConfig) SyslogConfig { c.ServerName = "siem.example"; return c }},
		"TLS 1.1 collector":                {collectorOpts{maxTLS: tls.VersionTLS11}, func(c SyslogConfig) SyslogConfig { return c }},
		"mTLS without a cert":              {collectorOpts{mtls: true}, func(c SyslogConfig) SyslogConfig { c.CertFile, c.KeyFile = "", ""; return c }},
		"2 bytes of data, no close_notify": {collectorOpts{appData: true}, func(c SyslogConfig) SyslogConfig { return c }},
		"no close_notify back":             {collectorOpts{noNotify: true}, func(c SyslogConfig) SyslogConfig { return c }},
		"no close_notify, TLS 1.2":         {collectorOpts{noNotify: true, maxTLS: tls.VersionTLS12}, func(c SyslogConfig) SyslogConfig { return c }},
		"collector never closes":           {collectorOpts{hang: true}, func(c SyslogConfig) SyslogConfig { return c }},
	} {
		col := startCollector(t, p, c.opts)
		cfg := c.cfg(ok)
		cfg.Addr = col.addr
		s, err := NewSyslog(cfg)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		start := time.Now()
		if err := s.Send(context.Background(), []Entry{entry(1, `{}`)}); err == nil {
			t.Errorf("%s: Send succeeded", name)
		}
		if time.Since(start) > 3*time.Second {
			t.Errorf("%s: Send took %v (timeout 1s)", name, time.Since(start))
		}
	}
	for name, cfg := range map[string]SyslogConfig{
		"no port":               {Addr: "siem.example"},
		"cert, no key":          {Addr: "siem.example:6514", CertFile: p.clientCert},
		"bad CA file":           {Addr: "siem.example:6514", CAFile: p.clientKey},
		"missing CA file":       {Addr: "siem.example:6514", CAFile: filepath.Join(p.dir, "nope")},
		"bad SD-ID":             {Addr: "siem.example:6514", SDID: `a b@1`},
		"SD-ID, no PEN":         {Addr: "siem.example:6514", SDID: `audit`},
		"SD-ID, PEN not digits": {Addr: "siem.example:6514", SDID: `a@x1`},
		"SD-ID, trailing dot":   {Addr: "siem.example:6514", SDID: `a@1.`},
		"SD-ID, no name":        {Addr: "siem.example:6514", SDID: `@1`},
		"SD-ID, two @":          {Addr: "siem.example:6514", SDID: `a@b@1`},
		"SD-ID with =":          {Addr: "siem.example:6514", SDID: `a=b@1`},
		"SD-ID with ]":          {Addr: "siem.example:6514", SDID: `a]b@1`},
		"SD-ID over 32":         {Addr: "siem.example:6514", SDID: strings.Repeat("a", 28) + "@12345"},
	} {
		if _, err := NewSyslog(cfg); err == nil {
			t.Errorf("NewSyslog accepted %s", name)
		}
	}
}

// End to end: the exporter delivers a chain through the syslog sink, and a
// collector that refuses the client leaves the cursor where it was.
func TestSyslogExport(t *testing.T) {
	p := newPKI(t)
	d := openDB(t)
	tn, _ := chain(t, d, 3)
	c := startCollector(t, p, collectorOpts{mtls: true})
	s, err := NewSyslog(SyslogConfig{Addr: c.addr, CAFile: p.caFile, CertFile: p.clientCert, KeyFile: p.clientKey})
	if err != nil {
		t.Fatal(err)
	}
	name := sinkName()
	drain(t, exporter(t, d, name, s))
	var seqs []string
	for _, m := range c.messages() {
		if strings.Contains(m, `tenant="`+tn+`"`) {
			seqs = append(seqs, m[strings.Index(m, `seq="`)+5:][:1])
		}
	}
	if strings.Join(seqs, ",") != "1,2,3" {
		t.Errorf("collector got seqs %v", seqs)
	}
	if seq, _ := cursorSeq(t, name, tn); seq != 3 {
		t.Errorf("cursor %d after delivery", seq)
	}

	refusing := startCollector(t, p, collectorOpts{mtls: true})
	s2, err := NewSyslog(SyslogConfig{Addr: refusing.addr, CAFile: p.caFile, Timeout: time.Second}) // no client cert
	if err != nil {
		t.Fatal(err)
	}
	name2 := sinkName()
	x := exporter(t, d, name2, s2)
	if n, err := x.Once(context.Background()); n != 0 || err == nil {
		t.Errorf("Once against a refusing collector = %d, %v", n, err)
	}
	if seq, claimed := cursorSeq(t, name2, tn); seq != 0 || claimed {
		t.Errorf("cursor %d claimed=%v after a refused batch", seq, claimed)
	}
}

func TestSyslogSDIDs(t *testing.T) {
	for _, id := range []string{"licenseforge@32473", "a@1.2.3", "audit-log@12345", strings.Repeat("a", 26) + "@12345"} {
		if _, err := NewSyslog(SyslogConfig{Addr: "siem.example:6514", SDID: id}); err != nil {
			t.Errorf("SD-ID %q refused: %v", id, err)
		}
	}
}

// Rotated certificates (renewed Secrets) are used without a restart: the CA
// file is read for every batch, the client certificate at every handshake.
func TestSyslogPicksUpRotatedCertificates(t *testing.T) {
	p, q := newPKI(t), newPKI(t)
	dir := t.TempDir()
	ca, cert, key := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	install := func(k pki) {
		for src, dst := range map[string]string{k.caFile: ca, k.clientCert: cert, k.clientKey: key} {
			b, err := os.ReadFile(src)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dst, b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	install(p)
	cp, cq := startCollector(t, p, collectorOpts{mtls: true}), startCollector(t, q, collectorOpts{mtls: true})
	s, err := NewSyslog(SyslogConfig{Addr: cp.addr, CAFile: ca, CertFile: cert, KeyFile: key, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), []Entry{entry(1, `{}`)}); err != nil {
		t.Fatalf("before rotation: %v", err)
	}
	install(q) // both the collector's CA and our client certificate change
	s.addr = cq.addr
	if err := s.Send(context.Background(), []Entry{entry(2, `{}`)}); err != nil || len(cq.messages()) != 1 {
		t.Errorf("after rotation: %v, %d messages", err, len(cq.messages()))
	}
}

func TestSyslogWarnsAboutLargeMessages(t *testing.T) {
	p := newPKI(t)
	c := startCollector(t, p, collectorOpts{})
	var logs strings.Builder
	s, err := NewSyslog(SyslogConfig{Addr: c.addr, CAFile: p.caFile, Log: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	big := entry(1, `{"note":"`+strings.Repeat("x", 9000)+`"}`)
	if err := s.Send(context.Background(), []Entry{big, entry(2, `{}`)}); err != nil {
		t.Fatal(err)
	}
	if strings.Count(logs.String(), "over 8 KB") != 1 {
		t.Errorf("log: %s", logs.String())
	}
}
