package auditexport

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SyslogConfig configures the syslog sink (ADR-0036): RFC 5424 messages over
// TLS (RFC 5425), certificate verification always on.
type SyslogConfig struct {
	Addr       string // host:port of the collector (6514 by convention)
	CAFile     string // PEM roots for the collector's certificate; empty: system roots
	CertFile   string // optional client certificate (mTLS), PEM, with KeyFile
	KeyFile    string
	ServerName string        // name the collector's certificate must have; default Addr's host
	Timeout    time.Duration // per batch: dial, handshake, write and close; default 10s
	Hostname   string        // the HOSTNAME field; default os.Hostname
	SDID       string        // the structured data ID (name@PEN); default licenseforge@32473
	Log        *slog.Logger  // warnings (oversized messages); default slog.Default()
}

// Syslog is the RFC 5424/5425 sink. Each batch goes over its own TLS
// connection, which is closed in both directions (close_notify sent and
// received) before Send returns nil: RFC 5425 has no application-level
// acknowledgement, so a clean close after a flush is the best evidence of
// delivery there is (ADR-0036). Any loss shows in the SIEM's continuity check.
type Syslog struct {
	addr, serverName          string
	caFile, certFile, keyFile string
	timeout                   time.Duration
	hostname, sdID            string
	log                       *slog.Logger
}

// maxMessage is RFC 5425's minimum every receiver must accept; larger ones
// are sent but may be truncated by the collector, so they are logged.
const maxMessage = 8192

var (
	// SD-ID name@PEN (RFC 5424 §6.3.2, §7.2.2): the name printable ASCII
	// except = SP ] " @, the PEN dotted digits; at most 32 characters in all.
	sdIDRE   = regexp.MustCompile(`^[!#-<>-?A-\\^-~]{1,32}@[0-9]+(\.[0-9]+)*$`)
	hostChar = func(r rune) bool { return r > 32 && r < 127 }
)

// NewSyslog checks c and loads its certificates; errors stop the server at
// start, not at the first batch.
func NewSyslog(c SyslogConfig) (*Syslog, error) {
	host, port, err := net.SplitHostPort(c.Addr)
	if err != nil || host == "" || port == "" {
		return nil, fmt.Errorf("syslog: address %q: want host:port", c.Addr)
	}
	if (c.CertFile == "") != (c.KeyFile == "") {
		return nil, errors.New("syslog: a client certificate needs both the certificate and the key")
	}
	s := &Syslog{addr: c.Addr, serverName: c.ServerName, caFile: c.CAFile, certFile: c.CertFile, keyFile: c.KeyFile,
		timeout: c.Timeout, hostname: c.Hostname, sdID: c.SDID, log: c.Log}
	if s.serverName == "" {
		s.serverName = host
	}
	if s.timeout <= 0 {
		s.timeout = 10 * time.Second
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.hostname == "" {
		s.hostname, _ = os.Hostname()
	}
	if s.hostname = strings.Map(func(r rune) rune {
		if hostChar(r) {
			return r
		}
		return -1
	}, s.hostname); len(s.hostname) > 255 || s.hostname == "" {
		s.hostname = "-"
	}
	if s.sdID == "" {
		s.sdID = "licenseforge@32473"
	}
	if len(s.sdID) > 32 || !sdIDRE.MatchString(s.sdID) {
		return nil, fmt.Errorf("syslog: structured data ID %q: want name@enterprise-number, at most 32 characters", s.sdID)
	}
	// Fail at start on unreadable files; Send reads them again (rotation).
	if _, err := s.tlsConfig(); err != nil {
		return nil, err
	}
	if s.certFile != "" {
		if _, err := tls.LoadX509KeyPair(s.certFile, s.keyFile); err != nil {
			return nil, fmt.Errorf("syslog: client certificate: %w", err)
		}
	}
	return s, nil
}

// tlsConfig is built for every batch: the CA file is read again and the
// client certificate loaded at each handshake, so rotated Secrets take
// effect without a restart.
func (s *Syslog) tlsConfig() (*tls.Config, error) {
	return clientTLS("syslog", s.serverName, s.caFile, s.certFile, s.keyFile)
}

// clientTLS is a sink's TLS client configuration: TLS 1.2+, verification
// always on, roots from caFile (re-read on every call; empty: system roots)
// and an optional client certificate loaded at each handshake, so rotated
// Secrets apply without a restart.
func clientTLS(sink, serverName, caFile, certFile, keyFile string) (*tls.Config, error) {
	t := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("%s: CA: %w", sink, err)
		}
		t.RootCAs = x509.NewCertPool()
		if !t.RootCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: CA file has no PEM certificates", sink)
		}
	}
	if certFile != "" {
		t.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			c, err := tls.LoadX509KeyPair(certFile, keyFile)
			return &c, err
		}
	}
	return t, nil
}

// Send writes the batch, octet-counted (RFC 5425 §4.3), then closes the TLS
// connection cleanly within the timeout.
func (s *Syslog) Send(ctx context.Context, batch []Entry) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	var nd net.Dialer
	raw, err := nd.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return fmt.Errorf("syslog: %w", err)
	}
	cfg, err := s.tlsConfig()
	if err != nil {
		_ = raw.Close()
		return err
	}
	rec := &rawEOF{Conn: raw}
	conn := tls.Client(rec, cfg)
	defer func() { _ = conn.Close() }()
	if err := conn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("syslog: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	w := bufio.NewWriter(conn)
	for _, e := range batch {
		m := s.message(e)
		if len(m) > maxMessage {
			s.log.Warn("audit export: syslog message over 8 KB, the collector may truncate it", "id", e.ID, "bytes", len(m))
		}
		if _, err := w.WriteString(strconv.Itoa(len(m)) + " " + m); err != nil {
			return fmt.Errorf("syslog: write: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("syslog: write: %w", err)
	}
	// RFC 5425 §5.3: send close_notify, then wait for the collector's.
	if err := conn.CloseWrite(); err != nil {
		return fmt.Errorf("syslog: close: %w", err)
	}
	if _, err := io.Copy(io.Discard, conn); err != nil {
		return fmt.Errorf("syslog: close: no clean close from the collector: %w", err)
	}
	// crypto/tls reports a plain TCP close at a record boundary as io.EOF,
	// like a close_notify. But after a close_notify it stops reading the
	// raw connection, so a raw EOF means the collector closed without one.
	if rec.eof {
		return errors.New("syslog: close: the collector closed without close_notify")
	}
	return nil
}

// rawEOF notes whether the raw connection itself reached EOF.
type rawEOF struct {
	net.Conn
	eof bool
}

func (r *rawEOF) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	if errors.Is(err, io.EOF) {
		r.eof = true
	}
	return n, err
}

// facility 13 (log audit, RFC 5424 §6.2.1); refusals and failures are
// warnings, successes informational.
func pri(outcome string) int {
	if outcome == "success" {
		return 13*8 + 6
	}
	return 13*8 + 4
}

// message is one RFC 5424 message. Every audit field is an SD-PARAM of one
// SD-ELEMENT; MSG is a short human-readable summary.
func (s *Syslog) message(e Entry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<%d>1 %s %s licenseforge - audit [%s", pri(e.Outcome),
		e.OccurredAt.UTC().Format("2006-01-02T15:04:05.000000Z"), s.hostname, s.sdID)
	param := func(name, v string) {
		if v != "" {
			b.WriteString(" " + name + `="` + sdEscape(v) + `"`)
		}
	}
	param("id", e.ID)
	param("tenant", e.TenantID)
	param("seq", strconv.FormatInt(e.Seq, 10))
	param("actor_type", e.ActorType)
	param("actor", e.ActorID)
	param("action", e.Action)
	param("object_type", e.ObjectType)
	param("object", e.ObjectID)
	param("outcome", e.Outcome)
	param("ip", e.SourceIP)
	param("ua", e.UserAgent)
	param("details", string(e.Details))
	param("prev_hash", e.PrevHash)
	param("hash", e.Hash)
	b.WriteString("] " + e.Action + " " + e.Outcome)
	return b.String()
}

// sdEscape escapes a PARAM-VALUE (RFC 5424 §6.3.3): '"', '\' and ']' get a
// backslash. Values are valid UTF-8 already (the database stores them so).
func sdEscape(v string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`).Replace(v)
}
