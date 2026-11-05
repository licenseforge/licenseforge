package auditexport

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
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
}

// Syslog is the RFC 5424/5425 sink. Each batch goes over its own TLS
// connection, which is closed in both directions (close_notify sent and
// received) before Send returns nil: RFC 5425 has no application-level
// acknowledgement, so a clean close after a flush is the best evidence of
// delivery there is (ADR-0036). Any loss shows in the SIEM's continuity check.
type Syslog struct {
	addr     string
	tls      *tls.Config
	timeout  time.Duration
	hostname string
	sdID     string
}

var (
	sdIDRE   = regexp.MustCompile(`^[!#-<>-\\^-~]{1,32}$`) // SD-NAME: PRINTUSASCII except = SP ] "
	hostChar = func(r rune) bool { return r > 32 && r < 127 }
)

// NewSyslog checks c and loads its certificates; errors stop the server at
// start, not at the first batch.
func NewSyslog(c SyslogConfig) (*Syslog, error) {
	host, port, err := net.SplitHostPort(c.Addr)
	if err != nil || host == "" || port == "" {
		return nil, fmt.Errorf("syslog: address %q: want host:port", c.Addr)
	}
	t := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if c.ServerName != "" {
		t.ServerName = c.ServerName
	}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("syslog: CA: %w", err)
		}
		t.RootCAs = x509.NewCertPool()
		if !t.RootCAs.AppendCertsFromPEM(pem) {
			return nil, errors.New("syslog: CA file has no PEM certificates")
		}
	}
	switch {
	case c.CertFile != "" && c.KeyFile != "":
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("syslog: client certificate: %w", err)
		}
		t.Certificates = []tls.Certificate{cert}
	case c.CertFile != "" || c.KeyFile != "":
		return nil, errors.New("syslog: a client certificate needs both the certificate and the key")
	}
	s := &Syslog{addr: c.Addr, tls: t, timeout: c.Timeout, hostname: c.Hostname, sdID: c.SDID}
	if s.timeout <= 0 {
		s.timeout = 10 * time.Second
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
	if !sdIDRE.MatchString(s.sdID) || !strings.Contains(s.sdID, "@") {
		return nil, fmt.Errorf("syslog: structured data ID %q: want name@enterprise-number", s.sdID)
	}
	return s, nil
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
	rec := &records{Conn: raw}
	conn := tls.Client(rec, s.tls)
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
	// like a close_notify. Only the latter counts as delivered.
	if !rec.endedWithAlert(conn.ConnectionState().Version) {
		return errors.New("syslog: close: the collector closed without close_notify")
	}
	return nil
}

// records watches the TLS records a connection receives, to tell a
// close_notify from a plain TCP close.
type records struct {
	net.Conn
	hdr      []byte // partial record header
	left     int    // body bytes still to come in the current record
	lastType byte   // type and length of the last complete record
	lastLen  int
}

func (r *records) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	for b := p[:n]; len(b) > 0; {
		if r.left > 0 {
			k := min(r.left, len(b))
			r.left, b = r.left-k, b[k:]
			continue
		}
		k := min(5-len(r.hdr), len(b))
		r.hdr, b = append(r.hdr, b[:k]...), b[k:]
		if len(r.hdr) == 5 {
			r.lastType, r.lastLen = r.hdr[0], int(r.hdr[3])<<8|int(r.hdr[4])
			r.left, r.hdr = r.lastLen, r.hdr[:0]
		}
	}
	return n, err
}

// endedWithAlert reports whether the stream ended exactly after an alert
// record. In TLS 1.2 alerts have their own record type (21). TLS 1.3 hides
// the type: an alert is the only 19-byte record (2 bytes of alert, its inner
// type byte and a 16-byte AEAD tag, unpadded). A fatal alert would have
// failed the read, so a final alert here is the close_notify.
func (r *records) endedWithAlert(version uint16) bool {
	if r.left != 0 || len(r.hdr) != 0 {
		return false // the stream stopped inside a record
	}
	if version == tls.VersionTLS13 {
		return r.lastType == 23 && r.lastLen == 19
	}
	return r.lastType == 21
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
