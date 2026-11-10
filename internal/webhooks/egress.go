package webhooks

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Egress (ADR-0044): where a delivery may connect. Every address a dial
// tries (each resolved candidate, on every attempt) is checked in the
// dialer's Control, after DNS, so DNS rebinding doesn't help.

// special are the ranges the IANA IPv4 and IPv6 Special-Purpose Address
// Registries mark not globally reachable, plus IPv6 forms that embed an
// IPv4 address in a way that can't be checked (refused outright). The
// operator's allowlist can lift these, except for always.
var special = prefixes(
	// IPv4
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
	"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	// IPv6
	"::/96",                      // unspecified, loopback, IPv4-compatible
	"64:ff9b:1::/48",             // local-use NAT64: where the IPv4 sits is the operator's choice (RFC 8215)
	"100::/64",                   // discard
	"2001::/23",                  // IETF protocol assignments, Teredo (2001::/32) and benchmarking among them
	"2001:db8::/32", "3fff::/20", // documentation
	"2002::/16", // 6to4
	"5f00::/16", // SRv6 SIDs
	"fc00::/7",  // unique local
	"fe80::/10", // link-local
	"fec0::/10", // site-local (deprecated)
	"ff00::/8",  // multicast
)

// always are refused even when allowlisted: this host, link-local, and the
// cloud platforms' metadata and host addresses (some of which sit in ranges
// an operator may allowlist, or are globally routable).
var always = prefixes(
	"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "::/128", "::1/128", "fe80::/10",
	"fd00:ec2::254/128",  // AWS metadata (IPv6, in ULA space)
	"100.100.100.200/32", // Alibaba metadata (in CGNAT space)
	"192.0.0.192/32",     // Oracle metadata
	"168.63.129.16/32",   // Azure WireServer and host DNS (globally routable)
)

// nat64 is the well-known NAT64 prefix (RFC 6052): the last 32 bits are the
// IPv4 address an IPv6-only cluster with DNS64 reaches; that is checked.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

func prefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func inAny(ps []netip.Prefix, a netip.Addr) bool {
	return slices.ContainsFunc(ps, func(p netip.Prefix) bool { return p.Contains(a) })
}

// Guard is the operator's egress policy for webhooks.
type Guard struct {
	Allow []netip.Prefix // LICENSEFORGE_WEBHOOK_ALLOW_CIDRS: internal receivers (self-hosted installs)
	Deny  []netip.Prefix // LICENSEFORGE_WEBHOOK_DENY_CIDRS: e.g. an operator-chosen NAT64 prefix
	Ports []int          // LICENSEFORGE_WEBHOOK_PORTS; empty: 443
}

// ParseGuard reads the three settings: comma-separated CIDRs and ports.
func ParseGuard(allow, deny, ports string) (Guard, error) {
	var g Guard
	for _, f := range []struct {
		s   string
		dst *[]netip.Prefix
	}{{allow, &g.Allow}, {deny, &g.Deny}} {
		for _, c := range strings.Split(f.s, ",") {
			if c = strings.TrimSpace(c); c == "" {
				continue
			}
			p, err := netip.ParsePrefix(c)
			if err != nil {
				return Guard{}, fmt.Errorf("webhooks: CIDR %q: %w", c, err)
			}
			*f.dst = append(*f.dst, p.Masked())
		}
	}
	for _, s := range strings.Split(ports, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		p, err := strconv.Atoi(s)
		if err != nil || p < 1 || p > 65535 {
			return Guard{}, fmt.Errorf("webhooks: port %q", s)
		}
		g.Ports = append(g.Ports, p)
	}
	return g, nil
}

// Allowed reports whether a delivery may connect to a.
func (g Guard) Allowed(a netip.Addr) bool {
	if a.Zone() != "" {
		return false
	}
	a = a.Unmap()
	if nat64.Contains(a) {
		b := a.As16()
		a = netip.AddrFrom4([4]byte(b[12:]))
	}
	switch {
	case inAny(always, a), inAny(g.Deny, a):
		return false
	case inAny(special, a):
		return inAny(g.Allow, a)
	}
	return true
}

func (g Guard) port(p int) bool {
	if len(g.Ports) == 0 {
		return p == 443
	}
	return slices.Contains(g.Ports, p)
}

// errBlocked: the address or port isn't allowed. Reported to tenants as
// "connection", like any failed connection (no probing).
var errBlocked = errors.New("webhooks: destination not allowed")

// control is the dialer's Control: it sees the address actually dialled.
func (g Guard) control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil || !g.Allowed(ap.Addr()) || !g.port(int(ap.Port())) {
		return errBlocked
	}
	return nil
}

// Timeout bounds one delivery attempt (ADR-0044: 15 s).
const Timeout = 15 * time.Second

// Client is the delivery client: the guard on every dial, the pure-Go
// resolver (numeric host names aren't read as addresses), no proxy from
// the environment, TLS 1.2+ against the system roots (extraCA included),
// redirects never followed.
func (g Guard) Client() *http.Client { return client(g.control, nil, Timeout) }

func client(control func(string, string, syscall.RawConn) error, tlsConf *tls.Config, timeout time.Duration) *http.Client {
	if tlsConf == nil {
		tlsConf = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	d := &net.Dialer{Timeout: 10 * time.Second, Control: control, Resolver: &net.Resolver{PreferGo: true}}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            d.DialContext,
			TLSClientConfig:        tlsConf,
			TLSHandshakeTimeout:    10 * time.Second,
			MaxResponseHeaderBytes: 64 << 10,
			ForceAttemptHTTP2:      true,
			MaxIdleConnsPerHost:    2,
			IdleConnTimeout:        90 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
