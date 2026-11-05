// Package ratelimit is the per-client-address rate limit of the public
// listener (ADR-0032, Order of checks, step 0): it runs before anything else,
// counts requests per client address and surface in fixed one-minute windows,
// and answers 429 with Retry-After and the IETF RateLimit headers.
//
// The client address is the connection's peer, unless the peer is a trusted
// proxy (LICENSEFORGE_TRUSTED_PROXIES): then it is the right-most address in
// X-Forwarded-For that isn't a trusted proxy, so a client can't choose its
// address by sending the header itself. IPv6 clients are counted per /64,
// the block one host or customer usually holds.
//
// ponytail: per replica and fixed windows, like the per-key limiter
// (internal/api); N replicas allow N × quota. A shared store when
// per-cluster limits matter.
package ratelimit

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"licenseforge.io/licenseforge/internal/metrics"
)

// Surface is a group of routes with its own quota.
type Surface string

const (
	None       Surface = ""           // not limited: health checks, the dashboard's static files
	Activation Surface = "activation" // SDKs: /api/v1/activation/…
	Management Surface = "management" // the rest of /api/v1, and /auth/ except login
	Login      Surface = "login"      // /auth/login and /auth/callback: the IdP round trip
)

// Default quotas, requests per client address per minute, per replica. Many
// installs share a customer's egress address, so activation is generous (the
// per-key limit, 60/min, bounds each license); a dashboard page makes several
// API calls; a login is two requests, and the callback calls the IdP.
const (
	DefaultActivation = 1200
	DefaultManagement = 600
	DefaultLogin      = 60
)

// window is the length of a counting window.
const window = time.Minute

// DefaultMaxAddresses bounds the (surface, address) pairs tracked per window.
const DefaultMaxAddresses = 100_000

// Config sets the limiter up.
type Config struct {
	// Trusted are the proxies whose X-Forwarded-For is believed.
	Trusted []netip.Prefix
	// Quotas per surface, requests per address per minute; 0 turns the
	// surface's limit off (e.g. when the ingress limits it).
	Quotas map[Surface]int
	// MaxAddresses bounds memory; 0 means DefaultMaxAddresses.
	MaxAddresses int
	// Log gets one warning the first time X-Forwarded-For arrives from a
	// peer that isn't a trusted proxy; nil: slog.Default().
	Log *slog.Logger
}

// Limiter counts requests. Build it with New.
type Limiter struct {
	trusted []netip.Prefix
	quotas  map[Surface]int
	max     int
	now     func() time.Time
	log     *slog.Logger
	warned  sync.Once

	mu     sync.Mutex
	start  time.Time
	counts map[key]int
}

type key struct {
	surface Surface
	addr    netip.Prefix
}

// New returns a limiter for c.
func New(c Config) *Limiter {
	if c.MaxAddresses <= 0 {
		c.MaxAddresses = DefaultMaxAddresses
	}
	if c.Log == nil {
		c.Log = slog.Default()
	}
	return &Limiter{trusted: c.Trusted, quotas: c.Quotas, max: c.MaxAddresses, now: time.Now, log: c.Log, counts: map[key]int{}}
}

// SurfaceOf classifies a request by its decoded path as is, never cleaned:
// ServeMux redirects a path with literal dot segments but routes encoded
// ones ("/api/v1/%2e%2e/healthz" reaches the /api/v1/ handler as
// "/api/v1/../healthz"), so the prefix it routes by is the one to limit by.
func SurfaceOf(p string) Surface {
	switch {
	case strings.HasPrefix(p, "/api/v1/activation/"):
		return Activation
	case p == "/auth/login" || p == "/auth/callback":
		return Login
	case p == "/api/v1" || strings.HasPrefix(p, "/api/v1/") || strings.HasPrefix(p, "/auth/"):
		return Management
	}
	return None
}

// Narrowest prefixes ParseTrusted accepts: anything broader (a /0 above
// all) would let most of the internet set its own client address.
const (
	minBits4 = 8
	minBits6 = 32
)

// ParseTrusted parses a comma-separated list of CIDRs or single addresses,
// e.g. LICENSEFORGE_TRUSTED_PROXIES="10.0.0.0/8, fd00::/8, 192.0.2.7".
// IPv4-mapped IPv6 forms are read as IPv4 (as client addresses are).
func ParseTrusted(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if p, err := netip.ParsePrefix(part); err == nil {
			if p.Addr().Zone() != "" {
				return nil, fmt.Errorf("trusted proxy %q: no zones", part)
			}
			if p.Addr().Is4In6() {
				if p.Bits() < 96 {
					return nil, fmt.Errorf("trusted proxy %q: an IPv4-mapped prefix must be /96 or longer", part)
				}
				p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
			if p.Addr().Is4() && p.Bits() < minBits4 || p.Addr().Is6() && p.Bits() < minBits6 {
				return nil, fmt.Errorf("trusted proxy %q: broader than /%d (IPv4) or /%d (IPv6); list your proxies' own ranges", part, minBits4, minBits6)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(part)
		if err != nil || a.Zone() != "" {
			return nil, fmt.Errorf("trusted proxy %q: want a CIDR or an IP address", part)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func trusted(list []netip.Prefix, a netip.Addr) bool {
	for _, p := range list {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// parseAddr reads an address as it appears in RemoteAddr or one
// X-Forwarded-For hop: "ip", "ip:port" or "[ipv6]:port".
func parseAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().WithZone("").Unmap(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.WithZone("").Unmap(), true
	}
	return netip.Addr{}, false
}

// ClientAddr is r's client address: the peer, or, while the peer and the
// hops right of a candidate are trusted proxies, the next X-Forwarded-For
// hop to the left. It stops at the first untrusted hop (the client: anything
// left of it is the client's own claim) and at a malformed hop (keeping the
// trusted proxy right of it). ok is false if RemoteAddr isn't an address.
func ClientAddr(r *http.Request, trustedProxies []netip.Prefix) (netip.Addr, bool) {
	addr, ok := parseAddr(r.RemoteAddr)
	if !ok || !trusted(trustedProxies, addr) {
		return addr, ok
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		if strings.TrimSpace(hops[i]) == "" {
			continue
		}
		hop, ok := parseAddr(hops[i])
		if !ok {
			break
		}
		addr = hop
		if !trusted(trustedProxies, hop) {
			break
		}
	}
	return addr, true
}

type addrKey struct{}

// Addr returns the client address Wrap resolved for this request, if any
// (for audit entries).
func Addr(ctx context.Context) (netip.Addr, bool) {
	a, ok := ctx.Value(addrKey{}).(netip.Addr)
	return a, ok
}

// bucket is the counted unit for a: the address, or its /64 for IPv6.
func bucket(a netip.Addr) netip.Prefix {
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p
	}
	return netip.PrefixFrom(a, 32)
}

// take counts one request of a on s and reports whether it is within quota,
// the requests remaining and the seconds until the window resets. Past the
// address bound, a new address passes untracked (fail open): see the PR and
// the Secure Configuration Guide for why.
func (l *Limiter) take(s Surface, a netip.Addr, quota int) (ok, tracked bool, remaining, reset int) {
	k := key{s, bucket(a)}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if start := now.Truncate(window); !start.Equal(l.start) {
		l.start, l.counts = start, map[key]int{}
	}
	reset = max(1, int((l.start.Add(window).Sub(now)+time.Second-1)/time.Second))
	n, seen := l.counts[k]
	if !seen && len(l.counts) >= l.max {
		return true, false, quota, reset
	}
	if n >= quota {
		return false, true, 0, reset
	}
	l.counts[k] = n + 1
	return true, true, quota - n - 1, reset
}

// Refused and Untracked count refused requests and requests past the address
// bound, by surface; never by address (unbounded, and personal data).
var (
	Refused = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "licenseforge_rate_limited_requests_total", Help: "Requests refused by the per-client-address rate limit (429), by surface.",
	}, []string{"surface"})
	Untracked = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "licenseforge_rate_limit_untracked_requests_total", Help: "Requests let through untracked because the address table was full, by surface.",
	}, []string{"surface"})
	// IgnoredForwarded counts requests whose X-Forwarded-For was ignored
	// because the peer isn't a trusted proxy (a missing
	// LICENSEFORGE_TRUSTED_PROXIES, or a client sending the header itself).
	IgnoredForwarded = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "licenseforge_forwarded_headers_ignored_total", Help: "Requests with X-Forwarded-For from a peer that isn't a trusted proxy (header ignored).",
	})
)

func init() {
	for _, s := range []Surface{Activation, Management, Login} {
		Refused.WithLabelValues(string(s))
		Untracked.WithLabelValues(string(s))
	}
	metrics.Registry.MustRegister(Refused, Untracked, IgnoredForwarded)
}

// Wrap limits next: on a limited surface, a request over quota gets 429
// before next sees it. Every request carries its client address in its
// context (Addr).
func (l *Limiter) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, ok := ClientAddr(r, l.trusted)
		if ok {
			r = r.WithContext(context.WithValue(r.Context(), addrKey{}, a))
		}
		if peer, isAddr := parseAddr(r.RemoteAddr); isAddr && len(r.Header.Values("X-Forwarded-For")) > 0 && !trusted(l.trusted, peer) {
			IgnoredForwarded.Inc()
			l.warned.Do(func() {
				l.log.Warn("X-Forwarded-For from a peer that isn't a trusted proxy is ignored: clients behind a proxy count as the proxy for the rate limit and in audit entries; if this peer is your ingress, add it to LICENSEFORGE_TRUSTED_PROXIES",
					"peer", peer.String())
			})
		}
		s := SurfaceOf(r.URL.Path)
		quota := l.quotas[s]
		if s == None || quota <= 0 {
			next.ServeHTTP(w, r)
			return
		}
		if !ok { // not a TCP peer (tests, unix sockets): nothing to key on
			Untracked.WithLabelValues(string(s)).Inc()
			next.ServeHTTP(w, r)
			return
		}
		allowed, tracked, remaining, reset := l.take(s, a, quota)
		if !tracked {
			Untracked.WithLabelValues(string(s)).Inc()
			next.ServeHTTP(w, r)
			return
		}
		name := `"address-` + string(s) + `"`
		w.Header().Add("RateLimit-Policy", fmt.Sprintf("%s;q=%d;w=%d", name, quota, int(window/time.Second)))
		w.Header().Add("RateLimit", fmt.Sprintf("%s;r=%d;t=%d", name, remaining, reset))
		if allowed {
			next.ServeHTTP(w, r)
			return
		}
		Refused.WithLabelValues(string(s)).Inc()
		tooMany(w, reset)
	})
}

// tooMany writes the 429 as RFC 9457 problem+json, like the API's errors
// (ADR-0032), with its own request ID (the API's handler never runs).
func tooMany(w http.ResponseWriter, retry int) {
	id := rand.Text()
	b, _ := json.Marshal(map[string]any{
		"type": "about:blank", "title": http.StatusText(http.StatusTooManyRequests), "status": http.StatusTooManyRequests,
		"detail": "Too many requests from this address; retry after Retry-After seconds.", "code": "rate_limited", "request_id": id,
	})
	w.Header().Set("Retry-After", strconv.Itoa(retry))
	w.Header().Set("X-Request-Id", id)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write(append(b, '\n'))
}
