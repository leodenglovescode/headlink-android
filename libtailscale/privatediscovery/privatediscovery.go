// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package privatediscovery implements the Go half of Headlink's "Private
// Headscale IPv6 Discovery" feature.
//
// # What this is
//
// It is the equivalent of a single, application-local /etc/hosts line for the
// coordination server, and nothing more:
//
//	<discovered-public-ipv6>  headscale.example
//
// The Headscale hostname deliberately resolves to a private LAN address in
// public DNS so the home network's rotating public IPv6 is never published.
// That works at home and fails everywhere else. When it fails, this package
// supplies an alternate *physical* TCP destination while the *logical*
// hostname continues to drive TLS and HTTP.
//
// # Why the hook lives here
//
// Every control-plane TCP connection — both the pre-Noise "GET /key" fetch in
// control/controlclient and the Noise/ts2021 dial in control/controlhttp —
// bottoms out at tsdial.Dialer.SystemDial. Installing a wrapper around that one
// function therefore covers the whole control plane and nothing else.
//
// # Why TLS identity is preserved automatically
//
// Name resolution happens one layer ABOVE this code, in net/dnscache:
//
//   - dnscache resolves the hostname and calls the dial func with an IP
//     literal: fwd(ctx, network, net.JoinHostPort(ip.String(), port)).
//   - dnscache.TLSDialer then splits the ORIGINAL address (hostname:port),
//     takes whatever net.Conn the dial func returned, and does
//     cfg.ServerName = host before tls.Client(conn, cfg).
//   - ts2021 builds its request URLs from the configured server hostname.
//
// So this package only ever hands back a socket. SNI, TLS ServerName,
// certificate hostname verification and the HTTP Host header are all computed
// from the configured hostname, one layer up, and are structurally unreachable
// from here. Physical destination and TLS identity intentionally differ, and
// that difference is invisible to — and unmodifiable by — this code. Nothing
// here sets InsecureSkipVerify, pins a certificate, or touches a tls.Config.
//
// # Scope
//
// This affects the coordination-server dial only. WireGuard peer traffic never
// passes through tsdial.SystemDial (magicsock owns its own UDP sockets), and
// unrelated SystemDial users such as DERP and logtail are filtered out by the
// Fallback implementation, which returns "" for any address that is not one of
// the configured control server's own resolved addresses.
package privatediscovery

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"tailscale.com/net/netx"
	"tailscale.com/types/logger"
)

// Fallback is the Android side of the feature. It is implemented in Kotlin
// (see PrivateDiscovery.kt) and reached through the gomobile AppContext
// binding; libtailscale.AppContext satisfies it structurally.
//
// The Kotlin implementation owns all configuration, the shared secret, the
// authenticated HTTPS lookup, IPv6 validation, the cache and its expiry, rate
// limiting, and the decision of whether failedAddr even belongs to the
// configured coordination server.
//
// Contract:
//
//   - failedAddr is an "ip:port" literal whose dial just failed.
//   - allowLookup=false means "answer from cache only, never touch the network".
//   - allowLookup=true permits one fresh authenticated lookup, subject to the
//     implementation's own rate limiting.
//   - The return value is a replacement "ip:port" to dial, or "" for "not
//     applicable" / "unavailable". "" is not an error.
//   - Neither the returned string nor the returned error may ever contain the
//     shared secret or any other credential.
type Fallback interface {
	PrivateDiscoveryDialFallback(failedAddr string, allowLookup bool) (string, error)
}

// Dialer wraps a base dial func with the private-discovery fallback.
//
// The zero value is not usable; use New.
type Dialer struct {
	fb   Fallback
	logf logger.Logf

	// base is the dial func this wrapper falls back to and, on failure,
	// retries through. On Android it must be the netns dialer, because that
	// is what applies VpnService.protect()/bindSocketToNetwork() and so keeps
	// control-plane sockets out of the tunnel. The override dial deliberately
	// uses the same base, so the alternate socket is protected identically.
	base netx.DialFunc

	// bindToNetwork binds a socket to the underlying non-VPN network, or is nil
	// where that is not available. Binding to a concrete network is what makes
	// the override socket leave the device on the interface that can actually
	// reach the discovered address: an unbound socket on a phone with several
	// cellular PDNs may pick a source address belonging to the wrong one, which
	// looks exactly like an unreachable host.
	bindToNetwork func(fd int) error

	// mu guards sticky.
	mu sync.Mutex

	// sticky remembers, per failed address, a discovered address that has just
	// carried a working connection.
	//
	// The coordination client opens a fresh connection per request, and probes
	// more than one port in parallel. Re-deriving the fallback each time means
	// every one of those pays the full cost of failing the normal dial first,
	// which is enough to blow the client's own deadline: the key fetch would
	// succeed and the registration behind it would time out. Remembering a
	// known-good destination for a short window collapses that to a single
	// dial.
	sticky map[string]stickyEntry
}

// stickyEntry is a discovered address that recently worked, and when.
type stickyEntry struct {
	alt string
	at  time.Time
}

// stickyTTL bounds how long a discovered address is preferred over the normal
// path.
//
// Short on purpose. Preferring the override is only ever a latency
// optimisation, never a change of policy: when the window lapses the normal
// dial is tried first again, so returning home is noticed promptly rather than
// being masked by a cached decision.
const stickyTTL = 2 * time.Minute

// privateDialTimeout bounds the first attempt when the coordination server's
// hostname resolves to a private address.
//
// This is the difference between connecting in seconds and connecting in over
// a minute. A private destination that is not on the current network is
// usually black-holed rather than refused, so the connect runs to the kernel's
// full SYN-retry timeout — measured at 76s on cellular. At home the same dial
// completes in milliseconds, so the bound is never reached; away from home
// there is nothing to wait for, because that address cannot work.
//
// The value trades the away-from-home wait against the risk of giving up too
// early at home. A LAN answers in single-digit milliseconds, so this leaves
// roughly three orders of magnitude of headroom for a congested link or a
// radio waking from power-save. Tripping it at home is not harmful — the
// cached address still reaches the server, by hairpin — but it is wasteful,
// and if hairpinning were broken it would push a lookup request out from
// inside the home network, which this feature is meant to avoid.
//
// Deliberately not followed by an unbounded retry when no alternative works.
// Retrying would re-impose the full stall on precisely the case that is already
// failing, and the coordination client re-dials on its own schedule anyway, so
// each of its attempts gets a fresh 5s. The residual risk is a private network
// that legitimately needs more than 5s to accept a connection, which a LAN
// answering in milliseconds leaves a wide margin against.
const privateDialTimeout = 1500 * time.Millisecond

// New returns a Dialer that tries base first and only consults fb when base
// fails. fb may be nil, in which case the Dialer is a transparent pass-through.
func New(fb Fallback, logf logger.Logf, base netx.DialFunc, bindToNetwork func(fd int) error) *Dialer {
	if logf == nil {
		logf = logger.Discard
	}
	return &Dialer{fb: fb, logf: logf, base: base, bindToNetwork: bindToNetwork}
}

// DialContext implements netx.DialFunc.
//
// The ordering below is the whole feature:
//
//	PHASE 1  the normal, unmodified upstream dial. At home this succeeds and
//	         the lookup service is never contacted.
//	PHASE 2  on failure, a cached public IPv6 that is still within the
//	         configured max age.
//	PHASE 3  on further failure, one fresh authenticated lookup — which is why
//	         a dead cached address is not retried until it expires.
//
// At most one cached attempt and one refresh attempt happen per failed dial.
// There is no timer, no polling and no retry loop here; re-dials are driven by
// the existing controlclient reconnect logic.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// PHASE 0: a discovered address that worked moments ago, if any. This is
	// not a new policy — it is the outcome of a completed phase 1/2/3 cycle
	// being reused instead of re-derived for every connection.
	if alt, ok := d.stickyFor(addr); ok {
		if c, stickyErr := d.dialOverride(ctx, network, alt); stickyErr == nil {
			return c, nil
		}
		// It stopped working; forget it and fall through to the normal path.
		d.forgetSticky(addr)
		d.logf("private discovery: previously working override for %s failed; retrying normally", addr)
	}

	// PHASE 1.
	c, err := d.firstAttempt(ctx, network, addr, d.shouldBoundFirstAttempt(network, addr))
	if err == nil {
		return c, nil
	}
	// Deliberately logged for every failed dial, not just coordination-server
	// ones: when the fallback does not engage, this line and the reason below
	// are the only evidence of why. The address is a destination we already
	// tried, never the discovered one.
	d.logf("private discovery: dial of %s failed: %v", addr, err)
	if c, ok := d.dialFallback(ctx, network, addr); ok {
		return c, nil
	}
	// Always surface the original error. A fallback failure must never mask
	// why the normal connection failed.
	return nil, err
}

// shouldBoundFirstAttempt reports whether the first attempt should be given a
// short deadline rather than the kernel's.
//
// Only private destinations qualify, and only when a fallback exists to switch
// to. Public destinations — DERP, logtail, captive-portal probes — are left
// strictly alone, since shortening those would change behaviour for traffic
// this feature has no business touching.
func (d *Dialer) shouldBoundFirstAttempt(network, addr string) bool {
	if d.fb == nil || !strings.HasPrefix(network, "tcp") {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

func (d *Dialer) firstAttempt(ctx context.Context, network, addr string, bounded bool) (net.Conn, error) {
	if !bounded {
		return d.base(ctx, network, addr)
	}
	boundedCtx, cancel := context.WithTimeout(ctx, privateDialTimeout)
	defer cancel()
	return d.base(boundedCtx, network, addr)
}

// dialFallback reports whether an alternate destination worked.
func (d *Dialer) dialFallback(ctx context.Context, network, addr string) (net.Conn, bool) {
	if d.fb == nil {
		d.logf("private discovery: no fallback configured")
		return nil, false
	}
	// The control plane is TCP only.
	if !strings.HasPrefix(network, "tcp") {
		return nil, false
	}
	// dnscache resolves the coordination server's hostname before calling us,
	// so a control-plane dial always arrives here as an IP literal. Anything
	// else cannot be one, and we leave it alone.
	host, _, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		return nil, false
	}
	if _, parseErr := netip.ParseAddr(host); parseErr != nil {
		d.logf("private discovery: %s is not an IP literal; leaving it alone", addr)
		return nil, false
	}

	// PHASE 2: cached address only. No network activity, no lookup request.
	if c, ok := d.tryAlternate(ctx, network, addr, false); ok {
		return c, true
	}
	// PHASE 3: allow one fresh lookup. Reaching here means either there was no
	// usable cached address or the cached one just failed, so this is also the
	// path that makes a connection failure override the configured cache age.
	c, ok := d.tryAlternate(ctx, network, addr, true)
	if !ok {
		d.logf("private discovery: no alternate address available for %s", addr)
	}
	return c, ok
}

// altDialTimeout bounds an attempt against a discovered address.
//
// The address may be stale, or the home network may not accept inbound
// connections on that port at all, in which case the SYN is dropped and a bare
// connect would sit there for minutes — stalling the coordination connection
// behind a fallback that was only ever meant to be opportunistic. Failing fast
// lets phase 3 refresh a stale cached address, and otherwise returns the
// original error promptly.
const altDialTimeout = 10 * time.Second

// dialOverride connects to a discovered address, binding the socket to the
// underlying network when the host application can do so.
//
// Binding also provides the property VpnService.protect() would: a socket bound
// to a concrete non-VPN network does not re-enter the tunnel, so this cannot
// create a routing loop even once the VPN is up.
func (d *Dialer) dialOverride(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.bindToNetwork == nil {
		return d.base(ctx, network, addr)
	}
	dialer := &net.Dialer{
		Control: func(_, _ string, c syscall.RawConn) error {
			var bindErr error
			if err := c.Control(func(fd uintptr) {
				bindErr = d.bindToNetwork(int(fd))
			}); err != nil {
				return err
			}
			return bindErr
		},
	}
	return dialer.DialContext(ctx, network, addr)
}

func (d *Dialer) tryAlternate(ctx context.Context, network, addr string, allowLookup bool) (net.Conn, bool) {
	alt, err := d.fb.PrivateDiscoveryDialFallback(addr, allowLookup)
	if err != nil {
		// The Kotlin side is responsible for keeping credentials out of this
		// error; it reports categories and status codes, never headers.
		d.logf("private discovery: address lookup failed: %v", err)
		return nil, false
	}
	alt = strings.TrimSpace(alt)
	if alt == "" {
		// Not the coordination server, feature disabled, or nothing usable
		// cached. This is the common case and is intentionally silent.
		return nil, false
	}
	if alt == addr {
		// Nothing would change; don't burn a second identical attempt.
		return nil, false
	}
	if allowLookup {
		d.logf("private discovery: fetching updated public IPv6 and retrying the coordination connection")
	} else {
		d.logf("private discovery: normal coordination connection failed; attempting cached public IPv6")
	}
	// Deliberately never log alt: it is the home network's public IPv6, which
	// is precisely the value this feature exists to keep unpublished.
	// Log the shape of the attempt without the address: the port and family are
	// what diagnose a malformed target, and neither identifies the home network.
	if _, altPort, splitErr := net.SplitHostPort(alt); splitErr == nil {
		d.logf("private discovery: override target is network=%q port=%s literal-v6=%t",
			network, altPort, strings.HasPrefix(alt, "["))
	} else {
		d.logf("private discovery: override target is malformed")
	}

	altCtx, cancel := context.WithTimeout(ctx, altDialTimeout)
	defer cancel()
	c, dialErr := d.dialOverride(altCtx, network, alt)
	if dialErr != nil {
		// Report why, but never the address itself: a dial error embeds the
		// destination, which is the one value this feature exists to keep
		// unpublished. Redacting it keeps the errno, which is what diagnoses
		// routing versus refusal versus timeout.
		d.logf("private discovery: private IPv6 override connection failed: %s",
			strings.ReplaceAll(dialErr.Error(), alt, "<discovered>"))
		return nil, false
	}
	d.logf("private discovery: coordination connection established via private IPv6 override")
	d.rememberSticky(addr, alt)
	return c, true
}

func (d *Dialer) stickyFor(addr string) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.sticky[addr]
	if !ok {
		return "", false
	}
	if time.Since(e.at) > stickyTTL || time.Since(e.at) < 0 {
		delete(d.sticky, addr)
		return "", false
	}
	return e.alt, true
}

func (d *Dialer) rememberSticky(addr, alt string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sticky == nil {
		d.sticky = make(map[string]stickyEntry)
	}
	d.sticky[addr] = stickyEntry{alt: alt, at: time.Now()}
}

func (d *Dialer) forgetSticky(addr string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.sticky, addr)
}
