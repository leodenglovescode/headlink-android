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
}

// New returns a Dialer that tries base first and only consults fb when base
// fails. fb may be nil, in which case the Dialer is a transparent pass-through.
func New(fb Fallback, logf logger.Logf, base netx.DialFunc) *Dialer {
	if logf == nil {
		logf = logger.Discard
	}
	return &Dialer{fb: fb, logf: logf, base: base}
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
	// PHASE 1.
	c, err := d.base(ctx, network, addr)
	if err == nil {
		return c, nil
	}
	if c, ok := d.dialFallback(ctx, network, addr); ok {
		return c, nil
	}
	// Always surface the original error. A fallback failure must never mask
	// why the normal connection failed.
	return nil, err
}

// dialFallback reports whether an alternate destination worked.
func (d *Dialer) dialFallback(ctx context.Context, network, addr string) (net.Conn, bool) {
	if d.fb == nil {
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
		return nil, false
	}

	// PHASE 2: cached address only. No network activity, no lookup request.
	if c, ok := d.tryAlternate(ctx, network, addr, false); ok {
		return c, true
	}
	// PHASE 3: allow one fresh lookup. Reaching here means either there was no
	// usable cached address or the cached one just failed, so this is also the
	// path that makes a connection failure override the configured cache age.
	return d.tryAlternate(ctx, network, addr, true)
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
	c, dialErr := d.base(ctx, network, alt)
	if dialErr != nil {
		d.logf("private discovery: private IPv6 override connection failed")
		return nil, false
	}
	d.logf("private discovery: coordination connection established via private IPv6 override")
	return c, true
}
