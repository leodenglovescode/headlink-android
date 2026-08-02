// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package privatediscovery

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/net/dnscache"
)

// fakeFallback is a scriptable stand-in for the Kotlin implementation.
type fakeFallback struct {
	mu sync.Mutex

	// answers maps allowLookup -> address to return.
	cached    string
	refreshed string
	err       error

	calls  []fakeCall
	closed bool
}

type fakeCall struct {
	addr        string
	allowLookup bool
}

func (f *fakeFallback) PrivateDiscoveryDialFallback(failedAddr string, allowLookup bool) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fakeCall{addr: failedAddr, allowLookup: allowLookup})
	if f.err != nil {
		return "", f.err
	}
	if allowLookup {
		return f.refreshed, nil
	}
	return f.cached, nil
}

func (f *fakeFallback) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeFallback) callsSnapshot() []fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeCall(nil), f.calls...)
}

// recordingBase is a base dial func that succeeds only for the addresses in ok.
//
// By default a "successful" dial yields an in-memory pipe, which is enough for
// the ordering tests. Set real to make successful dials open an actual socket,
// which the TLS-identity test needs.
type recordingBase struct {
	mu    sync.Mutex
	ok    map[string]bool
	real  bool
	dials []string
}

func newRecordingBase(ok ...string) *recordingBase {
	m := map[string]bool{}
	for _, a := range ok {
		m[a] = true
	}
	return &recordingBase{ok: m}
}

func (r *recordingBase) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	r.mu.Lock()
	r.dials = append(r.dials, addr)
	allowed := r.ok[addr]
	real := r.real
	r.mu.Unlock()
	if !allowed {
		return nil, errors.New("connect: connection refused")
	}
	if real {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	c1, _ := net.Pipe()
	return c1, nil
}

func (r *recordingBase) dialsSnapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.dials...)
}

// Requirement 1 & 2: when the normal path works, upstream behaviour is
// unchanged and the lookup service is never consulted.
func TestNormalDialSucceedsFallbackUntouched(t *testing.T) {
	fb := &fakeFallback{cached: "[2001:db8::1]:443", refreshed: "[2001:db8::2]:443"}
	base := newRecordingBase("192.168.3.61:443")
	d := New(fb, t.Logf, base.dial, nil)

	c, err := d.DialContext(context.Background(), "tcp", "192.168.3.61:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	c.Close()

	if got := fb.callCount(); got != 0 {
		t.Errorf("fallback consulted %d times on a successful dial; want 0", got)
	}
	if got := base.dialsSnapshot(); len(got) != 1 || got[0] != "192.168.3.61:443" {
		t.Errorf("base dials = %v; want exactly one dial of the original address", got)
	}
}

// Requirement 3: normal path fails, a valid cached IPv6 is used, and no
// refresh is requested.
func TestCachedAddressUsedOnFailure(t *testing.T) {
	fb := &fakeFallback{cached: "[2001:db8::1]:443"}
	base := newRecordingBase("[2001:db8::1]:443")
	d := New(fb, t.Logf, base.dial, nil)

	c, err := d.DialContext(context.Background(), "tcp", "192.168.3.61:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	c.Close()

	calls := fb.callsSnapshot()
	if len(calls) != 1 {
		t.Fatalf("fallback calls = %d; want 1", len(calls))
	}
	if calls[0].allowLookup {
		t.Error("a fresh lookup was permitted even though the cached address worked")
	}
	if calls[0].addr != "192.168.3.61:443" {
		t.Errorf("fallback saw addr %q; want the failed original address", calls[0].addr)
	}
}

// Requirements 4 & 5: with nothing usable cached — or with a cached address
// that fails to connect — exactly one refresh attempt follows.
func TestRefreshAfterCachedAddressFails(t *testing.T) {
	fb := &fakeFallback{cached: "[2001:db8::1]:443", refreshed: "[2001:db8::2]:443"}
	base := newRecordingBase("[2001:db8::2]:443")
	d := New(fb, t.Logf, base.dial, nil)

	c, err := d.DialContext(context.Background(), "tcp", "192.168.3.61:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	c.Close()

	calls := fb.callsSnapshot()
	if len(calls) != 2 {
		t.Fatalf("fallback calls = %d; want 2 (cached then refresh)", len(calls))
	}
	if calls[0].allowLookup || !calls[1].allowLookup {
		t.Errorf("call order wrong: allowLookup flags = %v, %v; want false, true",
			calls[0].allowLookup, calls[1].allowLookup)
	}
	wantDials := []string{"192.168.3.61:443", "[2001:db8::1]:443", "[2001:db8::2]:443"}
	if got := base.dialsSnapshot(); !equalStrings(got, wantDials) {
		t.Errorf("base dials = %v; want %v", got, wantDials)
	}
}

// Requirement 22: a bad refreshed address does not loop. One cached attempt
// plus one refresh attempt, then the ORIGINAL error is surfaced.
func TestNoInfiniteRetryAndOriginalErrorPreserved(t *testing.T) {
	fb := &fakeFallback{cached: "[2001:db8::1]:443", refreshed: "[2001:db8::2]:443"}
	base := newRecordingBase() // nothing succeeds
	d := New(fb, t.Logf, base.dial, nil)

	_, err := d.DialContext(context.Background(), "tcp", "192.168.3.61:443")
	if err == nil {
		t.Fatal("DialContext succeeded; want failure")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("err = %v; want the original base-dial error", err)
	}
	if got := fb.callCount(); got != 2 {
		t.Errorf("fallback calls = %d; want exactly 2", got)
	}
	if got := len(base.dialsSnapshot()); got != 3 {
		t.Errorf("base dials = %d; want exactly 3 (original + cached + refreshed)", got)
	}
}

// Requirement 19 (scope): addresses the Kotlin side does not recognise as the
// coordination server — DERP, logtail, captive-portal probes, anything else —
// get "" and are left completely alone.
func TestUnrelatedTrafficUnaffected(t *testing.T) {
	// Empty cached/refreshed models the Kotlin side answering "not the
	// configured control server".
	fb := &fakeFallback{}
	base := newRecordingBase()
	d := New(fb, t.Logf, base.dial, nil)

	for _, addr := range []string{
		"192.0.2.10:443",  // DERP-ish
		"198.51.100.7:80", // logtail-ish
		"203.0.113.1:41641",
	} {
		if _, err := d.DialContext(context.Background(), "tcp", addr); err == nil {
			t.Fatalf("dial %s unexpectedly succeeded", addr)
		}
	}
	// Only the three original dials; no override was ever attempted.
	if got := base.dialsSnapshot(); len(got) != 3 {
		t.Errorf("base dials = %v; want only the 3 original attempts", got)
	}
}

// The data-plane invariant, expressed as far as this layer can: non-TCP dials
// (magicsock/WireGuard UDP, DNS) never reach the fallback at all.
func TestNonTCPNeverConsultsFallback(t *testing.T) {
	fb := &fakeFallback{cached: "[2001:db8::1]:443", refreshed: "[2001:db8::1]:443"}
	base := newRecordingBase()
	d := New(fb, t.Logf, base.dial, nil)

	for _, network := range []string{"udp", "udp4", "udp6", "unix"} {
		if _, err := d.DialContext(context.Background(), network, "192.168.3.61:443"); err == nil {
			t.Fatalf("dial %s unexpectedly succeeded", network)
		}
	}
	if got := fb.callCount(); got != 0 {
		t.Errorf("fallback consulted %d times for non-TCP dials; want 0", got)
	}
}

// A hostname (rather than an IP literal) cannot be a control-plane dial,
// because dnscache always resolves before calling us.
func TestHostnameAddressNeverConsultsFallback(t *testing.T) {
	fb := &fakeFallback{cached: "[2001:db8::1]:443"}
	base := newRecordingBase()
	d := New(fb, t.Logf, base.dial, nil)

	if _, err := d.DialContext(context.Background(), "tcp", "derp1.example.com:443"); err == nil {
		t.Fatal("dial unexpectedly succeeded")
	}
	if got := fb.callCount(); got != 0 {
		t.Errorf("fallback consulted %d times for a hostname dial; want 0", got)
	}
}

// A fallback that errors out must fail closed: no crash, no insecure retry,
// original error preserved.
func TestFallbackErrorFailsClosed(t *testing.T) {
	fb := &fakeFallback{err: errors.New("lookup failed: HTTP 401")}
	base := newRecordingBase()
	d := New(fb, t.Logf, base.dial, nil)

	_, err := d.DialContext(context.Background(), "tcp", "192.168.3.61:443")
	if err == nil {
		t.Fatal("DialContext succeeded; want failure")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("err = %v; want the original base-dial error", err)
	}
}

// A nil Fallback (feature never wired up) is a transparent pass-through.
func TestNilFallbackIsPassThrough(t *testing.T) {
	base := newRecordingBase("192.168.3.61:443")
	d := New(nil, t.Logf, base.dial, nil)

	c, err := d.DialContext(context.Background(), "tcp", "192.168.3.61:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	c.Close()
}

// Requirement 18, the critical one.
//
// This proves end-to-end, against the real tailscale.com dnscache/TLS stack,
// that redirecting the socket to a different IP does NOT redirect TLS identity:
//
//	physical TCP destination : 127.0.0.1:<port>   (supplied by the fallback)
//	logical hostname         : headscale.test
//	SNI                      : headscale.test     (asserted server-side)
//	certificate verification : headscale.test     (a cert for any other name
//	                                               would fail the handshake)
//
// DNS is rigged to return 127.0.0.2, where nothing is listening, so the normal
// path fails exactly as it does when the user is away from home.
func TestTLSIdentityFollowsHostnameNotDialedIP(t *testing.T) {
	const hostname = "headscale.test"

	caCert, caPool, serverCert := mustIssueCert(t, hostname)
	_ = caCert

	var (
		sniMu   sync.Mutex
		gotSNI  string
		sniSeen bool
	)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	tlsLn := tls.NewListener(ln, &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sniMu.Lock()
			gotSNI = chi.ServerName
			sniSeen = true
			sniMu.Unlock()
			return &serverCert, nil
		},
	})
	go func() {
		for {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func() {
				// Force the handshake, then hold the conn briefly.
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.HandshakeContext(context.Background())
				}
				time.Sleep(50 * time.Millisecond)
				c.Close()
			}()
		}
	}()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	realAddr := net.JoinHostPort("127.0.0.1", port)
	deadAddr := net.JoinHostPort("127.0.0.2", port)

	// The fallback stands in for "the lookup returned the current public
	// address"; here that address is simply where the server really is.
	fb := &fakeFallback{cached: realAddr}
	base := newRecordingBase(realAddr) // 127.0.0.2 is NOT dialable
	base.real = true                   // this test needs a genuine TCP socket
	d := New(fb, t.Logf, base.dial, nil)

	// Exactly the wiring control/controlhttp uses: a dnscache.Resolver pinned
	// to a single host, wrapped by dnscache.TLSDialer.
	resolver := &dnscache.Resolver{
		SingleHost:             hostname,
		SingleHostStaticResult: []netip.Addr{netip.MustParseAddr("127.0.0.2")},
		Logf:                   t.Logf,
	}
	tlsDial := dnscache.TLSDialer(d.DialContext, resolver, &tls.Config{
		RootCAs: caPool,
		// NOTE: ServerName is intentionally left empty. dnscache fills it in
		// from the hostname half of the address below. If this feature could
		// leak the dialed IP into TLS identity, it would show up right here.
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := tlsDial(ctx, "tcp", net.JoinHostPort(hostname, port))
	if err != nil {
		t.Fatalf("TLS dial through the private-discovery override failed: %v", err)
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		t.Fatalf("got %T; want *tls.Conn", conn)
	}
	state := tlsConn.ConnectionState()

	if state.ServerName != hostname {
		t.Errorf("client TLS ServerName = %q; want %q", state.ServerName, hostname)
	}
	if !state.HandshakeComplete {
		t.Error("handshake did not complete")
	}
	// Certificate verification ran against the hostname, not the IP literal:
	// VerifiedChains is only populated when verification succeeded, and the
	// certificate carries no IP SAN at all.
	if len(state.VerifiedChains) == 0 {
		t.Error("certificate was not verified")
	}
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		if err := leaf.VerifyHostname(hostname); err != nil {
			t.Errorf("leaf does not verify against %q: %v", hostname, err)
		}
		if len(leaf.IPAddresses) != 0 {
			t.Errorf("test cert unexpectedly has IP SANs %v", leaf.IPAddresses)
		}
	}

	sniMu.Lock()
	seen, sni := sniSeen, gotSNI
	sniMu.Unlock()
	if !seen {
		t.Fatal("server never saw a ClientHello")
	}
	if sni != hostname {
		t.Errorf("SNI seen by server = %q; want %q", sni, hostname)
	}

	// And confirm the socket really did go somewhere other than DNS said.
	dials := base.dialsSnapshot()
	if len(dials) < 2 || dials[0] != deadAddr {
		t.Fatalf("base dials = %v; want the DNS answer %s first", dials, deadAddr)
	}
	if dials[len(dials)-1] != realAddr {
		t.Errorf("final physical destination = %q; want the override %q", dials[len(dials)-1], realAddr)
	}
}

func mustIssueCert(t *testing.T, hostname string) (*x509.Certificate, *x509.CertPool, tls.Certificate) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "headlink test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// Deliberately no IPAddresses: the certificate is valid for the
		// hostname only, so the handshake can only succeed if verification
		// used the hostname rather than the IP we actually dialed.
		DNSNames: []string{hostname},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	return caCert, pool, tls.Certificate{
		Certificate: [][]byte{leafDER},
		PrivateKey:  leafKey,
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The coordination client opens a connection per request and probes several
// ports at once. Once an override has worked, later dials must reuse it rather
// than paying the full failure cycle again — that repeated cost is what pushed
// the client past its own deadline, so a working key fetch was followed by a
// registration that timed out.
func TestWorkingOverrideIsReusedForLaterDials(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	// The normal address always fails; the discovered one is a real listener.
	base := newRecordingBase(ln.Addr().String())
	base.real = true
	fb := &fakeFallback{cached: ln.Addr().String(), refreshed: ln.Addr().String()}
	d := New(fb, t.Logf, base.dial, nil)

	for i := 0; i < 3; i++ {
		c, err := d.DialContext(context.Background(), "tcp", "192.168.3.61:5007")
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		c.Close()
	}

	// Only the first dial should have consulted the fallback or retried the
	// normal path; the two after it go straight to the remembered address.
	if got := fb.callCount(); got != 1 {
		t.Errorf("fallback consulted %d times, want 1", got)
	}
	normalAttempts := 0
	for _, a := range base.dialsSnapshot() {
		if a == "192.168.3.61:5007" {
			normalAttempts++
		}
	}
	if normalAttempts != 1 {
		t.Errorf("normal path attempted %d times, want 1", normalAttempts)
	}
}

// A remembered override that stops working must not strand the caller: the
// normal path has to be retried and the original error surfaced.
func TestStickyOverrideIsAbandonedWhenItStopsWorking(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	base := newRecordingBase(ln.Addr().String())
	base.real = true
	fb := &fakeFallback{cached: ln.Addr().String(), refreshed: ln.Addr().String()}
	d := New(fb, t.Logf, base.dial, nil)

	c, err := d.DialContext(context.Background(), "tcp", "192.168.3.61:5007")
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	c.Close()

	// The discovered address goes away, and nothing new is on offer.
	ln.Close()
	base.mu.Lock()
	base.ok = map[string]bool{}
	base.mu.Unlock()
	fb.mu.Lock()
	fb.cached, fb.refreshed = "", ""
	fb.mu.Unlock()

	if _, err := d.DialContext(context.Background(), "tcp", "192.168.3.61:5007"); err == nil {
		t.Fatal("expected failure once neither path works")
	} else if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("want the original error surfaced, got %v", err)
	}
}

// A private address that is black-holed rather than refused must not hold the
// coordination connection hostage for the kernel's full SYN-retry timeout —
// measured at 76s on cellular, which is the whole "stuck on Starting..."
// symptom. Public destinations must keep their normal timing.
func TestBlackHoledPrivateAddressDoesNotStallTheDial(t *testing.T) {
	blackhole := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == "[2001:db8::1]:5007" {
			c, _ := net.Pipe()
			return c, nil
		}
		<-ctx.Done() // never answers, like a dropped SYN
		return nil, ctx.Err()
	}
	fb := &fakeFallback{cached: "[2001:db8::1]:5007"}
	d := New(fb, t.Logf, blackhole, nil)

	start := time.Now()
	c, err := d.DialContext(context.Background(), "tcp", "192.168.3.61:5007")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()
	if elapsed := time.Since(start); elapsed > privateDialTimeout+2*time.Second {
		t.Errorf("took %v; the first attempt should be bounded to %v", elapsed, privateDialTimeout)
	}
}

// The bound applies only to private destinations. DERP and similar public
// traffic must keep the caller's own deadline.
func TestPublicDestinationsAreNotBounded(t *testing.T) {
	fb := &fakeFallback{}
	d := New(fb, t.Logf, newRecordingBase().dial, nil)
	if d.shouldBoundFirstAttempt("tcp", "192.168.3.61:5007") != true {
		t.Error("a private address should be bounded")
	}
	for _, addr := range []string{"1.2.3.4:443", "[2606:4700::1]:443", "[2409:8a00::1]:5007"} {
		if d.shouldBoundFirstAttempt("tcp", addr) {
			t.Errorf("%s is public and must not be bounded", addr)
		}
	}
	if d.shouldBoundFirstAttempt("udp", "192.168.3.61:5007") {
		t.Error("non-TCP must not be bounded")
	}
}
