# Private Headscale IPv6 Discovery

A Headlink-only feature. It gives the app an application-local `/etc/hosts` override for the
coordination server, and nothing else.

## Why it exists

The Headscale server sits on a home network that has:

* no usable public IPv4,
* a working but **rotating** public IPv6,
* a hostname with a publicly trusted TLS certificate.

That hostname deliberately resolves to the server's **private LAN address** in public DNS, so the
home network's real public IPv6 is never published in DNS, DoH/DoT answers, certificate
transparency logs as an IP SAN, or any anonymously queryable API.

At home that works. Away from home the LAN address is unreachable and the control connection dies.

On macOS the fix is one line in `/etc/hosts`:

```
2409:8a00:1234:5678::abcd  headscale.example
```

Android cannot do that without root, and the VPN slot is already taken by Tailscale itself, so the
equivalent has to live inside the app. This feature is that equivalent — no more, no less.

## What it is not

It is **not** a proxy, a relay, a tunnel, or a second VPN. Specifically it does not do, and must
never grow into, any of: HTTP proxying of Headscale, SOCKS, HTTP CONNECT, WireGuard-over-anything,
a TCP/UDP relay, a custom DERP, device-wide DNS interception, custom DoH/DoT, certificate pinning,
or `InsecureSkipVerify`.

The lookup endpoint answers exactly one question — "what is the current public IPv6?" — and carries
no Tailscale traffic of any kind.

## Architecture

```
Kotlin                                        Go (libtailscale)
──────                                        ─────────────────
PrivateDiscovery.dialFallback()   <────────   privatediscovery.Dialer.DialContext
  settings, secure token,          AppContext   wraps the netns dialer, which is
  HTTPS lookup, IPv6 validation,   binding      installed as tsdial.Dialer.SystemDial
  cache, back-off, control-host
  matching
```

### The Go hook

`tsdial.Dialer.SystemDial` is the single funnel every coordination-server TCP connection passes
through:

```
LocalBackend.Start
  └─ controlclient.NewDirect(Options{Dialer: b.Dialer(), …})
       ├─ GET /key  : tr.DialContext / tr.DialTLSContext = dnscache.{Dialer,TLSDialer}(Dialer.SystemDial, …)
       └─ Noise     : ts2021.NewClient → controlhttp.Dialer{Dialer: Dialer.SystemDial}
                        → tr.DialContext / tr.DialTLSContext = dnscache.{Dialer,TLSDialer}(…)
```

`libtailscale/backend.go` builds that dialer with
`tsdial.NewFromFuncForDebug(logf, privatediscovery.New(appCtx, logf, netns.NewDialer(...).DialContext).DialContext)`.

Two consequences worth remembering:

1. **The base dial must be the netns dialer.** A `Dialer` built this way bypasses tsdial's own lazy
   netns dialer, and netns is what applies `VpnService.protect()` / `bindSocketToNetwork()`. The
   override dial uses the same base, so the alternate socket is protected identically and never
   loops back into the tunnel.
2. **`tsdial.NewFromFuncForDebug` is an unstable upstream seam.** It is exported and, unlike
   `SetSystemDialerForTest`, is not gated behind `testenv.AssertInTest()` — but the name says
   "ForDebug", so upstream does not treat it as API. See "Rebasing" below.

## TLS: why the certificate identity is untouched

This is the part that matters most, and it is enforced by structure rather than by care.

Name resolution happens one layer **above** the dial func, inside `tailscale.com/net/dnscache`:

* `dnscache.dialOne` calls the dial func with an **IP literal**:
  `fwd(ctx, network, net.JoinHostPort(ip.String(), port))`.
* `dnscache.TLSDialer` splits the **original** `hostname:port` address, takes whatever `net.Conn`
  the dial func returned, then sets `cfg.ServerName = host` and calls `tls.Client(conn, cfg)`.
* `ts2021.Client.DoWithBody` builds request URLs as `"https://" + host + path`.

So with `https://headscale.example` configured and `2409:8a00:1234:5678::abcd` discovered:

| | |
| --- | --- |
| physical TCP destination | `[2409:8a00:1234:5678::abcd]:443` |
| logical hostname | `headscale.example` |
| TLS SNI | `headscale.example` |
| TLS ServerName | `headscale.example` |
| certificate verification | `headscale.example` |
| HTTP Host | `headscale.example` |

The feature hands back a socket and nothing else. It never sees, constructs, or mutates a
`tls.Config`; it cannot set `InsecureSkipVerify`, pin a certificate, or verify against an IP
literal, because none of those things are reachable from where it sits.

`libtailscale/privatediscovery/privatediscovery_test.go` proves this end-to-end against the real
`dnscache` stack: a server holding a certificate valid for `headscale.test` **and no IP SANs** is
reached over a socket pointed at a different IP, and the test asserts the SNI seen by the server,
the client's `ServerName`, and that the chain verified.

## Connection algorithm

With the feature **disabled**, `PrivateDiscovery.dialFallback` returns `""` immediately and
behaviour is identical to upstream: no lookup requests, no alternate dialing.

With it **enabled**:

**Phase 1 — normal connection.** The ordinary dial runs first, unchanged. At home
`headscale.example → 192.168.3.61` connects and the lookup endpoint is never contacted.

**Phase 2 — cached address.** If phase 1 fails, and the failed IP is one of the control hostname's
own resolved addresses, and a cached IPv6 exists that is within the configured max age, dial
`[cached]:<same port>`.

**Phase 3 — refresh.** If there was nothing usable cached, or the cached address also failed, do
one authenticated lookup, cache the result, and dial it. **A connection failure always overrides
the configured cache age** — a dead address is never retried just because it is technically young.

If the lookup itself fails, an expired cached address is offered as a last resort; it may still be
correct, and trying it costs one TCP connect.

At most one cached attempt and one refresh attempt happen per failed dial. Whatever happens, the
**original** error is what surfaces, so a fallback failure never masks the real reason.

## Timing

The ordering above is correct but was, on its own, unusably slow. Three properties of the real
control plane had to be accounted for, each found by tracing an actual connection from cellular.

**The first attempt is bounded to 1.5s when the destination is a private address.** The
coordination hostname resolves to a LAN address by design. Away from home that address is
black-holed rather than refused, so the connect runs to the kernel's full SYN-retry timeout —
76 seconds, measured — before the fallback gets a turn. A LAN answers in single-digit
milliseconds, so the bound is never reached at home. It applies only to private destinations and
only when a fallback exists; DERP, logtail and probe traffic keep the caller's own deadline. There
is deliberately no unbounded retry when nothing works, since that would re-impose the stall on the
case already failing, and the coordination client re-dials on its own schedule anyway.

**A discovered address that works is reused for two minutes.** The coordination client opens a new
connection per request and probes several ports in parallel. Re-deriving the fallback for each one
compounded until the client's own deadline expired: the control key fetch would succeed and the
registration immediately behind it would time out. The window is short on purpose — preferring the
override is a latency optimisation, never a change of policy, so returning home is noticed promptly
rather than masked by a cached decision. A remembered address that stops working is dropped at once
and the normal path resumes.

**Only the coordination server's own port is eligible.** The client also probes port 80 for the
plaintext upgrade path. Nothing listens there, so every override offered for it was a dial that
could not succeed while still consuming the shared deadline.

Override sockets are bound to the underlying non-VPN network through the host application's
existing hook. Binding to a concrete network also keeps the socket out of the tunnel, which is the
property `VpnService.protect()` would provide but which is unavailable during login, before the VPN
service exists.

## Settings

Settings → Private Headscale IPv6 Discovery.

| Setting | Default | Notes |
| --- | --- | --- |
| Enable private IPv6 discovery | Off | Off means byte-for-byte upstream behaviour |
| Lookup URL | empty | HTTPS only, trimmed, validated |
| Auth header name | `X-Sync-Secret` | Any valid HTTP header name; use `Authorization` for bearer auth |
| Client certificate | none | PKCS#12 bundle, imported via the document picker; only needed for mutual-TLS endpoints |
| Bundle passphrase | empty | Masked; the bundle is stored only once it opens successfully |
| Extra CA certificate | none | PEM; trusted **in addition to** the system anchors |
| Shared secret | empty | Masked; show/hide toggle; sent verbatim as the header value |
| Cache max age | 24 hours | Minutes / Hours / Days / **Only on failure**; minimum 5 minutes |
| Request timeout | 10 seconds | 2–60; applies **only** to the lookup request |

Buttons: **Test Lookup** (runs a lookup, reports the result, leaves the cache alone), **Refresh
Now** (runs a lookup and replaces the cache), **Clear Cached Address** (removes only the cached
address and timestamp — the URL, secret, and timing settings are kept; confirmed by a dialog).

Status shows the cached IPv6, the last successful lookup time, the cache status
(Valid / Expired / Empty), and the last lookup result. Never the secret.

The existing coordination-server URL remains authoritative. There is no second hostname field; the
scheme, hostname, port, Host header, SNI and certificate identity all come from it, and this
feature contributes only a physical IP.

## Lookup API contract

```
GET <configured lookup URL>
<configured auth header>: <configured secret>
Accept: application/json, text/plain
```

The secret is sent verbatim as the value of a single configurable header. This suits a minimal
nginx `location` block, which can check one header directly:

```nginx
location = /ip {
    if ($http_x_sync_secret != "…") { return 403 '{"error":"forbidden"}'; }
    default_type application/json;
    alias /etc/ssl/example/server_ipv6.json;
    add_header Cache-Control "no-store";
}
```

Standard bearer auth is the same mechanism with different values: set the header name to
`Authorization` and the secret to `Bearer <token>`. The two are equivalent here — the client sends
the secret in exactly one header, to exactly one origin, over TLS, and never through a redirect.
A custom header is *not* stripped automatically by HTTP clients on a cross-origin redirect the way
`Authorization` is, which is precisely why redirects are refused outright rather than followed.

Response: `200` with either a bare IPv6 address as plain text,

```
2409:8a00:1234:5678::abcd
```

or a small JSON document containing one:

```json
{"ipv6": "2409:8a00:1234:5678::abcd"}
```

The JSON form is read without a JSON library and without depending on the field name: every string
*value* in the document is tried, and the first one that passes full address validation wins, so a
schema change on the server does not break the client. Nothing about validation is relaxed for JSON
— candidates go through exactly the same checks as a plain-text body.

Surrounding whitespace, CR and LF are trimmed. At most 2048 bytes of body are read, and at most 64
strings from a JSON document are examined.

Rejected: IPv4, IPv4-mapped/compatible, unspecified (`::`), loopback (`::1`), multicast (`ff00::/8`),
link-local (`fe80::/10`), site-local (`fec0::/10`), unique-local (`fc00::/7`), addresses with a zone
identifier, and anything unparseable.

## Mutual TLS

Some endpoints require a client certificate as well as the header secret. The one this feature was
written against does: its edge advertises

```
Acceptable client certificate CA names
C=XX, O=Example, OU=SyncCA, CN=Example Sync Root CA
```

and drops any connection that does not present a matching certificate. Because TLS 1.3 lets the
client finish the handshake before the server evaluates its certificate, that failure looks like a
successful handshake followed by a dead connection — `curl` reports `Empty reply from server` on
HTTP/1.1 and `Error in the HTTP2 framing layer` on h2, with no status line either way. Worth
recognising: it is easily mistaken for a server-side crash or an origin-pull failure.

`Mtls` handles this, and every part of it is additive:

* The client certificate is **presented**, which cannot weaken anything.
* An extra CA is **added to** the platform trust anchors, never substituted for them. The platform
  manager is consulted first and its verdict alone is sufficient, so publicly trusted endpoints
  validate exactly as they did before.
* Hostname verification is untouched; `HttpsURLConnection` still performs it. There is a test
  asserting a certificate valid for another name is still rejected.
* There is deliberately no "trust everything" path in the file. Unusable material produces a clean
  `CLIENT_CERT_ERROR`, never a downgrade.

The socket factory is set on the single lookup `HttpsURLConnection` — never on
`HttpsURLConnection.setDefaultSSLSocketFactory` — so no other connection in the process is affected,
least of all the coordination-server connection, which the Tailscale core makes and which never sees
any of this.

The bundle and its passphrase are stored with the same Keystore-backed AES-256-GCM wrapping as the
shared secret. The bundle contains a private key, so it is at least as sensitive.

### Regenerating the test fixtures

`src/test/resources/mtls/` holds a throwaway PKI so the tests can perform a real handshake against a
listener that requires client authentication:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 7300 \
  -subj "/O=Headlink Test/CN=Headlink Test Root CA"
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/O=Headlink Test/CN=localhost"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt \
  -days 7300 -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr \
  -subj "/O=Headlink Test/CN=headlink-test-client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt \
  -days 7300 -extfile <(printf "extendedKeyUsage=clientAuth\n")
openssl pkcs12 -export -in client.crt -inkey client.key -certfile ca.crt -out client.p12 \
  -passout pass:testpass -name headlink-test-client
openssl pkcs12 -export -in server.crt -inkey server.key -certfile ca.crt -out server.p12 \
  -passout pass:testpass -name headlink-test-server
```

## Security model

* **HTTPS only.** A plaintext URL is refused at validation time and again before the request is
  built, so the secret can never go over cleartext.
* **Ordinary certificate validation** on the lookup connection. Nothing is bypassed or pinned.
* **No redirects.** `instanceFollowRedirects = false`, and a 3xx is a clean failure. The secret
  header can therefore never be replayed to another origin.
* **The header name is validated** as an RFC 7230 token before use, so a malformed setting cannot
  inject additional headers into the one request that carries the secret.
* **The secret is sent to the configured lookup origin only**, on that one request.
* **The secret is never logged**, never in an exception message, never in a `LookupOutcome`, never in
  the UI, never in a bug report. `PrivateDiscoveryConfig.toString()` renders it as `<redacted>`, and
  URLs are logged through `redactUrl()`, which strips query and fragment (some deployments put
  secrets in query parameters).
* **The client certificate and its passphrase** get the same treatment as the secret: encrypted at
  rest, redacted in every rendering, never logged, and never shown in the UI beyond the
  certificate's subject and expiry.
* **Storage.** The secret is encrypted with AES-256-GCM under a non-exportable key generated in the
  Android Keystore (`KeystoreTokenStore`); only `Base64(iv‖ciphertext‖tag)` is written to
  SharedPreferences. This uses the platform Keystore directly rather than the now-deprecated
  `EncryptedSharedPreferences`. No user authentication is required to use the key, because the VPN
  service must be able to refresh while the screen is locked. See "What the secret is protected
  against" below for the limits of this.
* **Only the address and its timestamp are cached.** Response bodies are not persisted.
* **Failures never fall back to anything insecure.** Every error path ends in "no alternate
  address", and the original dial error is returned.

### What the secret is protected against

Being honest about the boundary matters more than the word "encrypted".

**Protected against:**

* **Other apps on the device.** The ciphertext lives in this app's private data directory, which the
  Android sandbox makes unreadable by any other app's UID.
* **Offline extraction of the file.** Keys generated in the Android Keystore cannot be exported —
  the raw key material never enters app memory, and on any device with a TEE it never leaves secure
  hardware. Copying the SharedPreferences file to another device yields ciphertext that nothing can
  decrypt.
* **Backups.** `android:allowBackup="false"` in the manifest, so the ciphertext never reaches a
  cloud or adb backup — and even if it did, the key would not be in it.
* **Logs, bug reports and the UI.** The secret is never written to any of them, and the field is
  masked unless explicitly revealed.

**Not protected against:**

* **Root.** An attacker with root can execute as this app's UID, and the Keystore will then decrypt
  on request — the key cannot be *extracted*, but it can be *used*. This is inherent to any
  credential an unattended background service must be able to use while the screen is locked;
  requiring authentication per use would break exactly the case this feature exists for.
* **A debuggable build plus ADB access.** Debug APKs are `android:debuggable="true"`, which lets
  anyone with USB debugging enabled and the device unlocked run `run-as dev.leodeng.headlink` and
  reach both the preferences file and the decryption path. A release build closes this; a debug
  build on a device handed to someone else does not.

**Consequences if it does leak.** The secret authorizes reading exactly one value: the home
network's current public IPv6. It grants no access to Headscale, to the tailnet, or to any node.
Rotating it is a one-line change in the nginx `if` plus a re-entry in the settings screen, so treat
it as rotatable rather than permanent, and prefer a value used for nothing else.

Acceptable log lines look like `normal coordination connection failed; offering cached public IPv6`
and `public IPv6 refreshed successfully`. The discovered address itself is deliberately **not**
logged — it is the value the whole feature exists to keep unpublished.

## Battery and background behaviour

There is no WorkManager job, no alarm, no timer, and no polling anywhere in this feature. Nothing
is scheduled. The only thing that can cause a lookup is a coordination connection that has just
failed, which is also why "cache max age" means "refresh the next time a connection actually needs
it", not "wake up every N hours".

Reconnect storms are contained by a minimum 30-second spacing between lookups, growing exponentially
with consecutive failures to a 30-minute ceiling.

## Why the data plane is untouched

* **WireGuard peer traffic never passes through `tsdial.SystemDial`.** magicsock owns its own UDP
  sockets. The hook is TCP-only and returns immediately for any non-TCP network.
* **The hook only ever supplies an alternate address for the configured coordination server.** The
  Kotlin side returns `""` unless the failed IP is one of the control hostname's own resolved
  addresses, so DERP, logtail, captive-portal probes and everything else are untouched — and it
  never applies to the default Tailscale coordination server, nor when the control URL is already an
  IP literal.
* **Nothing in this feature touches** peer endpoint selection, DERP selection or traffic, MagicDNS,
  subnet routes, exit nodes, peer hostnames, peer DNS, device DNS, or VPN routing.
* **The lookup request itself** is a single small HTTPS GET issued on the underlying non-VPN
  `Network`, entirely outside the tunnel and unrelated to any Tailscale connection.

## Limitations

* The hook sits **below** DNS resolution, so it can only help when the control hostname *resolves*
  and the TCP connect then fails. If DNS for the control hostname fails outright, the fallback never
  runs. This matches the intended setup, where the hostname resolves to the LAN address everywhere.
* **IPv4-only client networks are not supported.** If the phone has no IPv6 path to the home
  network, this cannot work, and that is accepted rather than solved with a relay, VPS, tunnel, or
  forced DERP.
* The feature is inert unless a custom coordination server is configured.

## Rebasing onto upstream

The whole feature is confined to:

| File | Role |
| --- | --- |
| `libtailscale/privatediscovery/` | all Go logic + tests (new package, no upstream edits) |
| `libtailscale/backend.go` | **one** changed statement: how `dialer` is constructed |
| `libtailscale/interfaces.go` | **one** added `AppContext` method |
| `android/.../privatediscovery/` | all Kotlin logic (new package) |
| `android/.../ui/view/PrivateDiscoveryView.kt`, `ui/viewModel/PrivateDiscoveryViewModel.kt` | UI (new files) |
| `SettingsViewModel.kt`, `SettingsView.kt`, `MainActivity.kt`, `App.kt`, `strings.xml` | small additive hooks |

When pulling upstream:

1. Check `tsdial.NewFromFuncForDebug` still exists and still sets the system dial func. If it was
   renamed or removed, that one line in `backend.go` is the only thing to fix.
2. Check `dnscache.TLSDialer` still sets `cfg.ServerName` from the address hostname. If that ever
   changes, the TLS invariant changes with it — `privatediscovery_test.go` will fail, loudly, which
   is the point.
3. Re-run `./tool/go test ./libtailscale/privatediscovery/` and
   `(cd android && ./gradlew testDebugUnitTest)`.
