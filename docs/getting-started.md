# Getting started

Headlink is an Android client for a **self-hosted Headscale** deployment. This walks through
installing it, connecting to your server, and — optionally — setting up Private Headscale IPv6
Discovery.

If you only want to connect to Headscale, stop after step 3. The discovery feature solves a
specific problem and most people do not have it.

---

## 1. Install

Build a debug APK and install it:

```sh
export JAVA_HOME=/path/to/jdk-17      # Gradle 8.13 rejects newer JDKs
export ANDROID_HOME="$HOME/Library/Android/sdk"
export ANDROID_SDK_ROOT="$ANDROID_HOME"

make apk
adb install -r headlink-debug.apk
```

Headlink uses the application ID `dev.leodeng.headlink`, so it installs **alongside** the official
Tailscale app. They do not share settings, accounts or the VPN slot — only one VPN can be active at
a time.

## 2. Allow it to run

Do this before connecting; skipping it produces failures that look like server problems.

**Settings → Apps → Headlink → App battery usage → Unrestricted.**

Android otherwise cuts the app's network the moment it loses foreground, which is exactly when a
VPN client needs to reconnect. The symptom is every connection failing at once — DNS included — with
nothing wrong on your server. See [FAQ](faq.md#android-silently-cuts-the-apps-network).

## 3. Connect to your Headscale server

Open Headlink and tap **Connect**, or go to **Settings → Headscale server**. One screen:

| Field | Value |
| --- | --- |
| Server address | `https://headscale.example.com:port` |
| Auth key | optional — leave empty to register in a browser |

To register without a browser, mint a pre-auth key on the server:

```sh
headscale users list                       # note the user id
headscale preauthkeys create --user 1 --expiration 1h
```

Paste it into the auth key field and tap **Connect**.

### The server address must match its certificate

The address you enter **is** the TLS identity — it drives SNI, certificate verification and the HTTP
Host header. An alias that the certificate does not cover cannot be used, even if it resolves:

```
x509: certificate is valid for headscale.example.com, not headscale.lan
```

Headscale's own `server_url` must match too, or clients get redirected somewhere they cannot verify.

### The certificate must be publicly trusted

Go on Android trusts only the system certificate store, **not** user-installed CAs. A private CA
will not work no matter what you install on the phone. Use a publicly trusted certificate; if the
hostname deliberately resolves to a private address, HTTP-01 validation cannot reach it, so issue
with **DNS-01**:

```sh
certbot certonly --preferred-challenges dns --manual -d headscale.example.com
```

That's it — you should reach `Running`, and your tailnet addresses become reachable.

---

## 4. Optional: Private Headscale IPv6 Discovery

### Is this for you?

Only if **all** of these hold:

* Your Headscale hostname resolves to a **private LAN address**, deliberately, so your home
  network's rotating public IPv6 is never published in DNS.
* You want the phone to connect from outside the house anyway.
* You can run a small HTTPS endpoint that reports your current public IPv6.

If your Headscale server is reachable at a public address, or you use dynamic DNS, you do not need
this — that is what the plain setup already does.

### How it behaves

1. Connect normally. **At home this succeeds and the lookup endpoint is never contacted.**
2. If that fails, try a cached address, if one is still within the configured age.
3. If that fails, perform one authenticated lookup and retry.

A connection failure always overrides the cache age. Nothing polls or schedules; every lookup is
triggered by a real failure.

Throughout, the Headscale hostname continues to drive TLS and the Host header. Only the physical
destination changes. See [the architecture doc](private-headscale-ipv6-discovery.md).

### The server side

You need an HTTPS endpoint that returns your current public IPv6 to an authenticated caller, as
plain text or JSON:

```json
{"ipv6": "2001:db8:1234:5678::abcd", "updated": "2026-01-01T00:00:00Z"}
```

A minimal nginx location, with a script keeping the file current:

```nginx
location = /ip {
    if ($http_x_sync_secret != "YOUR_SECRET") { return 403 '{"error":"forbidden"}'; }
    default_type application/json;
    alias /etc/ssl/example/server_ipv6.json;
    add_header Cache-Control "no-store";
}
```

This endpoint must be reachable from outside your home — typically through a CDN or a small VPS,
since your home address is the thing being looked up. It needs a publicly trusted certificate, for
the same reason as above.

### Configure the app

**Settings → Private Headscale IPv6 Discovery.**

| Setting | Notes |
| --- | --- |
| Enable | Off by default |
| Lookup URL | HTTPS only |
| Auth header name | Default `X-Sync-Secret`; use `Authorization` for bearer auth |
| Shared secret | Sent verbatim as that header's value; stored encrypted, never displayed |
| Client certificate | Only if your endpoint requires mutual TLS |
| Cache max age | Default 24 hours; "Only on failure" never expires by age |
| Request timeout | Applies only to the lookup request |

Tap **Test Lookup**. It performs the request and reports the result without touching the cache, and
works without enabling the feature — so you can verify the endpoint before relying on it.

| Result | Meaning |
| --- | --- |
| An IPv6 address | Working |
| `HTTP 403 Forbidden` | Reached and authenticated at the TLS layer; the secret is wrong |
| `Could not reach the lookup endpoint` | Network, TLS, or a required client certificate is missing |

### Verify it actually works

The only real test is from outside your home network. With wifi **off**:

1. Force stop Headlink, reopen it, tap Connect.
2. It should reach `Running` within a few seconds.

If it stalls for over a minute, time it — around 75 seconds means something is waiting on a kernel
connect timeout rather than on application logic. [FAQ](faq.md#connecting) has the specifics.

---

## Limits worth knowing

* **IPv4-only networks cannot work.** If the network you are on has no IPv6 path to your home, there
  is nothing to discover. This is deliberate: no relay, tunnel or proxy is introduced to work around
  it.
* **The hostname must resolve.** The fallback engages when a connection *fails*, not when a name
  fails to resolve. A hostname with no DNS record at all never gets that far.
* **The control URL must be a hostname**, never an IP literal — the hostname is the TLS identity,
  and an IP literal leaves nothing to substitute.
* **Only the coordination connection is affected.** Peer traffic, DERP, MagicDNS, subnet routes and
  exit nodes are untouched.
