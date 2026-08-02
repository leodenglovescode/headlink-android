# FAQ and quirks

Things that cost real time to work out, written down so they cost it only once. Most of these are
not bugs in Headlink — they are properties of Android, of the Tailscale core, or of a self-hosted
Headscale deployment.

## Connecting

### It sits on "Starting…" for over a minute, then connects

Fixed, but worth understanding because the shape recurs. The coordination hostname resolves to a
LAN address on purpose. Away from home that address is *black-holed* rather than refused, so the
TCP connect ran to the kernel's full SYN-retry timeout — **76 seconds, measured** — before anything
else could happen.

Headlink now bounds that first attempt to 1.5s (`privateDialTimeout`) when the destination is a
private address *and* a fallback exists. A LAN answers in single-digit milliseconds, so the bound
is never reached at home.

If you see a long stall again, time it. Near 75s means something is waiting on a kernel connect
timeout; a few seconds means it is application logic.

### It connects, then the registration times out

Also fixed. The coordination client opens a **new connection per request** and probes several ports
in parallel. Each one used to re-derive the fallback from scratch, and the accumulated cost blew the
client's own deadline — so the control key fetch would succeed and the registration immediately
behind it would fail. A discovered address that works is now reused for two minutes.

### The state shows `--` and Connect appears to do nothing

`--` is "no state reported", not "connecting". If the backend never leaves `NoState`, look for
`Switching ipn state` in the logs — its absence means the backend never started, which is different
from it starting and failing.

### `tailscale up` on another machine says the certificate is for the wrong name

```
x509: certificate is valid for ts.example.com, not headscale.lan
```

The login server URL **is** the TLS identity. A `/etc/hosts` alias cannot be used as the login
server unless the certificate covers that name. Use the certificate's name and keep the alias for
other purposes.

## Android platform quirks

### Android silently cuts the app's network

The single most misleading failure of the whole project. Every socket fails — DNS throws
`UnknownHostException`, dials return `i/o timeout`, and it looks exactly like a routing or firewall
problem on your server.

```sh
adb shell dumpsys connectivity | grep 'UID=<uid> blockedReasons'
```

A non-zero value is Android blocking the UID. The bits are
`BATTERY_SAVER=1, DOZE=2, APP_STANDBY=4, RESTRICTED_MODE=8, LOCKDOWN_VPN=16, LOW_POWER_STANDBY=32,
APP_BACKGROUND=64`, so `40` is `LOW_POWER_STANDBY | RESTRICTED_MODE`.

**Fix:** Settings → Apps → Headlink → App battery usage → **Unrestricted**. A VPN client needs
this; without it Android pulls the network out from under the app the moment it loses foreground,
which is exactly when a VPN needs to reconnect.

To confirm from a shell, compare the app's UID against the shell's:

```sh
adb shell run-as dev.leodeng.headlink toybox nc -w 5 <host> <port>   # app UID
adb shell toybox nc -w 5 <host> <port>                               # shell UID
```

Different answers at the same instant means the platform is blocking the app, not the network.

### Java name resolution stops working once the tunnel is up

`InetAddress.getAllByName` and `Network.getAllByName` both throw `UnknownHostException` inside the
app process while the VPN interface is up, even though the same name resolves fine from a shell and
the Go side resolved it moments earlier. This matters because it fails exactly when the discovery
feature is needed. Headlink therefore remembers the addresses the coordination hostname previously
resolved to, and falls back to matching on the coordination port.

### `logcat` loses the app's output

The default ring buffer is **256 KiB**, and a chatty system component (the camera stack, on a Pixel)
can evict everything within seconds. Symptoms look like the app having stopped logging.

```sh
adb logcat -G 16M
```

### `strings` on `.aar` and `.dex` reports nothing

An `.aar` is a zip, so its contents are compressed and invisible to `strings`. macOS `strings` also
refuses to scan `.dex` unless given `-a`. Both silently return zero matches, which reads as "the
code is missing". Use `grep -a`, and extract from the archive first.

## Build quirks

### The build succeeds but ships stale Go code

`make apk` has produced an APK containing a **stale** `libtailscale.aar` while reporting success.
The Kotlin half updates, the Go half does not, and you debug code that is not running.

Always check the ordering, and grep the shipped binary for something you just added:

```sh
rm -f android/libs/libtailscale*.aar libgojni.so.*
make apk
unzip -p headlink-debug.apk lib/arm64-v8a/libgojni.so | grep -ac 'some new log string'
```

To be certain the device has what you built:

```sh
adb shell md5sum $(adb shell pm path dev.leodeng.headlink | sed 's/package://')
md5 -q headlink-debug.apk
```

### Gradle refuses to run

Gradle 8.13 rejects JDK 26 with "Unsupported class file major version". JDK 17 is required; see
[CLAUDE.md](../CLAUDE.md) for the environment variables.

### `./gradlew lintDebug` fails

It fails on upstream's own code and did so before this fork existed (~115 errors, mostly `UseKtx`
and dependency-version warnings). It is not part of `make apk` or `make test`.

## Deployment quirks

### The lookup endpoint returns nothing at all

If `curl` reports `Empty reply from server` (exit 52) on HTTP/1.1 and a framing error (exit 16) on
HTTP/2, with no status line either way, the endpoint is probably requiring a **client certificate**.
TLS 1.3 completes the handshake before the server evaluates that certificate, so the rejection
arrives as a dead connection rather than an HTTP error. Check with:

```sh
openssl s_client -connect host:443 -servername host </dev/null 2>&1 |
  sed -n '/Acceptable client certificate CA names/,/^---/p'
```

Configure the client certificate under Settings → Private Headscale IPv6 Discovery.

### macOS `curl` rejects a PEM client certificate

macOS links `curl` against Secure Transport, which does **not** accept a separate `--cert`/`--key`
PEM pair and ignores `--cacert`. Exit code 58 is the giveaway. Use a PKCS#12 bundle:

```sh
curl --cert-type P12 --cert client.p12:PASSPHRASE https://host/ip
```

### Two hosts on one machine, one certificate

A private CA is fine for a server that only your own tooling talks to, but **Go on Android trusts
only the system store**, not user-installed CAs. Anything the app must reach — the coordination
server, and a DERP server if you run one — needs a publicly trusted certificate. Since the
coordination hostname deliberately resolves to a private address, HTTP-01 validation cannot reach
it: use **DNS-01**.

### Check the port before concluding anything is broken

A hostname can serve completely unrelated things on different ports. Probing `:443` and finding an
unrelated self-signed certificate says nothing about the coordination server on `:5007`. Always
probe the port the control URL actually names.
