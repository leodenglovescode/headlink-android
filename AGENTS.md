# Headlink — notes for coding agents

## What this repository is

Headlink is a **personal fork** of the open-source Tailscale Android client, used to connect to a
private, self-hosted Headscale deployment.

* Upstream: `https://github.com/tailscale/tailscale-android`
* Application ID: `dev.leodeng.headlink` (installs side by side with official Tailscale)
* Kotlin/Java namespace: still `com.tailscale.ipn` — **do not rename it**

Terminology, which is deliberate:

| Thing | Name |
| --- | --- |
| App / product | Headlink |
| Networking engine and protocol | Tailscale |
| Coordination server | Headscale |
| The custom feature | Private Headscale IPv6 Discovery |

## Rules

**Preserve rebaseability.** Upstream is pulled regularly. Keep custom code in its own files and
packages; prefer one small hook in existing code over duplicating a subsystem. Avoid large
refactors, unrelated reformatting, hand-edited generated files, and package-tree renames.

**Do not globally rename Tailscale.** The networking engine genuinely is Tailscale, and renaming
internal references makes them inaccurate and rebases painful. Only product-facing identity
(app name, launcher icon, theme, About screen) is Headlink. Preserve all upstream copyright
notices, the BSD-3-Clause license, `PATENTS`, and existing attribution.

**Private Headscale IPv6 Discovery affects only the coordination-server dial.** It supplies an
alternate physical TCP destination and nothing else. It must never touch WireGuard peer endpoints,
magicsock, peer sockets, DERP selection or traffic, MagicDNS, subnet routes, exit nodes, peer DNS,
device DNS, or VPN routing. See `docs/private-headscale-ipv6-discovery.md`.

**Never proxy the data plane.** No HTTP/SOCKS proxying, no CONNECT tunnelling, no
WireGuard-over-HTTPS/WebSocket, no custom relay or DERP, no second VPN, no device-wide DNS
interception. The lookup endpoint answers one question and carries no Tailscale traffic.

**Never weaken TLS.** No `InsecureSkipVerify`, no certificate pinning to a discovered IP, no
verification against an IP literal. The configured hostname always drives SNI, TLS ServerName,
certificate verification and the HTTP Host header, even when the socket goes somewhere else.
`libtailscale/privatediscovery/privatediscovery_test.go` asserts this; if it fails, stop.

**Keep secrets out of source and logs.** No hardcoded URLs, secrets, or addresses. The shared secret
lives only in Android Keystore-encrypted storage; it must never reach a log line, an exception
message, the UI, a bug report, or plain SharedPreferences. Do not log the discovered public IPv6
either — keeping it unpublished is the entire point of the feature. Log URLs through `redactUrl()`.

**Build and test before declaring anything complete.**

## Build

Requires a JDK 17 toolchain (Gradle 8.13 cannot run on JDK 24+), the Android SDK
(platform-36, build-tools 36.0.0, NDK 23.1.7779620 — `make androidsdk`), and the pinned Go
toolchain, which `./tool/go` fetches on first use.

```sh
export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
export ANDROID_HOME="$HOME/Library/Android/sdk"
export ANDROID_SDK_ROOT="$ANDROID_HOME"

make fmt                                     # gradlew ktfmtFormat — CI runs ktfmtCheck
./tool/go test ./libtailscale/privatediscovery/
make go-test                                 # excludes libtailscale itself (needs the NDK)
(cd android && ./gradlew testDebugUnitTest)   # Kotlin JVM unit tests
make apk                                     # -> headlink-debug.apk
```

Changing any interface in `libtailscale/*.go` requires rebuilding the AAR (`make libtailscale`)
before Kotlin can see it. `android/build.gradle` sets `warningsAsErrors true` for lint, so lint
regressions break the build.

## Git

Do not commit, push, force-push, reset, delete branches, change remotes, or open PRs unless
explicitly asked.

## Commit messages

Plain: subject line, blank line, body. **Never** append `Co-Authored-By`, `Claude-Session`,
"Generated with" or any similar trailer.

Never `git push`, force-push, `reset --hard`, delete branches, change remotes or open PRs unless
asked in that message. Committing to the current feature branch when asked is fine.

## Never commit deployment specifics

Real hostnames, public IP addresses, LAN addresses, ports, certificates, secrets and node names
belong in a local, git-ignored file (`CLAUDE.md`), never in the repository. Tests and documentation
use example values: `192.168.1.10`, `2001:db8::`, `example.com`.

The one credential-shaped exception is `android/src/test/resources/mtls/`, a throwaway PKI committed
so tests can perform a real handshake requiring client authentication. It protects nothing.

## Verify what you shipped, not what you built

`make apk` has packaged a **stale** `libtailscale.aar` while reporting success — the Kotlin half
updates and the Go half does not, so you debug code that is not running. After a Go change:

```sh
rm -f android/libs/libtailscale*.aar libgojni.so.*
make apk
unzip -p headlink-debug.apk lib/arm64-v8a/libgojni.so | grep -ac 'a string you just added'
```

Confirm the device has that exact build by comparing md5 against `pm path`. See
[docs/faq.md](docs/faq.md).

## Diagnosing

Every code path that declines to act must say so. Silent early returns made a feature that never
engaged indistinguishable from one that engaged and failed, which cost hours. Log the decision,
never the discovered address.

When something looks like a server fault, rule out the platform first — Android blocks a UID's
network for battery reasons, and the symptoms are indistinguishable from a routing problem.
[docs/faq.md](docs/faq.md) has the checks.
