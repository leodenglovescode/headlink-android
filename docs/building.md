# Building Headlink

Headlink builds the same way the upstream Tailscale Android client does: a Go module is compiled
into an AAR with `gomobile bind`, and Gradle assembles the Android app around it.

## What you need

- A Go runtime — the version in [`go.mod`](../go.mod)
- **JDK 17.** Gradle 8.13 rejects newer JDKs, including the JDK 26 Homebrew installs by default
- The Android SDK, plus the components `make androidsdk` installs

```sh
export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
export ANDROID_HOME="$HOME/Library/Android/sdk"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
```

If you installed the SDK through Android Studio, `make androidpath` prints the path to export.

## Setting up the SDK

### Android Studio

The most comfortable path for real development.

1. Install a [Go runtime](https://go.dev/dl/).
2. Install [Android Studio](https://developer.android.com/studio).
3. On the Welcome screen choose **More Actions → SDK Manager**.
4. Under **SDK Tools**, install *Android SDK Command-line Tools (latest)*.
5. Run `make androidsdk`.

Enable **Format on Save** with the ktfmt plugin on its default setting, so Kotlin, Java and XML stay
formatted the way `./gradlew ktfmtCheck` expects.

### Without Android Studio

Any Android SDK will do — the Makefile probes common locations, so `sudo apt install android-sdk`
is enough on Debian/Ubuntu. For an SDK somewhere unusual, point `ANDROID_SDK_ROOT` at it.

### Docker

To keep the toolchain off your host:

```sh
make docker-shell
```

Other `docker-*` recipes cover full builds. Containers are removed on completion but the image is
kept; if the toolchain changes, rebuild it (the image name is a Makefile variable, so changing it is
the quickest way to force a fresh one).

### Nix

With Nix 2.4 or later:

```sh
alias nix='nix --extra-experimental-features "nix-command flakes"'
nix develop
make androidsdk        # first time only
make apk
```

The flake supplies Java, `make`, `curl` and `git`, and points the build at a repo-local Android SDK
in `./android-sdk`, which is git-ignored and reused across builds. For one-shot commands:

```sh
nix develop --command make apk
```

Kotlin-only iteration, skipping the slow `gomobile bind` step:

```sh
nix develop --command bash -lc 'cd android && ./gradlew ktfmtCheck compileDebugKotlin'
```

## The commands

| Task | Command | Output |
| --- | --- | --- |
| Debug APK | `make apk` | `headlink-debug.apk` |
| Install on a connected device | `make install` | |
| Signed release APKs | `make release-apk` | `headlink-release.apk` + per-ABI APKs |
| Android unit tests | `(cd android && ./gradlew testDebugUnitTest)` | |
| Go tests | `./tool/go test -count=1 ./libtailscale/...` | |
| Format Kotlin | `(cd android && ./gradlew ktfmtFormat)` | |
| Check formatting | `(cd android && ./gradlew ktfmtCheck)` | |
| Everything the Makefile offers | `make help` | |

`make release-apk` needs the `HEADLINK_KEYSTORE_*` environment variables; without them, build the
debug APK instead.

> `./gradlew lintDebug` fails with roughly 115 errors that predate this fork. It is not part of
> `make apk` or `make test`. See [FAQ → `./gradlew lintDebug` fails](faq.md#gradlew-lintdebug-fails).

## Releases

CI builds every push. It publishes a GitHub Release only when the pushed commit message contains
`[release]`, or when a `v*` tag is pushed by hand. Every other build still produces a signed APK as
a 30-day workflow artifact.

`versionCode` is stamped by CI from wall-clock time, so each build outranks the last and installs
over the previous one. It is never committed.

## Developing on a Fire TV Stick

On the device: **Settings → My Fire TV → Developer Options → ADB Debugging → ON**.

```sh
adb connect 10.2.200.213:5555
adb install -r headlink-debug.apk
adb shell am start -n dev.leodeng.headlink/com.tailscale.ipn.MainActivity
adb shell pm uninstall dev.leodeng.headlink
```

Note that `am start` launches the app but never sends a Connect, so it is useless for reproducing
connection problems — the backend just idles.

## Before you touch the code

Read [AGENTS.md](../AGENTS.md). This fork is rebased onto upstream, so it is kept deliberately
small: a couple of one-line hooks and otherwise new files. It also documents which files are
fragile, and the security properties that must not regress.
