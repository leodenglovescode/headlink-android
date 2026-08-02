// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.privatediscovery

import android.content.Context
import android.content.SharedPreferences
import android.net.Network
import com.tailscale.ipn.NetworkChangeCallback
import com.tailscale.ipn.ui.Links
import com.tailscale.ipn.ui.notifier.Notifier
import com.tailscale.ipn.util.TSLog
import java.io.IOException
import java.io.InputStream
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.net.URI
import java.net.URL
import java.net.UnknownHostException
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLException

/**
 * Headlink's "Private Headscale IPv6 Discovery".
 *
 * The Headscale hostname deliberately resolves to a private LAN address so the home network's
 * rotating public IPv6 is never published. This object is the Android half of the fix: it holds the
 * settings, performs the authenticated lookup, caches the result, and answers the Go dialer's
 * question "this coordination-server dial failed — is there somewhere else to try?".
 *
 * It supplies an alternate *physical* destination only. TLS SNI, TLS ServerName, certificate
 * hostname verification and the HTTP Host header are all decided by the Tailscale core from the
 * configured coordination-server URL, one layer above the socket, and are untouched by any of this.
 * See docs/private-headscale-ipv6-discovery.md.
 *
 * Nothing here polls or schedules. Every lookup is triggered by a real connection failure.
 */
object PrivateDiscovery {
  private const val TAG = "PrivateDiscovery"

  private const val PREFS_NAME = "private_discovery"

  private const val KEY_ENABLED = "enabled"
  private const val KEY_LOOKUP_URL = "lookup_url"
  private const val KEY_AUTH_HEADER = "auth_header"
  private const val KEY_CACHE_AGE_VALUE = "cache_age_value"
  private const val KEY_CACHE_AGE_UNIT = "cache_age_unit"
  private const val KEY_TIMEOUT_SECONDS = "timeout_seconds"
  private const val KEY_CACHED_ADDRESS = "cached_address"
  private const val KEY_CACHED_AT = "cached_at"
  private const val KEY_LAST_RESULT = "last_result"

  /**
   * Storage key for the encrypted shared secret. The name is historical — the secret is sent in a
   * configurable header, not necessarily as a bearer token — and is kept as-is so an already
   * configured install does not silently lose its secret.
   */
  private const val KEY_SECRET_CIPHERTEXT = "bearer_token"

  /** Encrypted PKCS#12 client-certificate bundle (Base64 of the bundle, then encrypted). */
  private const val KEY_CLIENT_CERT_CIPHERTEXT = "client_cert_p12"

  /** Encrypted passphrase for the client-certificate bundle. */
  private const val KEY_CLIENT_CERT_PASS_CIPHERTEXT = "client_cert_passphrase"

  /**
   * Extra CA certificate, PEM. A CA certificate is public information, so unlike the bundle and its
   * passphrase this is stored in the clear.
   */
  private const val KEY_EXTRA_CA = "extra_ca_pem"

  /** How long a control-hostname DNS answer is reused, in milliseconds. */
  private const val RESOLVE_TTL_MILLIS = 60_000L

  private lateinit var appContext: Context
  private lateinit var tokenStore: TokenStore
  private lateinit var clientCertStore: TokenStore
  private lateinit var clientCertPassStore: TokenStore

  /** Overridable for tests. */
  @Volatile var transport: PrivateDiscoveryLookup.Transport = AndroidLookupTransport()

  @Volatile private var lastLookupAttemptMillis: Long = 0
  @Volatile private var consecutiveFailures: Int = 0

  private data class ResolvedHost(
      val host: String,
      val addresses: List<ByteArray>,
      val resolvedAtMillis: Long
  )

  @Volatile private var resolved: ResolvedHost? = null

  fun init(context: Context) {
    appContext = context.applicationContext
    tokenStore = KeystoreTokenStore(appContext, PREFS_NAME, KEY_SECRET_CIPHERTEXT)
    clientCertStore = KeystoreTokenStore(appContext, PREFS_NAME, KEY_CLIENT_CERT_CIPHERTEXT)
    clientCertPassStore =
        KeystoreTokenStore(appContext, PREFS_NAME, KEY_CLIENT_CERT_PASS_CIPHERTEXT)
  }

  /**
   * Test seam: substitute the storage-backed stores.
   *
   * The certificate stores default to [store] only for convenience; pass distinct instances when a
   * test exercises both a secret and a client certificate, since one store cannot hold both.
   */
  fun initForTest(
      context: Context,
      store: TokenStore,
      certStore: TokenStore = store,
      certPassStore: TokenStore = store
  ) {
    appContext = context.applicationContext
    tokenStore = store
    clientCertStore = certStore
    clientCertPassStore = certPassStore
  }

  private fun prefs(): SharedPreferences =
      appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

  // ---------------------------------------------------------------- settings

  fun config(): PrivateDiscoveryConfig {
    val p = prefs()
    return PrivateDiscoveryConfig(
        enabled = p.getBoolean(KEY_ENABLED, false),
        lookupUrl = p.getString(KEY_LOOKUP_URL, "") ?: "",
        authHeader = p.getString(KEY_AUTH_HEADER, DEFAULT_AUTH_HEADER) ?: DEFAULT_AUTH_HEADER,
        secret = tokenStore.load(),
        cacheAgeValue = p.getInt(KEY_CACHE_AGE_VALUE, DEFAULT_CACHE_AGE_VALUE),
        cacheAgeUnit =
            runCatching {
                  CacheAgeUnit.valueOf(
                      p.getString(KEY_CACHE_AGE_UNIT, DEFAULT_CACHE_AGE_UNIT.name)
                          ?: DEFAULT_CACHE_AGE_UNIT.name)
                }
                .getOrDefault(DEFAULT_CACHE_AGE_UNIT),
        timeoutSeconds = p.getInt(KEY_TIMEOUT_SECONDS, DEFAULT_TIMEOUT_SECONDS),
        clientCertP12Base64 = clientCertStore.load(),
        clientCertPassphrase = clientCertPassStore.load(),
        extraCaPem = p.getString(KEY_EXTRA_CA, "") ?: "")
  }

  fun setEnabled(enabled: Boolean) {
    prefs().edit().putBoolean(KEY_ENABLED, enabled).apply()
    if (enabled) {
      TSLog.d(TAG, "private Headscale IPv6 discovery enabled")
    } else {
      TSLog.d(TAG, "private Headscale IPv6 discovery disabled")
      // Drop any back-off state so re-enabling behaves predictably.
      lastLookupAttemptMillis = 0
      consecutiveFailures = 0
    }
  }

  fun setLookupUrl(url: String) {
    prefs().edit().putString(KEY_LOOKUP_URL, url.trim()).apply()
  }

  /** The header name is not a secret, so it lives in ordinary preferences alongside the URL. */
  fun setAuthHeader(name: String) {
    prefs().edit().putString(KEY_AUTH_HEADER, name.trim()).apply()
  }

  /** The secret is written straight through to the Keystore-backed store; it is never logged. */
  fun setSecret(secret: String) {
    tokenStore.save(secret.trim())
  }

  /**
   * Stores the client-certificate bundle, already Base64-encoded, and its passphrase.
   *
   * Both go through the Keystore-backed store: the bundle contains a private key, so it is at least
   * as sensitive as the shared secret. Passing an empty bundle clears both.
   */
  fun setClientCert(p12Base64: String, passphrase: String) {
    if (p12Base64.isBlank()) {
      clientCertStore.clear()
      clientCertPassStore.clear()
      TSLog.d(TAG, "client certificate removed")
      return
    }
    clientCertStore.save(p12Base64)
    clientCertPassStore.save(passphrase)
    TSLog.d(TAG, "client certificate stored")
  }

  /** A CA certificate is public, so this is the one credential-adjacent field kept in the clear. */
  fun setExtraCaPem(pem: String) {
    prefs().edit().putString(KEY_EXTRA_CA, pem.trim()).apply()
  }

  fun setCacheAge(value: Int, unit: CacheAgeUnit) {
    prefs()
        .edit()
        .putInt(KEY_CACHE_AGE_VALUE, value)
        .putString(KEY_CACHE_AGE_UNIT, unit.name)
        .apply()
  }

  fun setTimeoutSeconds(seconds: Int) {
    prefs()
        .edit()
        .putInt(KEY_TIMEOUT_SECONDS, seconds.coerceIn(MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS))
        .apply()
  }

  // ------------------------------------------------------------------- cache

  fun cache(): PrivateDiscoveryPolicy.CacheEntry? {
    val p = prefs()
    val address = p.getString(KEY_CACHED_ADDRESS, null) ?: return null
    if (address.isBlank()) return null
    val at = p.getLong(KEY_CACHED_AT, 0L)
    if (at <= 0L) return null
    return PrivateDiscoveryPolicy.CacheEntry(address, at)
  }

  /** Clears only the cached address and timestamp. Settings and the token are untouched. */
  fun clearCache() {
    prefs().edit().remove(KEY_CACHED_ADDRESS).remove(KEY_CACHED_AT).apply()
    TSLog.d(TAG, "cached public IPv6 cleared")
  }

  fun lastResult(): String? = prefs().getString(KEY_LAST_RESULT, null)

  private fun storeCache(address: String, nowMillis: Long) {
    prefs().edit().putString(KEY_CACHED_ADDRESS, address).putLong(KEY_CACHED_AT, nowMillis).apply()
  }

  private fun storeLastResult(message: String) {
    prefs().edit().putString(KEY_LAST_RESULT, message).apply()
  }

  // ----------------------------------------------------------- user actions

  /**
   * Performs a lookup with the current settings and reports the outcome, without touching the
   * cache. Backs the "Test Lookup" button.
   */
  fun testLookup(): PrivateDiscoveryLookup.LookupOutcome {
    val outcome = PrivateDiscoveryLookup.perform(config(), transport)
    recordOutcome(outcome, "Test lookup")
    return outcome
  }

  /**
   * Performs a lookup and, on success, replaces the cached address and timestamp. Backs the
   * "Refresh Now" button.
   */
  fun refreshNow(): PrivateDiscoveryLookup.LookupOutcome {
    val outcome = performLookupAndCache(System.currentTimeMillis())
    recordOutcome(outcome, "Refresh")
    return outcome
  }

  private fun recordOutcome(outcome: PrivateDiscoveryLookup.LookupOutcome, what: String) {
    when (outcome) {
      is PrivateDiscoveryLookup.LookupOutcome.Success ->
          // Deliberately not logging the address: it is the value this feature exists to keep
          // unpublished.
          storeLastResult("$what succeeded")
      is PrivateDiscoveryLookup.LookupOutcome.Failure ->
          storeLastResult("$what failed: ${outcome.detail}")
    }
  }

  /** Runs one lookup, updating the cache, back-off counters and last-result on the way. */
  private fun performLookupAndCache(nowMillis: Long): PrivateDiscoveryLookup.LookupOutcome {
    lastLookupAttemptMillis = nowMillis
    TSLog.d(TAG, "fetching updated public IPv6 from ${redactUrl(config().lookupUrl)}")
    val outcome = PrivateDiscoveryLookup.perform(config(), transport)
    when (outcome) {
      is PrivateDiscoveryLookup.LookupOutcome.Success -> {
        consecutiveFailures = 0
        storeCache(outcome.address, nowMillis)
        TSLog.d(TAG, "public IPv6 refreshed successfully")
      }
      is PrivateDiscoveryLookup.LookupOutcome.Failure -> {
        consecutiveFailures += 1
        TSLog.w(TAG, "public IPv6 lookup failed: ${outcome.detail}")
      }
    }
    return outcome
  }

  // ------------------------------------------------------------ dial bridge

  /**
   * Called from Go (via `AppContext.PrivateDiscoveryDialFallback`) after a coordination-server TCP
   * dial has failed.
   *
   * @param failedAddr the `ip:port` literal whose dial failed.
   * @param allowLookup false for phase 2 (cache only, no network); true for phase 3.
   * @return a replacement `[ipv6]:port` to try, or "" for "not applicable".
   *
   * Returning "" is the normal, quiet outcome for every dial that is not the configured
   * coordination server — DERP, logtail, captive-portal probes and everything else. That check is
   * what confines this feature to the control plane.
   */
  fun dialFallback(failedAddr: String, allowLookup: Boolean): String {
    return try {
      dialFallbackInner(failedAddr, allowLookup)
    } catch (e: Exception) {
      // This runs on a Go goroutine inside the VPN process. It must never be able to take the
      // service down, so absolutely everything is contained here.
      TSLog.e(TAG, "dial fallback failed unexpectedly")
      ""
    }
  }

  private fun dialFallbackInner(failedAddr: String, allowLookup: Boolean): String {
    if (!::appContext.isInitialized) return ""

    val config = config()
    if (!config.enabled) return ""

    val port = portOf(failedAddr) ?: return ""
    val failedIp = ipOf(failedAddr) ?: return ""

    if (!isConfiguredControlServer(failedIp)) return ""
    if (!config.isUsable()) {
      TSLog.w(TAG, "coordination connection failed but private discovery is not fully configured")
      return ""
    }

    val now = System.currentTimeMillis()
    val cached = cache()
    val stage =
        if (allowLookup) PrivateDiscoveryPolicy.Stage.ALLOW_LOOKUP
        else PrivateDiscoveryPolicy.Stage.CACHE_ONLY

    return when (PrivateDiscoveryPolicy.decide(
        stage, config, cached, now, lastLookupAttemptMillis, consecutiveFailures)) {
      PrivateDiscoveryPolicy.Decision.NOT_APPLICABLE -> ""
      PrivateDiscoveryPolicy.Decision.USE_CACHE -> {
        TSLog.d(TAG, "normal coordination connection failed; offering cached public IPv6")
        PrivateDiscoveryPolicy.dialTarget(cached!!.address, port)
      }
      PrivateDiscoveryPolicy.Decision.USE_STALE_CACHE -> {
        // Rate-limited: a stale address beats no address at all.
        TSLog.d(TAG, "lookup is rate-limited; offering the expired cached public IPv6")
        PrivateDiscoveryPolicy.dialTarget(cached!!.address, port)
      }
      PrivateDiscoveryPolicy.Decision.LOOKUP -> {
        when (val outcome = performLookupAndCache(now)) {
          is PrivateDiscoveryLookup.LookupOutcome.Success ->
              PrivateDiscoveryPolicy.dialTarget(outcome.address, port)
          is PrivateDiscoveryLookup.LookupOutcome.Failure -> {
            storeLastResult("Automatic refresh failed: ${outcome.detail}")
            // Last resort: an expired cached address may still be correct, and trying it costs
            // one TCP connect. Better than certain failure.
            cached?.let {
              TSLog.d(TAG, "lookup failed; falling back to the expired cached public IPv6")
              PrivateDiscoveryPolicy.dialTarget(it.address, port)
            } ?: ""
          }
        }
      }
    }
  }

  // ------------------------------------------------------- control-host match

  /**
   * Whether [failedIp] is one of the addresses the configured coordination-server hostname
   * currently resolves to.
   *
   * This is the scoping check that keeps the feature off every other connection the Tailscale core
   * makes. It never applies to the default Tailscale coordination server, nor when the control URL
   * is already an IP literal.
   */
  private fun isConfiguredControlServer(failedIp: InetAddress): Boolean {
    val controlUrl = Notifier.prefs.value?.ControlURL?.trim().orEmpty()
    if (controlUrl.isEmpty()) return false
    if (controlUrl == Links.DEFAULT_CONTROL_URL) return false

    val host =
        try {
          URI(controlUrl).host
        } catch (e: Exception) {
          null
        } ?: return false
    if (host.isBlank()) return false
    // Already an IP literal: there is nothing to override.
    if (looksLikeIpLiteral(host)) return false
    if (host.equals("controlplane.tailscale.com", ignoreCase = true)) return false

    val target = failedIp.address
    return resolveControlHost(host).any { it.contentEquals(target) }
  }

  /** Resolves the control hostname on the underlying (non-VPN) network, memoized briefly. */
  private fun resolveControlHost(host: String): List<ByteArray> {
    val now = System.currentTimeMillis()
    resolved?.let {
      if (it.host == host && now - it.resolvedAtMillis in 0 until RESOLVE_TTL_MILLIS) {
        return it.addresses
      }
    }
    val addresses =
        try {
          val network: Network? = NetworkChangeCallback.cachedDefaultNetwork
          val answers = network?.getAllByName(host) ?: InetAddress.getAllByName(host)
          answers.map { it.address }
        } catch (e: Exception) {
          // Resolution failure just means "we cannot confirm this is the control server".
          emptyList()
        }
    resolved = ResolvedHost(host, addresses, now)
    return addresses
  }

  // ------------------------------------------------------------------ helpers

  private fun portOf(hostPort: String): Int? {
    val idx = hostPort.lastIndexOf(':')
    if (idx < 0) return null
    return hostPort.substring(idx + 1).toIntOrNull()?.takeIf { it in 1..65535 }
  }

  private fun ipOf(hostPort: String): InetAddress? {
    val idx = hostPort.lastIndexOf(':')
    if (idx < 0) return null
    val host = hostPort.substring(0, idx).removePrefix("[").removeSuffix("]")
    if (!looksLikeIpLiteral(host)) return null
    return try {
      // Safe: looksLikeIpLiteral has already ruled out anything that could trigger a DNS query.
      InetAddress.getByName(host)
    } catch (e: Exception) {
      null
    }
  }

  /**
   * A cheap character-class check used to guarantee we never hand a hostname to
   * [InetAddress.getByName], which would silently perform a DNS lookup.
   */
  private fun looksLikeIpLiteral(host: String): Boolean {
    if (host.isEmpty()) return false
    if (!host.contains(':') && !host.contains('.')) return false
    return host.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }
  }
}

/**
 * The real lookup transport.
 *
 * The request is issued on the underlying non-VPN [Network] whenever one is known, so it leaves the
 * device directly instead of being routed into the Tailscale tunnel — which matters precisely
 * because this code runs when the tunnel's coordination server is unreachable.
 */
class AndroidLookupTransport(
    private val networkProvider: () -> Network? = { NetworkChangeCallback.cachedDefaultNetwork }
) : PrivateDiscoveryLookup.Transport {

  override fun get(request: PrivateDiscoveryLookup.Request): PrivateDiscoveryLookup.HttpResult {
    val parsed = URL(request.url)
    if (!parsed.protocol.equals("https", ignoreCase = true)) {
      throw PrivateDiscoveryLookup.TransportException(
          PrivateDiscoveryLookup.FailureKind.NOT_HTTPS, "Lookup URL must use https://")
    }

    val network = networkProvider()
    val connection =
        (network?.openConnection(parsed) ?: parsed.openConnection()) as? HttpsURLConnection
            ?: throw PrivateDiscoveryLookup.TransportException(
                PrivateDiscoveryLookup.FailureKind.NOT_HTTPS, "Lookup URL must use https://")

    // Mutual TLS, when the endpoint requires a client certificate. This is scoped to this single
    // connection: it is set on this HttpsURLConnection instance, never on
    // HttpsURLConnection.setDefaultSSLSocketFactory, so no other connection in the process — least
    // of all the coordination-server connection — is affected.
    try {
      Mtls.socketFactory(
              p12 = decodeBase64OrNull(request.clientCertP12Base64),
              passphrase = request.clientCertPassphrase,
              extraCaPem = request.extraCaPem.ifBlank { null })
          ?.let { connection.sslSocketFactory = it }
    } catch (e: Mtls.MtlsException) {
      // e.message is written by Mtls and is credential-free by contract.
      throw PrivateDiscoveryLookup.TransportException(
          PrivateDiscoveryLookup.FailureKind.CLIENT_CERT_ERROR, e.message ?: "Client certificate")
    }

    val timeoutMillis = request.timeoutSeconds * 1000
    connection.requestMethod = "GET"
    // Never follow a redirect: doing so could replay the secret header to another origin. This
    // matters more with a custom header than with Authorization, which HTTP clients are expected
    // to strip on a cross-origin redirect; a custom header gets no such protection anywhere.
    connection.instanceFollowRedirects = false
    connection.connectTimeout = timeoutMillis
    connection.readTimeout = timeoutMillis
    connection.useCaches = false
    connection.setRequestProperty("Accept", "application/json, text/plain")
    // The one place the secret is used. It is set on this request only, to the configured origin
    // only, and is never logged or echoed back. The header name is validated as an RFC 7230 token
    // before we get here, so it cannot inject additional headers.
    connection.setRequestProperty(request.authHeader, request.secret)

    try {
      val status = connection.responseCode
      val stream: InputStream? =
          if (status in 200..299) connection.inputStream else connection.errorStream
      val body = stream?.use { readCapped(it) } ?: ""
      return PrivateDiscoveryLookup.HttpResult(status, body)
    } catch (e: SocketTimeoutException) {
      throw PrivateDiscoveryLookup.TransportException(
          PrivateDiscoveryLookup.FailureKind.TIMEOUT, "Timed out after ${request.timeoutSeconds}s")
    } catch (e: SSLException) {
      throw PrivateDiscoveryLookup.TransportException(
          PrivateDiscoveryLookup.FailureKind.TLS_ERROR,
          if (request.clientCertP12Base64.isBlank())
              "TLS error contacting the lookup endpoint; it may require a client certificate"
          else "TLS error contacting the lookup endpoint")
    } catch (e: UnknownHostException) {
      throw PrivateDiscoveryLookup.TransportException(
          PrivateDiscoveryLookup.FailureKind.NETWORK_ERROR, "Could not resolve the lookup endpoint")
    } catch (e: IOException) {
      throw PrivateDiscoveryLookup.TransportException(
          PrivateDiscoveryLookup.FailureKind.NETWORK_ERROR, "Could not reach the lookup endpoint")
    } finally {
      connection.disconnect()
    }
  }

  /** Returns null rather than throwing: an unreadable stored bundle is handled as "not set". */
  private fun decodeBase64OrNull(base64: String): ByteArray? =
      if (base64.isBlank()) null
      else
          try {
            android.util.Base64.decode(base64, android.util.Base64.NO_WRAP)
          } catch (e: IllegalArgumentException) {
            null
          }

  private fun readCapped(stream: InputStream): String {
    val buffer = ByteArray(PrivateDiscoveryLookup.MAX_BODY_BYTES)
    var total = 0
    while (total < buffer.size) {
      val read = stream.read(buffer, total, buffer.size - total)
      if (read <= 0) break
      total += read
    }
    return String(buffer, 0, total, Charsets.UTF_8)
  }
}
