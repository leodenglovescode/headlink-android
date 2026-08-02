// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.privatediscovery

/**
 * Configuration and validation for Headlink's "Private Headscale IPv6 Discovery" feature.
 *
 * This file is deliberately free of Android imports so the whole of it is exercised by plain JVM
 * unit tests.
 */

/** How the cached address ages out. */
enum class CacheAgeUnit(val seconds: Long) {
  MINUTES(60L),
  HOURS(3_600L),
  DAYS(86_400L),

  /**
   * Never expire by age. The cached address is refreshed only when a connection using it actually
   * fails. This is the lowest-traffic mode: the lookup endpoint is contacted only after a real
   * failure.
   */
  ONLY_ON_FAILURE(0L)
}

/** Minimum configurable cache max age, to keep the lookup endpoint from being hammered. */
const val MIN_CACHE_AGE_SECONDS: Long = 5 * 60

const val MIN_TIMEOUT_SECONDS: Int = 2
const val MAX_TIMEOUT_SECONDS: Int = 60
const val DEFAULT_TIMEOUT_SECONDS: Int = 10

const val DEFAULT_CACHE_AGE_VALUE: Int = 24
val DEFAULT_CACHE_AGE_UNIT: CacheAgeUnit = CacheAgeUnit.HOURS

/**
 * The request header the shared secret is sent in, by default.
 *
 * A dedicated header is used rather than `Authorization` because that is what a minimal nginx
 * `location` block can check most directly (`$http_x_sync_secret`). Both are equivalent as far as
 * this client is concerned: the secret is sent in exactly one header, to exactly one origin, over
 * TLS, and never through a redirect. To use standard bearer auth instead, set the header name to
 * `Authorization` and the secret to `Bearer <token>`.
 */
const val DEFAULT_AUTH_HEADER: String = "X-Sync-Secret"

data class PrivateDiscoveryConfig(
    val enabled: Boolean = false,
    val lookupUrl: String = "",
    /** The name of the request header the secret is sent in. Not itself a secret. */
    val authHeader: String = DEFAULT_AUTH_HEADER,
    /**
     * The shared secret, sent verbatim as the value of [authHeader]. Present only in memory, for
     * the duration of a lookup. Never logged, never displayed.
     */
    val secret: String = "",
    val cacheAgeValue: Int = DEFAULT_CACHE_AGE_VALUE,
    val cacheAgeUnit: CacheAgeUnit = DEFAULT_CACHE_AGE_UNIT,
    val timeoutSeconds: Int = DEFAULT_TIMEOUT_SECONDS,
    /**
     * Base64 of a PKCS#12 bundle presented as the client certificate, when the lookup endpoint
     * requires mutual TLS. Held as Base64 rather than raw bytes so this stays a well-behaved data
     * class. Empty means "no client certificate", which is the default.
     */
    val clientCertP12Base64: String = "",
    /** Passphrase for [clientCertP12Base64]. Never logged, never displayed. */
    val clientCertPassphrase: String = "",
    /**
     * PEM of one or more extra CA certificates to trust *in addition to* the system trust anchors,
     * for endpoints whose certificate is issued by a private CA. Never replaces the system anchors.
     */
    val extraCaPem: String = "",
) {
  fun hasClientCert(): Boolean = clientCertP12Base64.isNotBlank()

  fun hasExtraCa(): Boolean = extraCaPem.isNotBlank()

  /**
   * The configured max age in seconds, or null when the cache never expires by age
   * ([CacheAgeUnit.ONLY_ON_FAILURE]).
   */
  fun maxAgeSeconds(): Long? =
      when (cacheAgeUnit) {
        CacheAgeUnit.ONLY_ON_FAILURE -> null
        else -> (cacheAgeValue.toLong() * cacheAgeUnit.seconds).coerceAtLeast(MIN_CACHE_AGE_SECONDS)
      }

  /** Whether this config can actually be used to perform a lookup. */
  fun isUsable(): Boolean =
      enabled &&
          validateLookupUrl(lookupUrl) == null &&
          validateAuthHeader(authHeader) == null &&
          secret.isNotBlank()

  /**
   * A redacted rendering, safe for logs and bug reports. Never include [secret] in any string
   * representation.
   */
  override fun toString(): String =
      "PrivateDiscoveryConfig(enabled=$enabled, lookupUrl=${redactUrl(lookupUrl)}, " +
          "authHeader=$authHeader, secret=<redacted>, cacheAge=$cacheAgeValue $cacheAgeUnit, " +
          "timeoutSeconds=$timeoutSeconds, clientCert=${present(hasClientCert())}, " +
          "clientCertPassphrase=<redacted>, extraCa=${present(hasExtraCa())})"
}

/** Reasons a field can be rejected. The UI maps these onto string resources. */
enum class ValidationError {
  EMPTY,
  NOT_A_URL,
  NOT_HTTPS,
  NO_HOST,
  OUT_OF_RANGE,
  INVALID_HEADER_NAME,
}

/**
 * Validates a lookup URL, returning null when it is acceptable.
 *
 * HTTPS is mandatory: the request carries a shared secret and the response reveals private
 * infrastructure, so plaintext is never allowed, not even for testing. A non-default port
 * (`https://host:5006/ip`) is perfectly acceptable.
 */
fun validateLookupUrl(raw: String): ValidationError? {
  val url = raw.trim()
  if (url.isEmpty()) return ValidationError.EMPTY

  val parsed =
      try {
        java.net.URI(url)
      } catch (e: Exception) {
        return ValidationError.NOT_A_URL
      }
  val scheme = parsed.scheme?.lowercase() ?: return ValidationError.NOT_A_URL
  if (scheme != "https") return ValidationError.NOT_HTTPS
  if (parsed.host.isNullOrBlank()) return ValidationError.NO_HOST
  return null
}

/**
 * Validates a request header name, returning null when it is acceptable.
 *
 * Only RFC 7230 token characters are allowed. This is not a cosmetic check: a name containing CR,
 * LF or a colon would be a header-injection primitive, letting a malformed setting smuggle extra
 * headers into the request that carries the secret.
 */
fun validateAuthHeader(raw: String): ValidationError? {
  val name = raw.trim()
  if (name.isEmpty()) return ValidationError.EMPTY
  val tokenChars = "!#$%&'*+-.^_`|~"
  if (!name.all { (it.code < 128 && it.isLetterOrDigit()) || it in tokenChars }) {
    return ValidationError.INVALID_HEADER_NAME
  }
  return null
}

fun validateTimeoutSeconds(raw: String): ValidationError? {
  val value = raw.trim().toIntOrNull() ?: return ValidationError.NOT_A_URL
  if (value < MIN_TIMEOUT_SECONDS || value > MAX_TIMEOUT_SECONDS)
      return ValidationError.OUT_OF_RANGE
  return null
}

fun validateCacheAgeValue(raw: String, unit: CacheAgeUnit): ValidationError? {
  if (unit == CacheAgeUnit.ONLY_ON_FAILURE) return null
  val value = raw.trim().toIntOrNull() ?: return ValidationError.NOT_A_URL
  if (value < 1) return ValidationError.OUT_OF_RANGE
  if (value.toLong() * unit.seconds < MIN_CACHE_AGE_SECONDS) return ValidationError.OUT_OF_RANGE
  return null
}

/** Renders a presence flag without revealing the thing itself. */
internal fun present(value: Boolean): String = if (value) "<present>" else "<absent>"

/**
 * Strips the query and fragment from a URL so it can be logged.
 *
 * Some deployments put a token in a query parameter; never let one reach a log line or a bug
 * report. Returns a placeholder rather than the raw string if parsing fails.
 */
fun redactUrl(raw: String): String {
  val url = raw.trim()
  if (url.isEmpty()) return "<unset>"
  return try {
    val parsed = java.net.URI(url)
    val host = parsed.host ?: return "<url>"
    val port = if (parsed.port >= 0) ":${parsed.port}" else ""
    val path = parsed.path ?: ""
    val suffix = if (parsed.query != null || parsed.fragment != null) "?<redacted>" else ""
    "${parsed.scheme}://$host$port$path$suffix"
  } catch (e: Exception) {
    "<url>"
  }
}
