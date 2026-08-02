// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.privatediscovery

/**
 * The authenticated lookup: "what is my home network's current public IPv6?".
 *
 * The transport is abstracted so the whole decision/validation path is unit-testable without a
 * network. See [AndroidLookupTransport] for the real implementation.
 *
 * Security rules enforced here and in the transport:
 * * HTTPS only, with ordinary certificate validation. Never `InsecureSkipVerify`-equivalent.
 * * The secret is sent to the configured lookup origin and nowhere else.
 * * Redirects are refused outright, so a redirect can never carry the secret to another origin.
 * * No retries; one request per call.
 * * The secret never appears in a log line, an exception message, a [LookupOutcome], or the UI.
 */
object PrivateDiscoveryLookup {

  /**
   * Hard cap on the response body.
   *
   * The response may be a bare address on one line or a small JSON document, so this leaves room
   * for a handful of fields while still bounding what a compromised or confused endpoint can make
   * this client read into memory.
   */
  const val MAX_BODY_BYTES: Int = 2048

  /** What a transport reports back. Never carries request headers. */
  data class HttpResult(val statusCode: Int, val body: String)

  /**
   * Everything a transport needs to issue the one lookup request.
   *
   * Grouped into an object rather than a long parameter list so that credentials are redacted in
   * exactly one place — [toString] here is what any accidental log line or crash report would use.
   */
  data class Request(
      val url: String,
      val authHeader: String,
      val secret: String,
      val timeoutSeconds: Int,
      val clientCertP12Base64: String = "",
      val clientCertPassphrase: String = "",
      val extraCaPem: String = "",
  ) {
    override fun toString(): String =
        "Request(url=${redactUrl(url)}, authHeader=$authHeader, secret=<redacted>, " +
            "timeoutSeconds=$timeoutSeconds, " +
            "clientCert=${present(clientCertP12Base64.isNotBlank())}, " +
            "clientCertPassphrase=<redacted>, extraCa=${present(extraCaPem.isNotBlank())})"
  }

  /** Failure categories. Every one of these renders to a credential-free message. */
  enum class FailureKind {
    NOT_CONFIGURED,
    NOT_HTTPS,
    MISSING_SECRET,
    INVALID_HEADER_NAME,
    UNAUTHORIZED,
    FORBIDDEN,
    NOT_FOUND,
    RATE_LIMITED,
    SERVER_ERROR,
    REDIRECT_REFUSED,
    HTTP_ERROR,
    CLIENT_CERT_ERROR,
    TIMEOUT,
    TLS_ERROR,
    NETWORK_ERROR,
    BAD_RESPONSE,
  }

  sealed class LookupOutcome {
    data class Success(val address: String) : LookupOutcome()

    /** [detail] is always safe to display and log: it never contains credentials. */
    data class Failure(val kind: FailureKind, val detail: String) : LookupOutcome()
  }

  /** Thrown by transports to signal a category the HTTP status cannot express. */
  class TransportException(val kind: FailureKind, message: String) : Exception(message)

  interface Transport {
    /**
     * Issues `GET request.url` with a single `<authHeader>: <secret>` request header and returns
     * the status and (at most [MAX_BODY_BYTES] of) the body.
     *
     * The secret is sent verbatim, so bearer-style auth is expressed by the caller as `authHeader =
     * "Authorization"`, `secret = "Bearer <token>"`.
     *
     * Implementations must not follow redirects and must not log the secret.
     */
    fun get(request: Request): HttpResult
  }

  /**
   * Performs one lookup. Never throws; every failure mode comes back as [LookupOutcome.Failure].
   */
  fun perform(config: PrivateDiscoveryConfig, transport: Transport): LookupOutcome {
    val url = config.lookupUrl.trim()
    when (validateLookupUrl(url)) {
      null -> {}
      ValidationError.NOT_HTTPS ->
          return LookupOutcome.Failure(FailureKind.NOT_HTTPS, "Lookup URL must use https://")
      else -> return LookupOutcome.Failure(FailureKind.NOT_CONFIGURED, "Lookup URL is not valid")
    }
    val authHeader = config.authHeader.trim()
    if (validateAuthHeader(authHeader) != null) {
      return LookupOutcome.Failure(
          FailureKind.INVALID_HEADER_NAME, "Auth header name is not a valid HTTP header name")
    }
    if (config.secret.isBlank()) {
      return LookupOutcome.Failure(FailureKind.MISSING_SECRET, "Shared secret is not set")
    }

    val request =
        Request(
            url = url,
            authHeader = authHeader,
            secret = config.secret,
            timeoutSeconds = config.timeoutSeconds,
            clientCertP12Base64 = config.clientCertP12Base64,
            clientCertPassphrase = config.clientCertPassphrase,
            extraCaPem = config.extraCaPem)

    val result =
        try {
          transport.get(request)
        } catch (e: TransportException) {
          // e.message is written by the transport and is credential-free by contract.
          return LookupOutcome.Failure(e.kind, e.message ?: "Lookup failed")
        } catch (e: Exception) {
          // Deliberately do not include e.message: an arbitrary exception string is not a
          // credential-free channel we control.
          return LookupOutcome.Failure(FailureKind.NETWORK_ERROR, "Lookup failed")
        }

    statusFailure(result.statusCode)?.let {
      return it
    }

    return when (val parsed = Ipv6Address.parseLookupResponse(result.body)) {
      is Ipv6Address.Result.Valid -> LookupOutcome.Success(parsed.address)
      is Ipv6Address.Result.Invalid ->
          LookupOutcome.Failure(FailureKind.BAD_RESPONSE, describe(parsed.reason))
    }
  }

  private fun statusFailure(status: Int): LookupOutcome.Failure? =
      when {
        status in 200..299 -> null
        status in 300..399 ->
            LookupOutcome.Failure(
                FailureKind.REDIRECT_REFUSED,
                "Lookup endpoint redirected (HTTP $status); refused so the secret is not forwarded")
        status == 401 -> LookupOutcome.Failure(FailureKind.UNAUTHORIZED, "HTTP 401 Unauthorized")
        status == 403 -> LookupOutcome.Failure(FailureKind.FORBIDDEN, "HTTP 403 Forbidden")
        status == 404 -> LookupOutcome.Failure(FailureKind.NOT_FOUND, "HTTP 404 Not Found")
        status == 429 ->
            LookupOutcome.Failure(FailureKind.RATE_LIMITED, "HTTP 429 Too Many Requests")
        status >= 500 -> LookupOutcome.Failure(FailureKind.SERVER_ERROR, "HTTP $status")
        else -> LookupOutcome.Failure(FailureKind.HTTP_ERROR, "HTTP $status")
      }

  private fun describe(reason: Ipv6Address.Rejection): String =
      when (reason) {
        Ipv6Address.Rejection.EMPTY -> "Lookup endpoint returned an empty response"
        Ipv6Address.Rejection.NOT_IPV6 -> "Response was not a valid IPv6 address"
        Ipv6Address.Rejection.IPV4_MAPPED -> "Response was an IPv4 address; IPv6 is required"
        Ipv6Address.Rejection.UNSPECIFIED -> "Response was the unspecified address (::)"
        Ipv6Address.Rejection.LOOPBACK -> "Response was a loopback address"
        Ipv6Address.Rejection.MULTICAST -> "Response was a multicast address"
        Ipv6Address.Rejection.LINK_LOCAL -> "Response was a link-local address"
        Ipv6Address.Rejection.SITE_LOCAL -> "Response was a site-local address"
        Ipv6Address.Rejection.UNIQUE_LOCAL -> "Response was a unique-local address"
      }
}
