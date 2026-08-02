// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.privatediscovery

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** HTTP behaviour and secret handling for the authenticated lookup. */
class PrivateDiscoveryLookupTest {

  private val secret = "super-secret-shared-secret-value"

  private val goodConfig =
      PrivateDiscoveryConfig(
          enabled = true,
          lookupUrl = "https://lookup.example.com/current-ip",
          authHeader = "X-Sync-Secret",
          secret = secret,
          timeoutSeconds = 10)

  /** Records what it was asked to do and replays a canned answer. */
  private class FakeTransport(
      private val result: PrivateDiscoveryLookup.HttpResult? = null,
      private val throwing: Exception? = null
  ) : PrivateDiscoveryLookup.Transport {
    var calls = 0
    var lastRequest: PrivateDiscoveryLookup.Request? = null

    val lastUrl: String?
      get() = lastRequest?.url

    val lastHeader: String?
      get() = lastRequest?.authHeader

    val lastSecret: String?
      get() = lastRequest?.secret

    val lastTimeout: Int?
      get() = lastRequest?.timeoutSeconds

    override fun get(request: PrivateDiscoveryLookup.Request): PrivateDiscoveryLookup.HttpResult {
      calls += 1
      lastRequest = request
      throwing?.let { throw it }
      return result!!
    }
  }

  private fun ok(body: String) = FakeTransport(PrivateDiscoveryLookup.HttpResult(200, body))

  private fun status(code: Int, body: String = "") =
      FakeTransport(PrivateDiscoveryLookup.HttpResult(code, body))

  private fun failure(
      outcome: PrivateDiscoveryLookup.LookupOutcome
  ): PrivateDiscoveryLookup.LookupOutcome.Failure {
    assertTrue(
        "expected a failure, got $outcome", outcome is PrivateDiscoveryLookup.LookupOutcome.Failure)
    return outcome as PrivateDiscoveryLookup.LookupOutcome.Failure
  }

  // Requirement 6 (first half): a successful lookup yields the address.
  @Test
  fun successReturnsTheAddress() {
    val transport = ok("2409:8a00:1234:5678::abcd\n")
    val outcome = PrivateDiscoveryLookup.perform(goodConfig, transport)

    assertEquals(PrivateDiscoveryLookup.LookupOutcome.Success("2409:8a00:1234:5678::abcd"), outcome)
    assertEquals(1, transport.calls)
    assertEquals("https://lookup.example.com/current-ip", transport.lastUrl)
    assertEquals(10, transport.lastTimeout)
  }

  @Test
  fun sendsTheSecretToTheConfiguredOriginOnly() {
    val transport = ok("2409:8a00::1")
    PrivateDiscoveryLookup.perform(goodConfig, transport)
    assertEquals(secret, transport.lastSecret)
    assertEquals("https://lookup.example.com/current-ip", transport.lastUrl)
  }

  /** The secret goes in the configured header, verbatim, with nothing prepended. */
  @Test
  fun usesTheConfiguredHeaderName() {
    val transport = ok("2409:8a00::1")
    PrivateDiscoveryLookup.perform(goodConfig, transport)
    assertEquals("X-Sync-Secret", transport.lastHeader)
    assertEquals(secret, transport.lastSecret)
  }

  /** Bearer auth is just a particular choice of header name and value. */
  @Test
  fun supportsBearerStyleAuthAsAPlainConfiguration() {
    val transport = ok("2409:8a00::1")
    PrivateDiscoveryLookup.perform(
        goodConfig.copy(authHeader = "Authorization", secret = "Bearer $secret"), transport)
    assertEquals("Authorization", transport.lastHeader)
    assertEquals("Bearer $secret", transport.lastSecret)
  }

  @Test
  fun headerNameIsTrimmedBeforeUse() {
    val transport = ok("2409:8a00::1")
    PrivateDiscoveryLookup.perform(goodConfig.copy(authHeader = "  X-Sync-Secret  "), transport)
    assertEquals("X-Sync-Secret", transport.lastHeader)
  }

  /**
   * A header name containing CR, LF or a colon would be a header-injection primitive on the one
   * request that carries the secret, so it is refused before any request is made.
   */
  @Test
  fun malformedHeaderNamesAreRefusedBeforeAnyRequest() {
    for (name in listOf("X-Sync\r\nInjected: 1", "X Sync Secret", "X-Sync:Secret", "")) {
      val transport = ok("2409:8a00::1")
      val f = failure(PrivateDiscoveryLookup.perform(goodConfig.copy(authHeader = name), transport))
      assertEquals("header=$name", PrivateDiscoveryLookup.FailureKind.INVALID_HEADER_NAME, f.kind)
      assertEquals("header=$name", 0, transport.calls)
    }
  }

  // Requirement 14/15/16: clean failures for 401 / 403 / 5xx.
  @Test
  fun httpErrorsFailCleanly() {
    val cases =
        mapOf(
            401 to PrivateDiscoveryLookup.FailureKind.UNAUTHORIZED,
            403 to PrivateDiscoveryLookup.FailureKind.FORBIDDEN,
            404 to PrivateDiscoveryLookup.FailureKind.NOT_FOUND,
            429 to PrivateDiscoveryLookup.FailureKind.RATE_LIMITED,
            500 to PrivateDiscoveryLookup.FailureKind.SERVER_ERROR,
            502 to PrivateDiscoveryLookup.FailureKind.SERVER_ERROR,
            418 to PrivateDiscoveryLookup.FailureKind.HTTP_ERROR,
        )
    for ((code, kind) in cases) {
      val outcome = PrivateDiscoveryLookup.perform(goodConfig, status(code, "denied"))
      val f = failure(outcome)
      assertEquals("status $code", kind, f.kind)
      assertTrue("status $code detail should be non-empty", f.detail.isNotBlank())
    }
  }

  @Test
  fun redirectsAreRefusedRatherThanFollowed() {
    val outcome = PrivateDiscoveryLookup.perform(goodConfig, status(302))
    val f = failure(outcome)
    assertEquals(PrivateDiscoveryLookup.FailureKind.REDIRECT_REFUSED, f.kind)
  }

  // Requirement 17: a timeout is a clean failure.
  @Test
  fun timeoutFailsCleanly() {
    val transport =
        FakeTransport(
            throwing =
                PrivateDiscoveryLookup.TransportException(
                    PrivateDiscoveryLookup.FailureKind.TIMEOUT, "Timed out after 10s"))
    val f = failure(PrivateDiscoveryLookup.perform(goodConfig, transport))
    assertEquals(PrivateDiscoveryLookup.FailureKind.TIMEOUT, f.kind)
  }

  @Test
  fun tlsAndDnsErrorsFailCleanly() {
    val tls =
        FakeTransport(
            throwing =
                PrivateDiscoveryLookup.TransportException(
                    PrivateDiscoveryLookup.FailureKind.TLS_ERROR, "TLS error"))
    assertEquals(
        PrivateDiscoveryLookup.FailureKind.TLS_ERROR,
        failure(PrivateDiscoveryLookup.perform(goodConfig, tls)).kind)

    val dns =
        FakeTransport(
            throwing =
                PrivateDiscoveryLookup.TransportException(
                    PrivateDiscoveryLookup.FailureKind.NETWORK_ERROR, "Could not resolve"))
    assertEquals(
        PrivateDiscoveryLookup.FailureKind.NETWORK_ERROR,
        failure(PrivateDiscoveryLookup.perform(goodConfig, dns)).kind)
  }

  @Test
  fun unexpectedExceptionsDoNotEscape() {
    val transport = FakeTransport(throwing = IllegalStateException("boom"))
    val f = failure(PrivateDiscoveryLookup.perform(goodConfig, transport))
    assertEquals(PrivateDiscoveryLookup.FailureKind.NETWORK_ERROR, f.kind)
  }

  @Test
  fun plainHttpIsRefusedBeforeAnyRequest() {
    val transport = ok("2409:8a00::1")
    val f =
        failure(
            PrivateDiscoveryLookup.perform(
                goodConfig.copy(lookupUrl = "http://lookup.example.com/current-ip"), transport))
    assertEquals(PrivateDiscoveryLookup.FailureKind.NOT_HTTPS, f.kind)
    assertEquals("the token must not be sent over plaintext", 0, transport.calls)
  }

  @Test
  fun missingSecretIsRefusedBeforeAnyRequest() {
    val transport = ok("2409:8a00::1")
    val f = failure(PrivateDiscoveryLookup.perform(goodConfig.copy(secret = ""), transport))
    assertEquals(PrivateDiscoveryLookup.FailureKind.MISSING_SECRET, f.kind)
    assertEquals(0, transport.calls)
  }

  @Test
  fun invalidUrlIsRefusedBeforeAnyRequest() {
    val transport = ok("2409:8a00::1")
    val f = failure(PrivateDiscoveryLookup.perform(goodConfig.copy(lookupUrl = "  "), transport))
    assertEquals(PrivateDiscoveryLookup.FailureKind.NOT_CONFIGURED, f.kind)
    assertEquals(0, transport.calls)
  }

  @Test
  fun badBodiesAreReportedAsBadResponse() {
    for (body in listOf("", "203.0.113.7", "nonsense", "::1", "fe80::1")) {
      val f = failure(PrivateDiscoveryLookup.perform(goodConfig, ok(body)))
      assertEquals("body=$body", PrivateDiscoveryLookup.FailureKind.BAD_RESPONSE, f.kind)
    }
  }

  @Test
  fun exactlyOneRequestPerCall() {
    val transport = ok("2409:8a00::1")
    PrivateDiscoveryLookup.perform(goodConfig, transport)
    assertEquals("no retries inside a single lookup", 1, transport.calls)
  }

  /** A JSON body, which is what an nginx `alias` of a small .json file returns. */
  @Test
  fun acceptsAJsonResponseBody() {
    val outcome =
        PrivateDiscoveryLookup.perform(goodConfig, ok("""{"ipv6":"2409:8a00:1234:5678::abcd"}"""))
    assertEquals(PrivateDiscoveryLookup.LookupOutcome.Success("2409:8a00:1234:5678::abcd"), outcome)
  }

  // Requirement 20: the secret never leaks into an outcome, a message, or a rendered config.
  @Test
  fun theSecretNeverAppearsInAnyOutcomeOrRendering() {
    val outcomes =
        listOf(
            PrivateDiscoveryLookup.perform(goodConfig, ok("2409:8a00::1")),
            PrivateDiscoveryLookup.perform(goodConfig, status(401, secret)),
            PrivateDiscoveryLookup.perform(goodConfig, status(500, "token=$secret")),
            PrivateDiscoveryLookup.perform(goodConfig, ok("garbage $secret")),
            PrivateDiscoveryLookup.perform(
                goodConfig,
                FakeTransport(
                    throwing =
                        PrivateDiscoveryLookup.TransportException(
                            PrivateDiscoveryLookup.FailureKind.TLS_ERROR, "TLS error"))),
            PrivateDiscoveryLookup.perform(goodConfig, FakeTransport(throwing = Exception(secret))),
        )
    for (outcome in outcomes) {
      assertFalse("token leaked into $outcome", outcome.toString().contains(secret))
    }
    assertFalse(goodConfig.toString().contains(secret))
    assertNotNull(goodConfig.toString())
  }

  @Test
  fun redactUrlStripsQueryAndFragment() {
    assertEquals(
        "https://lookup.example.com/current-ip?<redacted>",
        redactUrl("https://lookup.example.com/current-ip?key=$secret"))
    assertEquals(
        "https://lookup.example.com/current-ip", redactUrl("https://lookup.example.com/current-ip"))
    assertFalse(redactUrl("https://lookup.example.com/x?token=$secret").contains(secret))
    assertEquals("<unset>", redactUrl(""))
  }
}
