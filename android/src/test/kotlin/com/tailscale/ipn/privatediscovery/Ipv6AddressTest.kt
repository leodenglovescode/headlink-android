// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.privatediscovery

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Response parsing and address validation for Private Headscale IPv6 Discovery. */
class Ipv6AddressTest {

  private fun valid(body: String): String {
    val result = Ipv6Address.parseLookupResponse(body)
    assertTrue("expected $body to be accepted, got $result", result is Ipv6Address.Result.Valid)
    return (result as Ipv6Address.Result.Valid).address
  }

  private fun rejected(body: String): Ipv6Address.Rejection {
    val result = Ipv6Address.parseLookupResponse(body)
    assertTrue("expected $body to be rejected, got $result", result is Ipv6Address.Result.Invalid)
    return (result as Ipv6Address.Result.Invalid).reason
  }

  @Test
  fun acceptsAPlainAddress() {
    assertEquals("2409:8a00:1234:5678::abcd", valid("2409:8a00:1234:5678::abcd"))
  }

  // Requirement 7: response with a trailing newline is accepted.
  @Test
  fun acceptsTrailingNewline() {
    assertEquals("2409:8a00:1234:5678::abcd", valid("2409:8a00:1234:5678::abcd\n"))
    assertEquals("2409:8a00:1234:5678::abcd", valid("2409:8a00:1234:5678::abcd\r\n"))
  }

  // Requirement 8: surrounding spaces are accepted.
  @Test
  fun acceptsSurroundingWhitespace() {
    assertEquals("2409:8a00:1234:5678::abcd", valid("   2409:8a00:1234:5678::abcd  \t\r\n"))
  }

  @Test
  fun normalisesCase() {
    assertEquals("2409:8a00:1234:5678::abcd", valid("2409:8A00:1234:5678::ABCD"))
  }

  @Test
  fun acceptsFullyExpandedForm() {
    assertEquals(
        "2409:8a00:1234:5678:0000:0000:0000:abcd", valid("2409:8a00:1234:5678:0000:0000:0000:abcd"))
  }

  // Requirement 9: an IPv4 response is rejected.
  @Test
  fun rejectsIpv4() {
    assertEquals(Ipv6Address.Rejection.NOT_IPV6, rejected("203.0.113.7"))
    assertEquals(Ipv6Address.Rejection.NOT_IPV6, rejected("192.168.3.61\n"))
  }

  @Test
  fun rejectsIpv4MappedAndCompatible() {
    assertEquals(Ipv6Address.Rejection.IPV4_MAPPED, rejected("::ffff:203.0.113.7"))
    assertEquals(Ipv6Address.Rejection.IPV4_MAPPED, rejected("::ffff:cb00:7107"))
    assertEquals(Ipv6Address.Rejection.IPV4_MAPPED, rejected("::cb00:7107"))
  }

  // Requirement 10: garbage is rejected.
  @Test
  fun rejectsGarbage() {
    for (body in
        listOf(
            "hello world",
            "not-an-address",
            "<html><body>404</body></html>",
            "2409:8a00:1234:5678::abcd::1",
            "gggg::1",
            "2409:8a00:12345::1",
            "2409:8a00:1234:5678:9abc:def0:1234",
            "2409:8a00:1234:5678:9abc:def0:1234:5678:9999",
            "::::",
            ":",
        )) {
      assertEquals("body=$body", Ipv6Address.Rejection.NOT_IPV6, rejected(body))
    }
  }

  // Requirement 11: an empty body is rejected.
  @Test
  fun rejectsEmptyBody() {
    assertEquals(Ipv6Address.Rejection.EMPTY, rejected(""))
    assertEquals(Ipv6Address.Rejection.EMPTY, rejected("   \n\r\n "))
  }

  // Requirement 12: loopback is rejected.
  @Test
  fun rejectsLoopback() {
    assertEquals(Ipv6Address.Rejection.LOOPBACK, rejected("::1"))
    assertEquals(
        Ipv6Address.Rejection.LOOPBACK, rejected("0000:0000:0000:0000:0000:0000:0000:0001"))
  }

  // Requirement 13: link-local is rejected.
  @Test
  fun rejectsLinkLocal() {
    assertEquals(Ipv6Address.Rejection.LINK_LOCAL, rejected("fe80::1"))
    assertEquals(Ipv6Address.Rejection.LINK_LOCAL, rejected("febf:ffff::1"))
  }

  @Test
  fun rejectsOtherUnusableScopes() {
    assertEquals(Ipv6Address.Rejection.UNSPECIFIED, rejected("::"))
    assertEquals(Ipv6Address.Rejection.MULTICAST, rejected("ff02::1"))
    assertEquals(Ipv6Address.Rejection.SITE_LOCAL, rejected("fec0::1"))
    assertEquals(Ipv6Address.Rejection.UNIQUE_LOCAL, rejected("fd00::1"))
    assertEquals(Ipv6Address.Rejection.UNIQUE_LOCAL, rejected("fc00::1"))
  }

  // The lookup endpoint may serve application/json rather than a bare line.
  @Test
  fun acceptsJsonBodies() {
    assertEquals("2409:8a00:1234:5678::abcd", valid("""{"ipv6":"2409:8a00:1234:5678::abcd"}"""))
    assertEquals("2409:8a00:1234:5678::abcd", valid("""{"ip": "2409:8A00:1234:5678::ABCD"}"""))
    // The field name is not significant, so a schema change does not break the client.
    assertEquals(
        "2409:8a00:1234:5678::abcd",
        valid("""{"updated":"2026-08-02T10:00:00Z","address":"2409:8a00:1234:5678::abcd"}"""))
    // Pretty-printed, nested and array forms all work.
    assertEquals(
        "2409:8a00:1234:5678::abcd",
        valid("\n{\n  \"wan\": {\n    \"v6\": \"2409:8a00:1234:5678::abcd\"\n  }\n}\n"))
    assertEquals("2409:8a00:1234:5678::abcd", valid("""["2409:8a00:1234:5678::abcd"]"""))
  }

  /**
   * The exact response shape served by the real endpoint, pinned as a regression test.
   *
   * The address here is fabricated: the whole point of the feature is that the real one is never
   * published, so it must not appear in this repository either.
   */
  @Test
  fun acceptsTheRealEndpointResponseShape() {
    assertEquals(
        "2409:8a00:1234:5678::abcd",
        valid("""{"ipv6": "2409:8a00:1234:5678::abcd", "updated": "2026-08-01T20:12:08Z"}"""))
  }

  /** An ISO-8601 timestamp contains colons but must never be mistaken for an address. */
  @Test
  fun timestampsAreNotMistakenForAddresses() {
    assertEquals(
        Ipv6Address.Rejection.NOT_IPV6, rejected("""{"updated": "2026-08-01T20:12:08Z"}"""))
  }

  @Test
  fun jsonWithNoUsableAddressIsRejected() {
    assertEquals(Ipv6Address.Rejection.NOT_IPV6, rejected("""{"error":"forbidden"}"""))
    assertEquals(Ipv6Address.Rejection.NOT_IPV6, rejected("{}"))
    // A specific complaint survives, rather than being flattened to "not IPv6".
    assertEquals(Ipv6Address.Rejection.LINK_LOCAL, rejected("""{"ipv6":"fe80::1"}"""))
    assertEquals(Ipv6Address.Rejection.LOOPBACK, rejected("""{"ipv6":"::1"}"""))
    assertEquals(Ipv6Address.Rejection.IPV4_MAPPED, rejected("""{"ip":"::ffff:203.0.113.7"}"""))
  }

  /** A JSON key or unrelated string must never be mistaken for the answer. */
  @Test
  fun jsonPicksTheFirstStringThatIsActuallyAnAddress() {
    assertEquals(
        "2409:8a00:1234:5678::abcd",
        valid(
            """{"host":"headscale.lan","note":"not an address","v6":"2409:8a00:1234:5678::abcd"}"""))
    // An unusable address earlier in the document does not stop a usable one being found.
    assertEquals(
        "2409:8a00:1234:5678::abcd",
        valid("""{"lan":"fd00::1","wan":"2409:8a00:1234:5678::abcd"}"""))
  }

  @Test
  fun rejectsZoneIdentifiers() {
    assertEquals(Ipv6Address.Rejection.NOT_IPV6, rejected("fe80::1%wlan0"))
    assertEquals(Ipv6Address.Rejection.NOT_IPV6, rejected("2409:8a00::1%eth0"))
  }
}
